// Auto-generated from function_registry_v2.json
// Generated: 2025-12-15T15:44:29.888678
// Functions for D2gfx.dll
// Versions: LoD/PD2

var FUNCTIONS_D2gfx_dll = {
  "versions": [
    "LoD/PD2"
  ],
  "functions": {
    "D2gfx_MNE_b971a7136b1d": {
      "addresses": {
        "LoD/PD2": "0x6FA81000"
      },
      "rvas": {
        "LoD/PD2": "0x1000"
      },
      "sizes": {
        "LoD/PD2": 24
      },
      "name": "DeleteObjectWrapper",
      "signature": "void DeleteObjectWrapper(void * pObject)",
      "calling_convention": "__cdecl",
      "comment": "Setting prototype: void __cdecl DeleteObjectWrapper(type_info * pTypeInfo)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:b971a7136b1dcd60f532df35ec55e166",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "b971a7136b1dcd60f532df35ec55e166",
        "CFG": "e553846da5ba262778b53b44016b5225",
        "PRO": "b8fd1f8e7244b2bdde731da4f5cf9b3c"
      },
      "basic_block_counts": {
        "LoD/PD2": 4
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "api_calls": {
        "LoD/PD2": [
          "DeallocateMemoryBlock"
        ]
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2gfx_MNE_5c73446e6da2": {
      "addresses": {
        "LoD/PD2": "0x6FA8C0D3"
      },
      "rvas": {
        "LoD/PD2": "0xC0D3"
      },
      "sizes": {
        "LoD/PD2": 1
      },
      "name": "StubFunction",
      "signature": "void StubFunction(void)",
      "calling_convention": "__stdcall",
      "comment": "Stub function that performs no operations.\n\nAlgorithm:\n1. Immediately returns to caller with no side effects\n\nParameters:\nNone\n\nReturns:\nvoid - Function has no return value. Used as a placeholder or no-op function in function pointer tables or conditional execution paths.",
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
    "D2gfx_MNE_a3916ea23e38": {
      "addresses": {
        "LoD/PD2": "0x6FA81030"
      },
      "rvas": {
        "LoD/PD2": "0x1030"
      },
      "sizes": {
        "LoD/PD2": 55
      },
      "name": "RemoveListEntryWithExceptionHandler",
      "signature": "void RemoveListEntryWithExceptionHandler(_LIST_ENTRY * pListEntry)",
      "calling_convention": "__stdcall",
      "comment": "Safely removes a list entry while handling Windows SEH exceptions.\n\nAlgorithm:\n1. Save current SEH exception handler from FS:[0x0]\n2. Push exception handler chain frame with marker (0xffffffff) and handler routine address\n3. Update FS:[0x0] to point to new exception frame\n4. Call RemoveListEntry with protected exception handling active\n5. Restore previous exception handler from saved pointer\n6. Return to caller (callee cleanup: RET 0x4)\n\nThis function wraps RemoveListEntry with Windows Structured Exception Handling (SEH)\nto ensure safe cleanup if an exception occurs during list manipulation.\n\nParameters:\n- pListEntry (_LIST_ENTRY *): Pointer to the list entry to remove\n\nReturns:\nvoid\n\nStructure Layout:\nException Frame (Stack Layout):\nOffset | Size | Field           | Type    | Description\n-------|------|-----------------|---------|---------------------------\n-0x4   | 4    | dwExceptionMark | uint    | Sentinel value 0xFFFFFFFF\n-0x8   | 4    | pHandler        | void *  | Handler routine address\n-0xC   | 4    | pPrevious       | void *  | Previous exception frame\n0x0    | 4    | ESP value       | pointer | Saved ESP for return\n0x4    | 4    | pListEntry      | pointer | Parameter: list entry to remove",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:a3916ea23e38a520734795fd2a3822db",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "a3916ea23e38a520734795fd2a3822db",
        "CFG": null,
        "PRO": "6a327d4d7fb03660cd9aea84617be051"
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
    "D2gfx_MNE_8f1ca339ad64": {
      "addresses": {
        "LoD/PD2": "0x6FA81070"
      },
      "rvas": {
        "LoD/PD2": "0x1070"
      },
      "sizes": {
        "LoD/PD2": 107
      },
      "name": "InitializeExceptionFrame",
      "signature": "void InitializeExceptionFrame(ExceptionFrame * pFrame)",
      "calling_convention": "__stdcall",
      "comment": "Initialize Windows Structured Exception Handling (SEH) frame\n\nAlgorithm:\n1. Save the previous SEH frame from FS:[0x0] (thread exception chain)\n2. Install exception handler at 0x6fa8cbf5 into stack frame\n3. Clear all three fields of the ExceptionFrame structure (prevFrame, handler, encodedHandler)\n4. Set handler field to point to itself (self-referential pointer)\n5. Set encodedHandler to bitwise NOT of handler address (security cookie)\n6. Initialize exception state to 0 (no exception active)\n7. Re-initialize handler and encodedHandler with same values (duplicate initialization)\n8. Set exception state to 0xffffffff (exception handling complete)\n9. Restore the previous SEH frame to FS:[0x0]\n\nParameters:\n  pFrame - Pointer to 12-byte ExceptionFrame structure to initialize\n           Offsets: +0x0 = prevFrame, +0x4 = handler, +0x8 = encodedHandler\n\nReturns:\n  void\n\nSpecial Cases:\n- Handler address 0x6fa8cbf5 is the exception filter/handler function\n- Encoded handler uses bitwise NOT for obfuscation (~handler_address)\n- Exception state -1 (0xffffffff) indicates normal completion\n- Exception state 0 indicates initialization phase\n- Exception state 1 indicates handler is active\n- FS:[0x0] points to the thread's SEH chain head\n- This follows Windows __try/__except implementation pattern\n\nStructure Layout:\nOffset  Size  Field Name       Type     Description\n------  ----  ---------------  -------  ---------------------------\n0x00    4     prevFrame        pointer  Previous SEH frame in chain\n0x04    4     handler          pointer  Exception handler function\n0x08    4     encodedHandler   uint     Encoded handler (~address)\n------  ----  ---------------  -------  ---------------------------\nTotal: 12 bytes",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:8f1ca339ad6427a15e24d2eb1e58d366",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "8f1ca339ad6427a15e24d2eb1e58d366",
        "CFG": null,
        "PRO": "5d9f02c48591020da5026c9db0c3ff30"
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
    "D2gfx_MNE_a4bc3cba703d": {
      "addresses": {
        "LoD/PD2": "0x6FA810E0"
      },
      "rvas": {
        "LoD/PD2": "0x10E0"
      },
      "sizes": {
        "LoD/PD2": 120
      },
      "name": "RemoveListEntry",
      "signature": "void RemoveListEntry(_LIST_ENTRY * pListEntry)",
      "calling_convention": "__stdcall",
      "comment": "Remove an entry from a doubly-linked list structure and update surrounding node pointers.\n\nAlgorithm:\n1. Install structured exception handler for safe list manipulation\n2. Call RelocateListEntries() to initialize or acquire list lock\n3. Load backward link pointer (Blink) from offset +0x4 of pListEntry\n4. Check if Blink is NULL - if so, entry is unlinked and function exits\n5. Load offset/flags value from pListEntry[1].Flink (offset +0x8)\n6. Determine target node address based on offset value type:\n   - If offset is negative (bit 31 set), invert bitwise to get absolute address\n   - If offset is positive, calculate relative address: ppListEntryField + (dwOffsetValue - pBlinkNode->Blink)\n7. Store pBlinkNode pointer in target node's forward link field\n8. Update pBlinkNode's Blink field with the offset/flags value\n9. Clear pListEntry's Blink pointer to mark entry as removed\n10. Clear pListEntry's offset field completing removal\n11. Restore previous exception handler and return\n\nParameters:\n  pListEntry - Pointer to LIST_ENTRY structure with forward/backward links\n               The function accesses:\n               +0x0: Flink (forward link) - points to next entry\n               +0x4: Blink (backward link) - points to previous entry\n               +0x8: offset/flags value for relative addressing calculations\n\nReturns:\n  void - No return value\n\nSpecial Cases:\n  - If Blink is NULL, the entry is considered unlinked and exits without modification\n  - Negative offset values use bitwise NOT (~) to convert to absolute addresses\n  - Positive offset values are relative offsets from Blink's Blink address\n  - Exception handler at 0x6fa8cbcb protects against corruption during list updates\n  - Function uses __stdcall calling convention with RET 0x4 to clean parameter",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:a4bc3cba703dddfe045785e905b90541",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "a4bc3cba703dddfe045785e905b90541",
        "CFG": "d899fef07c1d12baa49df2291dfdf934",
        "PRO": "1a596ecdae28e1df1827f954f8515cf8"
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
    "D2gfx_MNE_7c308290a3e2": {
      "addresses": {
        "LoD/PD2": "0x6FA81160"
      },
      "rvas": {
        "LoD/PD2": "0x1160"
      },
      "sizes": {
        "LoD/PD2": 122
      },
      "name": "CreateAutoMessageSource",
      "signature": "void * CreateAutoMessageSource(void * pDestination, int nOffset, uint dwFlags)",
      "calling_convention": "__stdcall",
      "comment": "Creates and initializes an AutoMessageSource object with SEH protection.\n\nAlgorithm:\n1. Install structured exception handler frame on stack\n2. Load flags parameter and set bit 3 (OR with 0x8)\n3. Calculate source address by adding 0xC offset to nOffset parameter\n4. Call Ordinal_401 to allocate AutoMessageSource object with RTTI string \".?AUTMESSAGESOURCE@@\"\n5. If allocation succeeds, initialize first two DWORDs at offsets +0x0 and +0x4 to zero\n6. If nCleanupObject (ESI) is non-null, call cleanup function FUN_6fa81290\n7. Restore previous exception handler and return pointer to allocated object\n\nParameters:\npDestination - Destination pointer (stored but not used in this function)\nnOffset - Base offset to add 0xC to for source address calculation\ndwFlags - Allocation flags, OR'd with 0x8 before passing to allocator\nIMPLICIT: ESI - Optional cleanup object pointer passed via register\n\nReturns:\nPointer to newly allocated and initialized AutoMessageSource object\nReturns NULL if allocation fails\n\nSpecial Cases:\n- If allocation fails (returns NULL), function returns NULL without initialization\n- Cleanup via FUN_6fa81290 only called if ESI register contains non-zero pointer\n- Magic value 0xFFFFFFFE (-2) passed as third parameter to allocator\n- Exception state initialized to 0xFFFFFFFF indicating no active exception\n\nStructure Layout:\nOffset  Size  Field Name       Type      Description\n------  ----  ---------------  --------  -----------\n+0x0    4     field_0          DWORD     First field, initialized to 0\n+0x4    4     field_4          DWORD     Second field, initialized to 0\nTotal: 8+ bytes (actual size unknown, only first 8 bytes initialized)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:7c308290a3e2c2e8795a914b5df1adf9",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "7c308290a3e2c2e8795a914b5df1adf9",
        "CFG": "b3bbce4ecc1bf4d61b4305c0a2f44bde",
        "PRO": "379b3c04c124184bb68454ae8b80d2ef"
      },
      "basic_block_counts": {
        "LoD/PD2": 8
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "api_calls": {
        "LoD/PD2": [
          "AllocateMemoryFromArena"
        ]
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "D2gfx_MNE_a7dd2300cdab": {
      "addresses": {
        "LoD/PD2": "0x6FA811E0"
      },
      "rvas": {
        "LoD/PD2": "0x11E0"
      },
      "sizes": {
        "LoD/PD2": 103
      },
      "name": "RemoveListEntryCore",
      "signature": "void RemoveListEntryCore(int * pListEntry)",
      "calling_convention": "__stdcall",
      "comment": "Core list entry removal that unlinks a doubly-linked list node with offset-based addressing.\n\nAlgorithm:\n1. Setup structured exception handler for safe list manipulation\n2. Load Flink (forward link) from pListEntry[0]\n3. Check if Flink is NULL - if so, entry is unlinked, exit immediately\n4. Load offsetOrFlags value from pListEntry[1] (effective offset +0x8)\n5. Test offsetOrFlags sign bit to determine addressing mode\n6. If negative: Apply NOT to get absolute address\n7. If positive: Calculate relative address using (pListEntry + (offsetOrFlags - Blink[1]))\n8. Store Flink pointer at target node address\n9. Update Blink node's Blink field with offsetOrFlags value\n10. Clear Flink and offsetOrFlags fields marking entry as removed\n11. Restore exception handler and return\n\nParameters:\n  pListEntry - Pointer to _LIST_ENTRY structure accessed at +0x0 (Flink) and +0x4 (Blink)\n\nReturns:\n  void - No return value, modifies linked list in-place\n\nSpecial Cases:\n  - If Blink is NULL/0x0, function returns without modification\n  - Negative offsetOrFlags indicates absolute addressing (inverted with NOT)\n  - Positive offsetOrFlags indicates relative addressing from Blink's Blink field",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:a7dd2300cdab6e9d677439176366b161",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "a7dd2300cdab6e9d677439176366b161",
        "CFG": "cb0ff409c6c417241ca55c6e4c444bac",
        "PRO": "9a010b561e57fdde24a8dbc0c8965f4a"
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
    "D2gfx_MNE_92144b2f5cf5": {
      "addresses": {
        "LoD/PD2": "0x6FA81250"
      },
      "rvas": {
        "LoD/PD2": "0x1250"
      },
      "sizes": {
        "LoD/PD2": 54
      },
      "name": "UnlinkFrameNode",
      "signature": "void UnlinkFrameNode(FrameNode * pFrame)",
      "calling_convention": "__stdcall",
      "comment": "Removes a FrameNode from a doubly-linked list by updating pointer references using offset-based calculations.\n\nAlgorithm:\n1. Check if pFrame parameter is null - if null, return without modification\n2. Load pPrevNode pointer from offset 0 of the FrameNode structure\n3. Load nodeOffset value from offset 4 of the FrameNode structure\n4. Test nodeOffset to determine addressing mode: if negative, use complement; if positive, calculate relative address\n5. For negative nodeOffset: use bitwise complement (~nodeOffset) as the direct target address\n6. For positive nodeOffset: calculate target as (pFrame base + nodeOffset - pPrevNode[+4]) \n7. Write pPrevNode value to the calculated target address to update the reverse link\n8. Load the pPrevNode[+4] value and store it to pPrevNode[+4] to update the linkage field\n9. Clear both pFrame->pPrevNode (offset 0) and pFrame->nodeOffset (offset 4) fields to zero\n10. Return from function\n\nParameters:\npFrame (EAX): Pointer to FrameNode structure containing link information and offset encoding\n\nReturns:\nvoid - Function modifies FrameNode in place and has no return value\n\nSpecial Cases:\nNegative nodeOffset indicates absolute addressing mode using bitwise complement\nPositive nodeOffset indicates relative addressing mode requiring delta calculation\nNull pFrame pointer triggers immediate return without any list modifications",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:92144b2f5cf531a7090569e6c9590a02",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "92144b2f5cf531a7090569e6c9590a02",
        "CFG": "c65594e8aa0dd1dd8530e7ed504d685d",
        "PRO": "de3537d24dccfca026921ae6596e25a2"
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
    "D2gfx_MNE_353e1c4fa51d": {
      "addresses": {
        "LoD/PD2": "0x6FA81290"
      },
      "rvas": {
        "LoD/PD2": "0x1290"
      },
      "sizes": {
        "LoD/PD2": 166
      },
      "name": "InsertLinkedListNode",
      "signature": "void InsertLinkedListNode(int nInsertMode, int nDestOffset)",
      "calling_convention": "__stdcall",
      "comment": "Inserts a node into a doubly-linked list at a specified position.\n\nAlgorithm:\n1. Load source node address: Calculate from baseAddress (EAX) + nodeToInsert offset (EBX); if offset is zero, use baseAddress+4\n2. Unlink source node if currently linked: Check source node's forward pointer at offset 0; if non-zero, unlink by updating backward references\n3. Load destination node address: Calculate from baseAddress + destOffset parameter; if destOffset is zero, use baseAddress+4\n4. Insert after destination (insertMode != 1): Copy destination's forward/backward links to source node, update destination node's forward pointer to reference source node, update forward node's backward pointer to source offset\n5. Insert before destination (insertMode == 1): Copy destination node address to source forward, copy destination backward link to source, update backward references bidirectionally\n6. Handle backward link addressing: For negative backward links, convert using bitwise NOT (~) to absolute address; for positive links, calculate relative offset using [next+4] values\n7. Maintain bidirectional links: Update both forward and backward pointers for all affected nodes to preserve list integrity\n8. Return with list structure updated in-place\n\nParameters:\nEAX (implicit, __d2call): baseAddress - Pointer to list base structure or index table\nEBX (implicit, __d2call): nNodeToInsert - Byte offset of source node within list (0 means use baseAddress+4)\ninsertMode: Operation mode: 0 = insert after destination, 1 = insert before destination\ndestOffset: Byte offset of destination node within list (0 means use baseAddress+4)\n\nReturns:\nvoid - Updates linked list structure in-place with node repositioned correctly\n\nStructure Layout (Node):\nOffset  Size  Field Name    Type      Description\n------  ----  -----------   -----     -----------\n+0      4     pNextNode     int*      Forward link (pointer or offset to next node)\n+4      4     dwBackLink    int       Backward link (negative=absolute via ~, positive=relative offset)\n\nSpecial Cases:\n- Offset value 0 indicates direct head node (baseAddress+4)\n- Negative backward links require bitwise NOT (~) for absolute address conversion\n- Node offset stored indirectly at baseAddress allows two-level indirection\n- Function uses implicit parameters in EAX (baseAddress) and EBX (nNodeToInsert) per __d2call convention",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:353e1c4fa51ddf27db13e6d8edeb456c",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "353e1c4fa51ddf27db13e6d8edeb456c",
        "CFG": "46032800ba22ab7a7a9f9db51bda9d1a",
        "PRO": "1b2890d80557dfe2e1e276574a9d58e8"
      },
      "basic_block_counts": {
        "LoD/PD2": 21
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "D2gfx_MNE_ad0bca5018bb": {
      "addresses": {
        "LoD/PD2": "0x6FA81340"
      },
      "rvas": {
        "LoD/PD2": "0x1340"
      },
      "sizes": {
        "LoD/PD2": 68
      },
      "name": "RelocateListEntries",
      "signature": "void RelocateListEntries(void)",
      "calling_convention": "__d2call",
      "comment": "Relocate list entry pointers during list manipulation operations.\n\nAlgorithm:\n1. Load entry count from pListHeader[2] (offset +0x8)\n2. Test if count > 0; exit if count <= 0 (empty list)\n3. Loop through entries: Load entry value from array at base + count offset\n4. Load offset field from entry at offset +0x4\n5. Test offset sign: if negative, invert with NOT to get absolute address\n6. If offset positive: calculate relative address using delta from base offsets\n7. Store entry value at relocated target pointer address\n8. Load forward link from current entry and update with offset value\n9. Zero both entry and offset fields to mark as relocated\n10. Return to step 3 for next entry until count decremented\n\nParameters:\n  pListHeader - List container with entry array (implicit EDI register)\n                +0x0: Pointer to entry array\n                +0x8: Entry count for loop\n\nReturns:\n  void - No return value; modifies list structure in-place\n\nSpecial Cases:\n  Empty list: If count <= 0, return immediately without processing\n  Null entries: Skip processing if entry value is zero\n  Negative offsets: Stored as bitwise NOT of address; inverted to recover original\n  Pointer chains: Forward links form chain connecting relocated entries",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:ad0bca5018bb85bedbe4c97b9fabd47c",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "ad0bca5018bb85bedbe4c97b9fabd47c",
        "CFG": "afe8a26fb516db4af542a569592e7d26",
        "PRO": "b3fb54c738df198bd721e48575f55edb"
      },
      "basic_block_counts": {
        "LoD/PD2": 13
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "D2gfx_STR_c170bd72c7a3": {
      "addresses": {
        "LoD/PD2": "0x6FA81384"
      },
      "rvas": {
        "LoD/PD2": "0x1384"
      },
      "sizes": {
        "LoD/PD2": 47
      },
      "name": "___crtExitProcess",
      "signature": "void ___crtExitProcess(int param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___crtExitProcess\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "STR",
      "index": "STR:c170bd72c7a30c3be9e6aa15fb836e49",
      "indexes": {
        "EXP": null,
        "STR": "c170bd72c7a30c3be9e6aa15fb836e49",
        "API": null,
        "MNE": "df0a04b7db34c5f035a394dc061ca513",
        "CFG": "80845e7377749fe62fdfa1726193a977",
        "PRO": "23d2236144a313ec4288377308ddee33"
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
    "D2gfx_MNE_f23ef2b3a6cf": {
      "addresses": {
        "LoD/PD2": "0x6FA87897"
      },
      "rvas": {
        "LoD/PD2": "0x7897"
      },
      "sizes": {
        "LoD/PD2": 9
      },
      "name": "AcquireLockWithSize",
      "signature": "void AcquireLockWithSize(void)",
      "calling_convention": "__stdcall",
      "comment": "Acquires a lock with a size parameter of 8 bytes.\n\nAlgorithm:\n1. Push lock size parameter (0x8) onto the stack\n2. Call __lock() function to acquire the lock\n3. Pop return value from __lock into ECX register\n4. Return to caller\n\nParameters:\nNone (lock size is hardcoded to 0x8)\n\nReturns:\nvoid\n\nSpecial Cases:\n- Lock size (0x8) is hardcoded as immediate value; no parameter variation\n- Called during process cleanup from __onexit function\n- Part of process termination sequence",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:f23ef2b3a6cfdeb1f35221d5fc7b15e0",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "CFG": null,
        "PRO": "077c6c21b34882d84f3f3eb00803f72f"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "D2gfx_MNE_996e3f0c6129": {
      "addresses": {
        "LoD/PD2": "0x6FA813C6"
      },
      "rvas": {
        "LoD/PD2": "0x13C6"
      },
      "sizes": {
        "LoD/PD2": 24
      },
      "name": "__initterm",
      "signature": "undefined __initterm(undefined4 * param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __initterm\n\nLibrary: Visual Studio 2003 Release",
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
    "D2gfx_MNE_28a1cba9ddfd": {
      "addresses": {
        "LoD/PD2": "0x6FA813DE"
      },
      "rvas": {
        "LoD/PD2": "0x13DE"
      },
      "sizes": {
        "LoD/PD2": 106
      },
      "name": "__cinit",
      "signature": "int __cinit(int param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __cinit\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:28a1cba9ddfd9945ee3fec59104d67a8",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "28a1cba9ddfd9945ee3fec59104d67a8",
        "CFG": "e88749fdb0bfc0cf5a0e32fc67bb3506",
        "PRO": "bc4ca0abfb21371701ea9c607fda15b0"
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
    "D2gfx_MNE_2ef7e47ffada": {
      "addresses": {
        "LoD/PD2": "0x6FA81448"
      },
      "rvas": {
        "LoD/PD2": "0x1448"
      },
      "sizes": {
        "LoD/PD2": 176
      },
      "name": "DoExit",
      "signature": "void DoExit(uint dwExitCode, int nQuickExit, int nTerminateProcess)",
      "calling_convention": "__cdecl",
      "comment": "Performs application exit sequence with optional termination callback handling.\n\nAlgorithm:\n1. Acquire lock to prevent concurrent exit operations (call __lock)\n2. Check if exit already initiated (g_dwExitProcessFlag == 1)\n   - If so, get current process handle and terminate with exit code\n3. Mark exit as in-progress (g_dwExitInProgress = 1)\n4. Store exit mode parameter (g_byExitMode = param_3)\n5. If nQuickExit == 0 (normal exit):\n   - Execute atexit callbacks in reverse order:\n     a. Check if g_pAtexit_limit is defined\n     b. Decrement g_pAtexit_current pointer and verify bounds\n     c. Call handler function pointer if non-null\n     d. Repeat until limit reached\n   - Initialize and call deinit functions for C constructors\n6. Initialize and call deinit functions for other objects\n7. Perform conditional cleanup based on mode\n8. If nTerminateProcess == 0:\n   - Mark exit flag to prevent recursive exit\n   - Call ___crtExitProcess with exit code (no return)\n\nParameters:\nnExitCode - Exit code to pass to TerminateProcess (unsigned int)\nnQuickExit - If 0, execute normal cleanup; if non-zero, skip atexit handlers (int)\nnTerminateProcess - If 0, call crt exit process; if non-zero, return normally (int)\n\nReturns:\nvoid - Function does not return in normal exit path (calls ___crtExitProcess)\n\nSpecial Cases:\n- Concurrent exit attempts: If g_dwExitProcessFlag is already 1, immediately terminate process\n- Empty atexit array: If g_pAtexit_limit is null, skip callback execution\n- Pointer underflow: Validates g_pAtexit_current >= g_pAtexit_limit before dereferencing",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:2ef7e47ffada49e021fc9ebda7c95a50",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "2ef7e47ffada49e021fc9ebda7c95a50",
        "CFG": "bb2d29c85306f40b8ffddce47a988e1f",
        "PRO": "8c5ce4c92a78647993cda4fca4fb8c41"
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
    "D2gfx_MNE_ca7f27832b0d": {
      "addresses": {
        "LoD/PD2": "0x6FA814F7"
      },
      "rvas": {
        "LoD/PD2": "0x14F7"
      },
      "sizes": {
        "LoD/PD2": 14
      },
      "name": "PerformConditionalCleanup",
      "signature": "void PerformConditionalCleanup(void)",
      "calling_convention": "__stdcall",
      "comment": "Performs conditional cleanup operations during program exit sequence.\n\nAlgorithm:\n1. Compare the exit mode parameter [EBP+0x10] with the EDI register value\n2. If the values are equal (exit mode matches), jump directly to exit without cleanup\n3. If values differ, push cleanup type code 0x8 onto the stack\n4. Call UnlockCriticalSectionByIndex to release critical section 8\n5. Clean up stack by popping return value into ECX\n6. Return to caller (DoExit)\n\nParameters:\nIMPLICIT EBP - Saved frame pointer containing pointer to exit mode value at offset +0x10\nIMPLICIT EDI - Exit mode indicator for conditional comparison\n\nReturns:\nvoid - Function performs side effects (critical section unlock) with no return value\n\nSpecial Cases:\n- Cleanup is skipped if [EBP+0x10] equals EDI (matching exit mode)\n- Parameter 0x8 indicates critical section index 8 to be unlocked\n- Called as part of CRT exit sequence, typically from DoExit function\n- The conditional logic prevents redundant cleanup operations",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:ca7f27832b0deaebe496b377f1c5001a",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "ca7f27832b0deaebe496b377f1c5001a",
        "CFG": "f1596e7f5926afa1510db879e6d50457",
        "PRO": "465eab5d0d34c37c8d1b18f13fd959b3"
      },
      "basic_block_counts": {
        "LoD/PD2": 4
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "D2gfx_MNE_cd85d17a6b19": {
      "addresses": {
        "LoD/PD2": "0x6FA8151C"
      },
      "rvas": {
        "LoD/PD2": "0x151C"
      },
      "sizes": {
        "LoD/PD2": 17
      },
      "name": "_exit",
      "signature": "void _exit(int _Code)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n _exit\n\nLibrary: Visual Studio 2003 Release",
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
    "D2gfx_MNE_7a5e6ed384be": {
      "addresses": {
        "LoD/PD2": "0x6FA8152D"
      },
      "rvas": {
        "LoD/PD2": "0x152D"
      },
      "sizes": {
        "LoD/PD2": 15
      },
      "name": "__cexit",
      "signature": "void __cexit(void)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __cexit\n\nLibrary: Visual Studio 2003 Release",
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
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "D2gfx_MNE_fa8972b50a91": {
      "addresses": {
        "LoD/PD2": "0x6FA8153C"
      },
      "rvas": {
        "LoD/PD2": "0x153C"
      },
      "sizes": {
        "LoD/PD2": 88
      },
      "name": "_sprintf",
      "signature": "int _sprintf(char * _Dest, char * _Format, ...)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n _sprintf\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:fa8972b50a91454e34542a6f7b824984",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "fa8972b50a91454e34542a6f7b824984",
        "CFG": "0c83c6bd384507886ac1365a43eb2cf8",
        "PRO": "cc9dc3a343c87517576eeba67052d948"
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
    "D2gfx_MNE_7a09c5a73235": {
      "addresses": {
        "LoD/PD2": "0x6FA81594"
      },
      "rvas": {
        "LoD/PD2": "0x1594"
      },
      "sizes": {
        "LoD/PD2": 128
      },
      "name": "__onexit_lk",
      "signature": "undefined __onexit_lk(void)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Single Match\n __onexit_lk\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:7a09c5a73235698eb35bf1fa40abce3a",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "7a09c5a73235698eb35bf1fa40abce3a",
        "CFG": "4c747082602c7f76e5a0b6b31e0c33ed",
        "PRO": "cc75019028ca58cb984a564e8c07d1b4"
      },
      "basic_block_counts": {
        "LoD/PD2": 8
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "D2gfx_MNE_266baaaf79f2": {
      "addresses": {
        "LoD/PD2": "0x6FA81614"
      },
      "rvas": {
        "LoD/PD2": "0x1614"
      },
      "sizes": {
        "LoD/PD2": 40
      },
      "name": "___onexitinit",
      "signature": "undefined4 ___onexitinit(void)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Single Match\n ___onexitinit\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:266baaaf79f230c6a6856a4a53b42d70",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "266baaaf79f230c6a6856a4a53b42d70",
        "CFG": "074729d34b2ceac5cf54de1f1ab60b22",
        "PRO": "db6cb273acc70a9231f1f59f109b25ed"
      },
      "basic_block_counts": {
        "LoD/PD2": 3
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "D2gfx_MNE_5d2d40297dfe": {
      "addresses": {
        "LoD/PD2": "0x6FA8163C"
      },
      "rvas": {
        "LoD/PD2": "0x163C"
      },
      "sizes": {
        "LoD/PD2": 50
      },
      "name": "__onexit",
      "signature": "_onexit_t __onexit(_onexit_t _Func)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __onexit\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:5d2d40297dfe2be53beef9d63f51ef80",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "5d2d40297dfe2be53beef9d63f51ef80",
        "CFG": null,
        "PRO": "2b942ffac088fef531d6bda41060e56a"
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
    "D2gfx_MNE_e7313d19d2f1": {
      "addresses": {
        "LoD/PD2": "0x6FA8166E"
      },
      "rvas": {
        "LoD/PD2": "0x166E"
      },
      "sizes": {
        "LoD/PD2": 6
      },
      "name": "ReleaseCriticalSectionCleanup",
      "signature": "void ReleaseCriticalSectionCleanup(void)",
      "calling_convention": "__stdcall",
      "comment": "Releases critical section 8 during program exit cleanup.\n\nAlgorithm:\n1. Call ReleaseCriticalSection8() to release the hard-coded critical section index 8\n2. Return to caller (__onexit cleanup handler)\n\nParameters:\nNone - This function uses no parameters.\n\nReturns:\nvoid - No return value.\n\nSpecial Cases:\nThis is a thin wrapper function called from the __onexit C runtime cleanup handler chain. The critical\nsection at index 8 is released when the program terminates, ensuring proper cleanup of any locks protecting\ngame resources. The function is statically linked and always targets the same critical section index.",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:e7313d19d2f1b94221ec63dffd5562f1",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "e7313d19d2f1b94221ec63dffd5562f1",
        "CFG": null,
        "PRO": "a2ad55d571003470ebafe0caea715437"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "D2gfx_MNE_2544af1d7a07": {
      "addresses": {
        "LoD/PD2": "0x6FA81674"
      },
      "rvas": {
        "LoD/PD2": "0x1674"
      },
      "sizes": {
        "LoD/PD2": 18
      },
      "name": "_atexit",
      "signature": "int _atexit(_func_4879 * param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n _atexit\n\nLibrary: Visual Studio 2003 Release",
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
    "D2gfx_MNE_1c48859ddf90": {
      "addresses": {
        "LoD/PD2": "0x6FA81686"
      },
      "rvas": {
        "LoD/PD2": "0x1686"
      },
      "sizes": {
        "LoD/PD2": 385
      },
      "name": "__CRT_INIT@12",
      "signature": "undefined4 __CRT_INIT@12(undefined4 param_1, int param_2)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Single Match\n __CRT_INIT@12\n\nLibrary: Visual Studio 2003 Release",
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
    "D2gfx_MNE_e12afdedf65b": {
      "addresses": {
        "LoD/PD2": "0x6FA81807"
      },
      "rvas": {
        "LoD/PD2": "0x1807"
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
        "CFG": "ce7ec282051a6cfc0cdf10b84b9dd8ff",
        "PRO": "9ba99ae5263908381f66aca450a138e0"
      },
      "display_name": "MNE_e12afdedf65b4f2d",
      "basic_block_counts": {
        "LoD/PD2": 25
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "D2gfx_MNE_bed936c73fe1": {
      "addresses": {
        "LoD/PD2": "0x6FA818EB"
      },
      "rvas": {
        "LoD/PD2": "0x18EB"
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
        "PRO": "567946a70c93ce17c92ea2e972db432d"
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
    "D2gfx_MNE_921d14ea2db8": {
      "addresses": {
        "LoD/PD2": "0x6FA8191E"
      },
      "rvas": {
        "LoD/PD2": "0x191E"
      },
      "sizes": {
        "LoD/PD2": 73
      },
      "name": "__mtinitlocks",
      "signature": "int __mtinitlocks(void)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __mtinitlocks\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:921d14ea2db8ace7085d489017738fb1",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "921d14ea2db8ace7085d489017738fb1",
        "CFG": "dedcacb5022ec3081bf0e8026ad6b099",
        "PRO": "697cd33d7d0b18708ffe155a28c97c27"
      },
      "basic_block_counts": {
        "LoD/PD2": 7
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "D2gfx_MNE_3d673ff0fb62": {
      "addresses": {
        "LoD/PD2": "0x6FA81967"
      },
      "rvas": {
        "LoD/PD2": "0x1967"
      },
      "sizes": {
        "LoD/PD2": 85
      },
      "name": "__mtdeletelocks",
      "signature": "void __mtdeletelocks(void)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __mtdeletelocks\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:3d673ff0fb622876ea58c1a43b2af6a0",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "3d673ff0fb622876ea58c1a43b2af6a0",
        "CFG": "8c5e1e7e8911884bea7e85560490f0e2",
        "PRO": "28a8240176f9ca86329f1e17d5a46a49"
      },
      "basic_block_counts": {
        "LoD/PD2": 11
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "D2gfx_MNE_e83d10405144": {
      "addresses": {
        "LoD/PD2": "0x6FA819BC"
      },
      "rvas": {
        "LoD/PD2": "0x19BC"
      },
      "sizes": {
        "LoD/PD2": 21
      },
      "name": "UnlockCriticalSectionByIndex",
      "signature": "void UnlockCriticalSectionByIndex(int nLockIndex)",
      "calling_convention": "__cdecl",
      "comment": "Setting prototype: void UnlockCriticalSectionByIndex(int nLockIndex)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:e83d104051445238b4510431aa98563d",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "e83d104051445238b4510431aa98563d",
        "CFG": null,
        "PRO": "3545bd28f6122545223bc761d456605d"
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
    "D2gfx_MNE_a51a9a5e7ceb": {
      "addresses": {
        "LoD/PD2": "0x6FA819D1"
      },
      "rvas": {
        "LoD/PD2": "0x19D1"
      },
      "sizes": {
        "LoD/PD2": 151
      },
      "name": "__mtinitlocknum",
      "signature": "int __mtinitlocknum(int _LockNum)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __mtinitlocknum\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:a51a9a5e7ceb2fab96b937dc9f784c13",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "a51a9a5e7ceb2fab96b937dc9f784c13",
        "CFG": "1b97c4c9ebb5e5f377a4d61d4467ef57",
        "PRO": "e428e200984bcf4dbf5280b18320bfbd"
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
    "D2gfx_MNE_a62c5e213216": {
      "addresses": {
        "LoD/PD2": "0x6FA81A71"
      },
      "rvas": {
        "LoD/PD2": "0x1A71"
      },
      "sizes": {
        "LoD/PD2": 49
      },
      "name": "__lock",
      "signature": "void __lock(int _File)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __lock\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:a62c5e213216063061d4d1c8c7db89e8",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "a62c5e213216063061d4d1c8c7db89e8",
        "CFG": "6c3b0aa07951c5e00ecf5c0f67c56cb3",
        "PRO": "7fcd11a1f5fde8eb0797531bfb045ffc"
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
    "D2gfx_MNE_9882f49b4616": {
      "addresses": {
        "LoD/PD2": "0x6FA81AE6"
      },
      "rvas": {
        "LoD/PD2": "0x1AE6"
      },
      "sizes": {
        "LoD/PD2": 61
      },
      "name": "__RTC_Initialize",
      "signature": "undefined __RTC_Initialize(void)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Single Match\n __RTC_Initialize\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:9882f49b46164551a852d0e5558c3763",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "9882f49b46164551a852d0e5558c3763",
        "CFG": "8c955c77011f408ad9ffc78e365640e4",
        "PRO": "9e99a4d960ed529bee7a34e327858e59"
      },
      "basic_block_counts": {
        "LoD/PD2": 14
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "D2gfx_MNE_aef9935d5818": {
      "addresses": {
        "LoD/PD2": "0x6FA81B2C"
      },
      "rvas": {
        "LoD/PD2": "0x1B2C"
      },
      "sizes": {
        "LoD/PD2": 59
      },
      "name": "__SEH_prolog",
      "signature": "undefined __SEH_prolog(undefined4 param_1, int param_2)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __SEH_prolog\n\nLibrary: Visual Studio",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:aef9935d5818b16bbad0952f5da65380",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "aef9935d5818b16bbad0952f5da65380",
        "CFG": null,
        "PRO": "11a49a4f4d1f7585dbaa721e43141a3f"
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
    "D2gfx_MNE_bb6caf8fa91f": {
      "addresses": {
        "LoD/PD2": "0x6FA81B67"
      },
      "rvas": {
        "LoD/PD2": "0x1B67"
      },
      "sizes": {
        "LoD/PD2": 17
      },
      "name": "__SEH_epilog",
      "signature": "undefined __SEH_epilog(void)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Single Match\n __SEH_epilog\n\nLibrary: Visual Studio",
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
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "D2gfx_MNE_89d1b6190541": {
      "addresses": {
        "LoD/PD2": "0x6FA81C66"
      },
      "rvas": {
        "LoD/PD2": "0x1C66"
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
    "D2gfx_MNE_c4685906a5c4": {
      "addresses": {
        "LoD/PD2": "0x6FA81C81"
      },
      "rvas": {
        "LoD/PD2": "0x1C81"
      },
      "sizes": {
        "LoD/PD2": 281
      },
      "name": "__flsbuf",
      "signature": "int __flsbuf(int _Ch, FILE * _File)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __flsbuf\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:c4685906a5c4fe97104af70b25069ec2",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "c4685906a5c4fe97104af70b25069ec2",
        "CFG": "d9f501ab35c3e45910d8af88940764ed",
        "PRO": "90e9eadc7c1c9da9ca3a515f73b13cf1"
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
    "D2gfx_MNE_97c22a850703": {
      "addresses": {
        "LoD/PD2": "0x6FA81D9A"
      },
      "rvas": {
        "LoD/PD2": "0x1D9A"
      },
      "sizes": {
        "LoD/PD2": 51
      },
      "name": "write_char",
      "signature": "void write_char(byte byChar)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n _write_char\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:97c22a85070344f102bcf14ee4f0ea92",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "97c22a85070344f102bcf14ee4f0ea92",
        "CFG": "2bdbe5d6049f47ae5e33650ee79d4920",
        "PRO": "a150a68162357ae364bc07ea3ee65f66"
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
    "D2gfx_MNE_fab24e5d32bf": {
      "addresses": {
        "LoD/PD2": "0x6FA81DCD"
      },
      "rvas": {
        "LoD/PD2": "0x1DCD"
      },
      "sizes": {
        "LoD/PD2": 36
      },
      "name": "write_multi_char",
      "signature": "void write_multi_char(int nCharacter, int nCount, int nParam3)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n _write_multi_char\n\nLibraries: Visual Studio 2003 Release, Visual Studio 2005 Release, Visual Studio 2008 Release, Visual Studio 2010 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:fab24e5d32bf792b67dd222a8e1cb96f",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "fab24e5d32bf792b67dd222a8e1cb96f",
        "CFG": "b8441cb013c68b06fc43e57279ea6dcd",
        "PRO": "2a71c12bffbff4b88bfa2138aefb8e0b"
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
    "D2gfx_MNE_d1375bb0092b": {
      "addresses": {
        "LoD/PD2": "0x6FA81DF1"
      },
      "rvas": {
        "LoD/PD2": "0x1DF1"
      },
      "sizes": {
        "LoD/PD2": 55
      },
      "name": "write_string",
      "signature": "undefined write_string(int nCharCount)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n _write_string\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:d1375bb0092b441c0ed3bd5dfaaa61cb",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "d1375bb0092b441c0ed3bd5dfaaa61cb",
        "CFG": "74030650fb753398d6147a03797d11f3",
        "PRO": "fe8b22ad597beafb09901c0376a7be71"
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
    "D2gfx_STR_c004c7748bfc": {
      "addresses": {
        "LoD/PD2": "0x6FA81E28"
      },
      "rvas": {
        "LoD/PD2": "0x1E28"
      },
      "sizes": {
        "LoD/PD2": 1946
      },
      "name": "ProcessFormatString",
      "signature": "void ProcessFormatString(uint dwBufferContext, byte * pszFormat, wchar_t * wszArgList)",
      "calling_convention": "__cdecl",
      "comment": "Converts printf-style format string with variable arguments into formatted output.\n\nAlgorithm:\n1. Initialize stack canary value and zero output counters\n2. Load first format string character\n3. Main parsing loop: read character, check for null terminator\n4. Classify character and determine parser state (0-7)\n5. Process format flags (space, #, +, -, 0) when detected\n6. Parse field width from digits or * argument\n7. Parse precision value from . and digits/asterisk\n8. Parse length modifiers (h, l, I64, w) for argument sizing\n9. Dispatch on conversion specifier (d, i, u, o, x, X, f, e, g, c, s, S, n, p, Z)\n10. For integer conversions: extract argument, negate if signed, divide by radix to build digit string\n11. For float conversions: call __fptrap callback with precision, check for minus sign\n12. For string conversions: measure length with boundary limits, set wide flag if needed\n13. For character conversions: handle single char or multibyte with _wctomb\n14. Apply formatting flags: calculate padding, output sign/prefix, pad with spaces/zeros\n15. Output converted string with field width and precision alignment\n16. Free dynamically allocated buffer if precision exceeded 163 (0xa3) byte threshold\n17. Validate stack canary XOR value before return\n\nParameters:\n  bufferContext (uint): Output buffer context passed to write callback functions\n  formatString (byte*): Printf-style format string with format specifiers\n  varArgList (wchar_t*): Variable argument list pointer for sequential access\n\nReturns:\n  void - All output written via write_char, write_string, write_multi_char callback functions\n\nSpecial Cases:\n  I64 Modifier: 64-bit integer conversion on 32-bit platform, uses high/low DWORD values\n  Wide String Support: %S and %lc conversions use multibyte character conversion with _wctomb\n  Dynamic Buffer: Precision > 0xa3 triggers malloc for temporary conversion buffer\n  Float Callbacks: External __fptrap function handles e/E/g/G/f conversions\n  Stack Protection: Stack canary XOR protection against buffer overflow",
      "name_source": "LoD/PD2",
      "method": "STR",
      "index": "STR:c004c7748bfc4fad131df79cf3b532f1",
      "indexes": {
        "EXP": null,
        "STR": "c004c7748bfc4fad131df79cf3b532f1",
        "API": null,
        "MNE": "21007ff5bd6460b5113e6bf65ba34c2f",
        "CFG": "08a47e92ff6d7488f728db6aa3d63aaa",
        "PRO": "c7b9eec6aeafeb135888b7ce8cd1548a"
      },
      "basic_block_counts": {
        "LoD/PD2": 201
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "D2gfx_MNE_630b0e4f3169": {
      "addresses": {
        "LoD/PD2": "0x6FA825E4"
      },
      "rvas": {
        "LoD/PD2": "0x25E4"
      },
      "sizes": {
        "LoD/PD2": 417
      },
      "name": "ReallocateMemoryWithRetry",
      "signature": "int * ReallocateMemoryWithRetry(int * pMemoryBlock, uint dwNewSize)",
      "calling_convention": "__cdecl",
      "comment": "Setting prototype: int * ReallocateMemoryWithRetry(int * pMemoryBlock, uint dwNewSize)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:630b0e4f3169af3d32abd2ac2d1bf3c9",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "630b0e4f3169af3d32abd2ac2d1bf3c9",
        "CFG": "cfb29ec8ba5518bec46a77b4d6fe6bcf",
        "PRO": "68b5f8f09942af1d0ce80c9cac7ef02d"
      },
      "basic_block_counts": {
        "LoD/PD2": 41
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "D2gfx_MNE_7fa238a0d1fe": {
      "addresses": {
        "LoD/PD2": "0x6FA82796"
      },
      "rvas": {
        "LoD/PD2": "0x2796"
      },
      "sizes": {
        "LoD/PD2": 106
      },
      "name": "__msize",
      "signature": "size_t __msize(void * _Memory)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __msize\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:7fa238a0d1fe5549fc522252a2120d78",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "7fa238a0d1fe5549fc522252a2120d78",
        "CFG": "8afe1dbf942c6c117dd7d41a44c33921",
        "PRO": "23291b0cfc9a0abfd7a03de687183b40"
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
    "D2gfx_MNE_8ac92c76a51a": {
      "addresses": {
        "LoD/PD2": "0x6FA8280C"
      },
      "rvas": {
        "LoD/PD2": "0x280C"
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
        "PRO": "91fa0e0b112f34432f3e8fa6631bec54"
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
    "D2gfx_MNE_be05c38d951a": {
      "addresses": {
        "LoD/PD2": "0x6FA82887"
      },
      "rvas": {
        "LoD/PD2": "0x2887"
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
    "D2gfx_MNE_301bd5440f60": {
      "addresses": {
        "LoD/PD2": "0x6FA828B3"
      },
      "rvas": {
        "LoD/PD2": "0x28B3"
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
        "PRO": "97a350d0b0dc45635b3c77f707f54501"
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
    "D2gfx_MNE_03ce6e557a60": {
      "addresses": {
        "LoD/PD2": "0x6FA828C5"
      },
      "rvas": {
        "LoD/PD2": "0x28C5"
      },
      "sizes": {
        "LoD/PD2": 9
      },
      "name": "AllocateTlsSlot",
      "signature": "DWORD AllocateTlsSlot(void)",
      "calling_convention": "__stdcall",
      "comment": "Allocates a thread-local storage (TLS) slot during runtime initialization.\n\nAlgorithm:\n1. Invoke TlsAlloc function pointer at address 0x6fa8d044 to allocate a TLS index\n2. Return the allocated TLS index to caller\n\nParameters:\nNone\n\nReturns:\nDWORD - TLS slot index on success, or TLS_OUT_OF_INDEXES (0xFFFFFFFF) on failure\n\nSpecial Cases:\n- Return value of TLS_OUT_OF_INDEXES (0xFFFFFFFF) indicates allocation failure\n- Called during multi-threaded initialization (__mtinit) to set up thread-local storage\n- Function pointer at 0x6fa8d044 may be redirected or stubbed in some configurations\n\nCalling Convention:\n__stdcall - Callee cleans 4 bytes of parameters from stack\n\nNotes:\nThis is a wrapper function that indirectly calls the Windows TlsAlloc API through a function pointer stored in the data segment. This pattern allows for runtime flexibility in TLS management and potential API hooking or stubbing.",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:03ce6e557a60cad10c5f167fdc7f4b70",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "03ce6e557a60cad10c5f167fdc7f4b70",
        "CFG": null,
        "PRO": "2e6249ad0abc59a109007597293b5187"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "D2gfx_MNE_aff5ecc93302": {
      "addresses": {
        "LoD/PD2": "0x6FA828CE"
      },
      "rvas": {
        "LoD/PD2": "0x28CE"
      },
      "sizes": {
        "LoD/PD2": 29
      },
      "name": "__mtterm",
      "signature": "void __mtterm(void)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __mtterm\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:aff5ecc933020ea9f6660ca70cb9d16a",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "aff5ecc933020ea9f6660ca70cb9d16a",
        "CFG": "e4d929dcade813bcfed0f23f20c25712",
        "PRO": "4f7ad6a4a3959f3b145dfc085a7e0375"
      },
      "basic_block_counts": {
        "LoD/PD2": 3
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "D2gfx_MNE_a1900c49d3b8": {
      "addresses": {
        "LoD/PD2": "0x6FA828EB"
      },
      "rvas": {
        "LoD/PD2": "0x28EB"
      },
      "sizes": {
        "LoD/PD2": 19
      },
      "name": "__initptd",
      "signature": "void __initptd(_ptiddata _Ptd, pthreadlocinfo _Locale)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __initptd\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:a1900c49d3b847e69ff3bf21a94518de",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "a1900c49d3b847e69ff3bf21a94518de",
        "CFG": null,
        "PRO": "8321c82fb7898b227b2e755c8b0db48d"
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
    "D2gfx_MNE_04f1e6f173a4": {
      "addresses": {
        "LoD/PD2": "0x6FA828FE"
      },
      "rvas": {
        "LoD/PD2": "0x28FE"
      },
      "sizes": {
        "LoD/PD2": 113
      },
      "name": "__getptd",
      "signature": "_ptiddata __getptd(void)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __getptd\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:04f1e6f173a4f00f5247db68bf412e5b",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "04f1e6f173a4f00f5247db68bf412e5b",
        "CFG": "0c8662126fe6ebdb099c385715f42fe6",
        "PRO": "b97829a4ce0885cd58d0706e5a329f3f"
      },
      "basic_block_counts": {
        "LoD/PD2": 6
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "D2gfx_MNE_adafedc33ce1": {
      "addresses": {
        "LoD/PD2": "0x6FA8296F"
      },
      "rvas": {
        "LoD/PD2": "0x296F"
      },
      "sizes": {
        "LoD/PD2": 301
      },
      "name": "__freefls@4",
      "signature": "undefined __freefls@4(void * param_1)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Single Match\n __freefls@4\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:adafedc33ce199c85ef6d812cf9b5974",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "adafedc33ce199c85ef6d812cf9b5974",
        "CFG": "2da93e684001310322c3f0b023dc49fc",
        "PRO": "1c03fd84b82e7e8408e0ba687bef06ab"
      },
      "basic_block_counts": {
        "LoD/PD2": 34
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2gfx_MNE_c0a536e0e6da": {
      "addresses": {
        "LoD/PD2": "0x6FA82AB6"
      },
      "rvas": {
        "LoD/PD2": "0x2AB6"
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
        "PRO": "c7aba8c6148a1dd833ce5838bcc2faa0"
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
    "D2gfx_STR_304d598e6d0a": {
      "addresses": {
        "LoD/PD2": "0x6FA82AE5"
      },
      "rvas": {
        "LoD/PD2": "0x2AE5"
      },
      "sizes": {
        "LoD/PD2": 239
      },
      "name": "__mtinit",
      "signature": "int __mtinit(void)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __mtinit\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "STR",
      "index": "STR:304d598e6d0a621c9e3544e6fb22e61e",
      "indexes": {
        "EXP": null,
        "STR": "304d598e6d0a621c9e3544e6fb22e61e",
        "API": null,
        "MNE": "bcce8ed29924bac295ff5cc0516a2419",
        "CFG": "47193e95d9e3342a5a8c63a689eefe67",
        "PRO": "ec3587cb6025a0f9d3c257aa39c73e28"
      },
      "basic_block_counts": {
        "LoD/PD2": 11
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "api_calls": {
        "LoD/PD2": [
          "TlsAlloc"
        ]
      }
    },
    "D2gfx_MNE_d5c8453c3e2b": {
      "addresses": {
        "LoD/PD2": "0x6FA82BD4"
      },
      "rvas": {
        "LoD/PD2": "0x2BD4"
      },
      "sizes": {
        "LoD/PD2": 104
      },
      "name": "_free",
      "signature": "void _free(void * _Memory)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n _free\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:d5c8453c3e2bb4ff6f437d3d747d2c97",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "d5c8453c3e2bb4ff6f437d3d747d2c97",
        "CFG": "555d704848b8e783f7d263b7ca7bd009",
        "PRO": "39dc174af1bb293fb63e5dc5181075fa"
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
    "D2gfx_MNE_43c1542ced67": {
      "addresses": {
        "LoD/PD2": "0x6FA82C45"
      },
      "rvas": {
        "LoD/PD2": "0x2C45"
      },
      "sizes": {
        "LoD/PD2": 203
      },
      "name": "AllocateMemory",
      "signature": "void * AllocateMemory(uint elementCount, uint elementSize)",
      "calling_convention": "__cdecl",
      "comment": "Allocates and zero-initializes a block of memory with integer overflow detection.\n\nAlgorithm:\n1. Validate elementCount and elementSize to prevent multiplication overflow using DIV instruction (elementSize must be <= 0xffffffe0 / elementCount)\n2. Calculate total allocation size as elementCount * elementSize and store in local variable\n3. If calculated size is zero, set minimum allocation size to 1 byte\n4. Enter allocation retry loop that continues until memory is successfully allocated or all retry attempts exhausted\n5. Check if total allocation size exceeds maximum limit (0xffffffe0)\n6. If small-block allocator is enabled (DAT_6fa9e908 == 3), attempt fast allocation: round requested size up to 16-byte boundary, compare against size threshold (DAT_6fa9d8ec), acquire lock via __lock(4), call ___sbh_alloc_block() to allocate, release lock, if successful zero-initialize memory with _memset() and return\n7. If small-block allocation failed or disabled, fall back to standard Windows HeapAlloc(hHeap, HEAP_ZERO_MEMORY, allocSize)\n8. If HeapAlloc succeeds, return pointer immediately\n9. If allocation fails and custom new-handler exists (DAT_6fa910cc != 0), call __callnewh() to attempt recovery and retry loop if handler returns true\n10. Return NULL pointer if multiplication overflowed, size exceeds maximum, or all allocation attempts failed\n\nParameters:\n  elementCount: Number of elements to allocate (uint, stack parameter at EBP+0x8)\n  elementSize: Size of each element in bytes (uint, stack parameter at EBP+0xc)\n\nReturns:\n  void*: Pointer to zero-initialized memory block on success, NULL on integer overflow or allocation failure\n\nSpecial Cases:\n  - Multiplication overflow protection: Uses DIV limit comparison to prevent elementCount * elementSize overflow\n  - Zero-size allocation: Converts to 1-byte minimum allocation to avoid zero-size blocks\n  - Dual allocation path: Fast small-block allocator for allocations up to DAT_6fa9d8ec bytes, standard heap for larger allocations\n  - Out-of-memory retry: Calls __callnewh() new-handler up to system limit if allocation fails (simulates C++ new handler behavior)\n  - 16-byte alignment: Small-block allocations are rounded to 16-byte boundary for performance\n  - Memory zeroing: Both allocation paths return zero-initialized memory (no uninitialized data)\n\nGlobals Referenced:\n  DAT_6fa9e908 (small-block allocator control, 3=enabled, 0=disabled)\n  DAT_6fa9d8ec (small-block size limit threshold)\n  DAT_6fa9e904 (heap handle for HeapAlloc)\n  DAT_6fa910cc (new-handler function pointer)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:43c1542ced67dd840c298e093699fef1",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "43c1542ced67dd840c298e093699fef1",
        "CFG": "d59138f44100bd891d1023b7740338fc",
        "PRO": "57ee8bdaa95c30c0024d7d29efcd3fed"
      },
      "basic_block_counts": {
        "LoD/PD2": 18
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "D2gfx_MNE_124a050f7896": {
      "addresses": {
        "LoD/PD2": "0x6FA82D1C"
      },
      "rvas": {
        "LoD/PD2": "0x2D1C"
      },
      "sizes": {
        "LoD/PD2": 510
      },
      "name": "__ioinit",
      "signature": "int __ioinit(void)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __ioinit\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:124a050f7896343631e89fc5722f0cb0",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "124a050f7896343631e89fc5722f0cb0",
        "CFG": "ce64ccb286409da41a70a80f89bb0d66",
        "PRO": "b7e9f190915bf60352c9f769f724ae68"
      },
      "basic_block_counts": {
        "LoD/PD2": 46
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "D2gfx_MNE_5c819fccbe8b": {
      "addresses": {
        "LoD/PD2": "0x6FA82F1A"
      },
      "rvas": {
        "LoD/PD2": "0x2F1A"
      },
      "sizes": {
        "LoD/PD2": 76
      },
      "name": "__ioterm",
      "signature": "void __ioterm(void)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __ioterm\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:5c819fccbe8be253acb13e92783cc438",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "5c819fccbe8be253acb13e92783cc438",
        "CFG": "f586866415c40e4eaee67b5c40cac105",
        "PRO": "0f3f2b41b41c68cbecf26eb8dc291235"
      },
      "basic_block_counts": {
        "LoD/PD2": 10
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "D2gfx_MNE_d286a589c482": {
      "addresses": {
        "LoD/PD2": "0x6FA82F66"
      },
      "rvas": {
        "LoD/PD2": "0x2F66"
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
        "PRO": "74d799a671909ed3d5577284da53dde4"
      },
      "basic_block_counts": {
        "LoD/PD2": 20
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "D2gfx_MNE_5309cc011f44": {
      "addresses": {
        "LoD/PD2": "0x6FA8302D"
      },
      "rvas": {
        "LoD/PD2": "0x302D"
      },
      "sizes": {
        "LoD/PD2": 364
      },
      "name": "ParseCommandLine",
      "signature": "void ParseCommandLine(void * pArgvArray, int * pArgcCounter)",
      "calling_convention": "__cdecl",
      "comment": "Setting prototype: void ParseCommandLine(void * pArgvArray, int * pArgcCounter)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:5309cc011f4489e83a895a5a05ecc215",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "5309cc011f4489e83a895a5a05ecc215",
        "CFG": "3ea934a2e5c85f7db5c3bb685cae36af",
        "PRO": "36e0d78a3d023220332b738484bde0f4"
      },
      "basic_block_counts": {
        "LoD/PD2": 63
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "D2gfx_MNE_457ecf3d8055": {
      "addresses": {
        "LoD/PD2": "0x6FA83199"
      },
      "rvas": {
        "LoD/PD2": "0x3199"
      },
      "sizes": {
        "LoD/PD2": 162
      },
      "name": "__setargv",
      "signature": "int __setargv(void)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __setargv\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:457ecf3d8055d8e00a172b3d901a03ca",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "457ecf3d8055d8e00a172b3d901a03ca",
        "CFG": "9d95d0d72ba3d0f8ca13ab2ea583953f",
        "PRO": "5ad96e331bf4b08647e856f0d3858814"
      },
      "basic_block_counts": {
        "LoD/PD2": 9
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "D2gfx_MNE_ba896e89d5b4": {
      "addresses": {
        "LoD/PD2": "0x6FA8323B"
      },
      "rvas": {
        "LoD/PD2": "0x323B"
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
        "PRO": "9aae7029081f58fd7f3bf8884ac7dd35"
      },
      "basic_block_counts": {
        "LoD/PD2": 30
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "D2gfx_MNE_02783607761b": {
      "addresses": {
        "LoD/PD2": "0x6FA8335D"
      },
      "rvas": {
        "LoD/PD2": "0x335D"
      },
      "sizes": {
        "LoD/PD2": 26
      },
      "name": "___heap_select",
      "signature": "undefined4 ___heap_select(void)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Single Match\n ___heap_select\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:02783607761bb7b7f3ed068e856f0ca2",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "02783607761bb7b7f3ed068e856f0ca2",
        "CFG": "5373f71b1fc67ec2016d5dcfe49dc588",
        "PRO": "0f5dfc13e612e57657d5276531fcc30d"
      },
      "basic_block_counts": {
        "LoD/PD2": 4
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "D2gfx_MNE_057b2070bbbd": {
      "addresses": {
        "LoD/PD2": "0x6FA83377"
      },
      "rvas": {
        "LoD/PD2": "0x3377"
      },
      "sizes": {
        "LoD/PD2": 81
      },
      "name": "__heap_init",
      "signature": "int __heap_init(void)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __heap_init\n\nLibrary: Visual Studio 2003 Release",
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
      "basic_block_counts": {
        "LoD/PD2": 6
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "D2gfx_MNE_43c0a0116a01": {
      "addresses": {
        "LoD/PD2": "0x6FA833C8"
      },
      "rvas": {
        "LoD/PD2": "0x33C8"
      },
      "sizes": {
        "LoD/PD2": 127
      },
      "name": "__heap_term",
      "signature": "void __heap_term(void)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __heap_term\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:43c0a0116a0179cd961980d35fb0c190",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "43c0a0116a0179cd961980d35fb0c190",
        "CFG": "79578de49aac4c106e2830a21ae26f42",
        "PRO": "1c84f1d9bcb44421257bec902c52a670"
      },
      "basic_block_counts": {
        "LoD/PD2": 7
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "D2gfx_MNE_f17bdc134d98": {
      "addresses": {
        "LoD/PD2": "0x6FA83450"
      },
      "rvas": {
        "LoD/PD2": "0x3450"
      },
      "sizes": {
        "LoD/PD2": 61
      },
      "name": "__chkstk",
      "signature": "undefined __chkstk(void)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Single Match\n __chkstk\n\nLibraries: Visual Studio 2003 Debug, Visual Studio 2003 Release",
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
      "basic_block_counts": {
        "LoD/PD2": 5
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "D2gfx_MNE_79c576ae79b5": {
      "addresses": {
        "LoD/PD2": "0x6FA8348D"
      },
      "rvas": {
        "LoD/PD2": "0x348D"
      },
      "sizes": {
        "LoD/PD2": 356
      },
      "name": "__XcptFilter",
      "signature": "int __XcptFilter(ulong _ExceptionNum, _EXCEPTION_POINTERS * _ExceptionPtr)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __XcptFilter\n\nLibrary: Visual Studio 2003 Release",
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
      "basic_block_counts": {
        "LoD/PD2": 36
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "D2gfx_MNE_179c969cc717": {
      "addresses": {
        "LoD/PD2": "0x6FA835F1"
      },
      "rvas": {
        "LoD/PD2": "0x35F1"
      },
      "sizes": {
        "LoD/PD2": 27
      },
      "name": "___CppXcptFilter",
      "signature": "int ___CppXcptFilter(ulong _ExceptionNum, _EXCEPTION_POINTERS * _ExceptionPtr)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___CppXcptFilter\n\nLibrary: Visual Studio 2003 Release",
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
    "D2gfx_STR_f8f89093f5c5": {
      "addresses": {
        "LoD/PD2": "0x6FA8360C"
      },
      "rvas": {
        "LoD/PD2": "0x360C"
      },
      "sizes": {
        "LoD/PD2": 376
      },
      "name": "DisplayRuntimeError",
      "signature": "void DisplayRuntimeError(int nErrorCode)",
      "calling_convention": "__cdecl",
      "comment": "Displays a runtime error message dialog by looking up error codes in a dispatch table.\n\nAlgorithm:\n1. Initialize the stack frame and retrieve the error code parameter\n2. Check error code validity and search error dispatch table for matching entry\n3. Validate the error code is within valid range (0-254)\n4. Special case: If error code is 0xFC, skip message box display and return early\n5. Get the executable module filename using GetModuleFileNameA or use fallback name\n6. Build error message string by copying program name and error description\n7. Create message box structure with program name, error string, and caption\n8. Display the message box dialog to the user\n9. Validate security cookie before function return\n10. Clean up stack frame and return to caller\n\nParameters:\n- errorCode: integer error code to look up (0-254 are valid range)\n\nReturns:\n- void: function does not return a value\n\nSpecial Cases:\n- Error code 0xFC is special and prevents message box display\n- If GetModuleFileNameA fails, uses fallback program name\n- Message box behavior depends on global configuration flags\n- Security cookie validation detects stack corruption before return\n- Buffer sizes: 136 bytes for error message, 256 bytes for program name\n\nGlobal Data References:\n- Error dispatch table at 0x6fa8d744\n- String constants for error messages and captions\n- Configuration flags for debug/output modes\n- Security cookie value for stack protection",
      "name_source": "LoD/PD2",
      "method": "STR",
      "index": "STR:f8f89093f5c5a57c3cdd998b61227276",
      "indexes": {
        "EXP": null,
        "STR": "f8f89093f5c5a57c3cdd998b61227276",
        "API": null,
        "MNE": "907ddf19e9b559942986798c3a61049f",
        "CFG": "c304b1fa988d3a8a245e0f6e2f9547a8",
        "PRO": "deb21491b93d4bc32bfcc4de9e80b3b4"
      },
      "basic_block_counts": {
        "LoD/PD2": 18
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2gfx_MNE_e0686acda8da": {
      "addresses": {
        "LoD/PD2": "0x6FA83784"
      },
      "rvas": {
        "LoD/PD2": "0x3784"
      },
      "sizes": {
        "LoD/PD2": 57
      },
      "name": "__FF_MSGBANNER",
      "signature": "void __FF_MSGBANNER(void)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __FF_MSGBANNER\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:e0686acda8daa87f807e8c4bf4d7ccee",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "e0686acda8daa87f807e8c4bf4d7ccee",
        "CFG": "285d09a7e9b985b0b82a1cfce0632509",
        "PRO": "d14e87288f1edcde9f795a0be8b3979b"
      },
      "basic_block_counts": {
        "LoD/PD2": 7
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "D2gfx_MNE_b2a8f1a86586": {
      "addresses": {
        "LoD/PD2": "0x6FA837BD"
      },
      "rvas": {
        "LoD/PD2": "0x37BD"
      },
      "sizes": {
        "LoD/PD2": 16
      },
      "name": "___crtInitCritSecNoSpinCount@8",
      "signature": "undefined4 ___crtInitCritSecNoSpinCount@8(LPCRITICAL_SECTION param_1)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Single Match\n ___crtInitCritSecNoSpinCount@8\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:b2a8f1a86586c795d4e7ef4b4053c58e",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "b2a8f1a86586c795d4e7ef4b4053c58e",
        "CFG": null,
        "PRO": "c326151ae67f2d2727298a6f840be658"
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
    "D2gfx_STR_5fd0e2b0faef": {
      "addresses": {
        "LoD/PD2": "0x6FA837CD"
      },
      "rvas": {
        "LoD/PD2": "0x37CD"
      },
      "sizes": {
        "LoD/PD2": 103
      },
      "name": "___crtInitCritSecAndSpinCount",
      "signature": "undefined ___crtInitCritSecAndSpinCount(undefined4 param_1, undefined4 param_2)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___crtInitCritSecAndSpinCount\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "STR",
      "index": "STR:5fd0e2b0faef558a78531f73f4d372dd",
      "indexes": {
        "EXP": null,
        "STR": "5fd0e2b0faef558a78531f73f4d372dd",
        "API": null,
        "MNE": "3f585ab7136accb11659a7703e402a24",
        "CFG": "5a6a1bad4884a279605e3598d136f1d3",
        "PRO": "4b6df95541e95bfc1e5d3dacc7b41df8"
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
    "D2gfx_MNE_b1691d6b7b8b": {
      "addresses": {
        "LoD/PD2": "0x6FA83861"
      },
      "rvas": {
        "LoD/PD2": "0x3861"
      },
      "sizes": {
        "LoD/PD2": 9
      },
      "name": "GetThreadDataOffset",
      "signature": "int * GetThreadDataOffset(void)",
      "calling_convention": "__stdcall",
      "comment": "Retrieve pointer to thread-local data offset.\n\nAlgorithm:\n1. Call __getptd() to get current thread's _ptiddata structure\n2. Add offset 0x8 to the returned pointer (points to _terrno field)\n3. Return the adjusted pointer for thread-safe data access\n\nParameters:\n(none)\n\nReturns:\nint* - Pointer to offset +0x8 within _ptiddata (thread error number location)\n\nSpecial Cases:\n- This offset (0x8) corresponds to _terrno field in CRT's _ptiddata structure\n- Used by multiple C Runtime functions for thread-safe operations\n- Callers: __mtinitlocknum, __lseek, __write, __get_osfhandle, __close, __free_osfhnd, __commit, __lseeki64_lk, ___wctomb_mt\n\nStructure Layout:\n_ptiddata offsets (relevant fields):\n- 0x0: Base pointer\n- 0x8: _terrno (thread error number)",
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
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "D2gfx_MNE_b6f8c1079854": {
      "addresses": {
        "LoD/PD2": "0x6FA8386A"
      },
      "rvas": {
        "LoD/PD2": "0x386A"
      },
      "sizes": {
        "LoD/PD2": 115
      },
      "name": "__dosmaperr",
      "signature": "void __dosmaperr(ulong param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __dosmaperr\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:b6f8c10798544c3b39933775b55c5c07",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "b6f8c10798544c3b39933775b55c5c07",
        "CFG": "29c5b729a612738fb6e8cb90e950eb24",
        "PRO": "2d65459b47791d7f297e0e3d020297be"
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
    "D2gfx_MNE_059e9bb2efc1": {
      "addresses": {
        "LoD/PD2": "0x6FA838E0"
      },
      "rvas": {
        "LoD/PD2": "0x38E0"
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
        "PRO": "83d4ad65d30dc1f07c8c82e05909137c"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
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
    "D2gfx_MNE_cd4ab8e23ed6": {
      "addresses": {
        "LoD/PD2": "0x6FA83922"
      },
      "rvas": {
        "LoD/PD2": "0x3922"
      },
      "sizes": {
        "LoD/PD2": 104
      },
      "name": "__local_unwind2",
      "signature": "undefined __local_unwind2(int param_1, int param_2)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __local_unwind2\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:cd4ab8e23ed6997cd2e2434b8d375458",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "cd4ab8e23ed6997cd2e2434b8d375458",
        "CFG": "d7e92aa36e4ea61ef8903512dfbaf1bc",
        "PRO": "96e279d5a20df43edcc3895c7a47428d"
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
    "D2gfx_MNE_3e05470f02af": {
      "addresses": {
        "LoD/PD2": "0x6FA8398A"
      },
      "rvas": {
        "LoD/PD2": "0x398A"
      },
      "sizes": {
        "LoD/PD2": 35
      },
      "name": "__abnormal_termination",
      "signature": "int __abnormal_termination(void)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __abnormal_termination\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:3e05470f02af6f6fdd7e67f07762fb3b",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "3e05470f02af6f6fdd7e67f07762fb3b",
        "CFG": "754bfc5d47177c4cbdd43b336248c7ba",
        "PRO": "fe5cb0e5a5ea56f320d608d4f70e96f9"
      },
      "basic_block_counts": {
        "LoD/PD2": 4
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "D2gfx_MNE_c43b47bac3ec": {
      "addresses": {
        "LoD/PD2": "0x6FA839AD"
      },
      "rvas": {
        "LoD/PD2": "0x39AD"
      },
      "sizes": {
        "LoD/PD2": 9
      },
      "name": "__NLG_Notify1",
      "signature": "undefined __NLG_Notify1(undefined4 param_1)",
      "calling_convention": "__fastcall",
      "comment": "Library Function - Single Match\n __NLG_Notify1\n\nLibraries: Visual Studio 2017 Debug, Visual Studio 2017 Release, Visual Studio 2019 Debug, Visual Studio 2019 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:c43b47bac3ec2db7a3f12c66010e2c00",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "c43b47bac3ec2db7a3f12c66010e2c00",
        "CFG": null,
        "PRO": "555cd55f889764e835a20b5b89a0d79e"
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
    "D2gfx_MNE_ed17ad9d511f": {
      "addresses": {
        "LoD/PD2": "0x6FA839B6"
      },
      "rvas": {
        "LoD/PD2": "0x39B6"
      },
      "sizes": {
        "LoD/PD2": 24
      },
      "name": "SaveExceptionContext",
      "signature": "void SaveExceptionContext(int nHandlerAddress)",
      "calling_convention": "__stdcall",
      "comment": "Setting prototype: void __stdcall SaveExceptionContext(int nHandlerAddress)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:ed17ad9d511f6e330c2b6a62378d83cf",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "ed17ad9d511f6e330c2b6a62378d83cf",
        "CFG": "014d2069a1aece9d955ffb144dc9da61",
        "PRO": "4bd24b9c5472cb9ce1aa70b12ba2413a"
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
    "D2gfx_MNE_81bc6e282733": {
      "addresses": {
        "LoD/PD2": "0x6FA839CE"
      },
      "rvas": {
        "LoD/PD2": "0x39CE"
      },
      "sizes": {
        "LoD/PD2": 553
      },
      "name": "__ValidateEH3RN",
      "signature": "undefined4 __ValidateEH3RN(void * param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __ValidateEH3RN\n\nLibrary: Visual Studio 2003 Release",
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
      "basic_block_counts": {
        "LoD/PD2": 59
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2gfx_MNE_5f91c25bb129": {
      "addresses": {
        "LoD/PD2": "0x6FA83BF7"
      },
      "rvas": {
        "LoD/PD2": "0x3BF7"
      },
      "sizes": {
        "LoD/PD2": 116
      },
      "name": "__lseek_lk",
      "signature": "DWORD __lseek_lk(uint param_1, LONG param_2, DWORD param_3)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __lseek_lk\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:5f91c25bb1292543e16ed50f66b203fb",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "5f91c25bb1292543e16ed50f66b203fb",
        "CFG": "5c82fc7968d7374fca493214f8fae70c",
        "PRO": "9114d3bb6407dfa943df5db9e97165ad"
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
    "D2gfx_MNE_d016b68ecb5d": {
      "addresses": {
        "LoD/PD2": "0x6FA83ED2"
      },
      "rvas": {
        "LoD/PD2": "0x3ED2"
      },
      "sizes": {
        "LoD/PD2": 160
      },
      "name": "__lseek",
      "signature": "long __lseek(int _FileHandle, long _Offset, int _Origin)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __lseek\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:d016b68ecb5da6df87847adf03c73f3a",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "d016b68ecb5da6df87847adf03c73f3a",
        "CFG": "73b6fc3e113b5ff46b8a372f2e1c93fa",
        "PRO": "0f46c92f4225ad4c1700f510920e63f9"
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
    "D2gfx_MNE_d4c2d26a88b1": {
      "addresses": {
        "LoD/PD2": "0x6FA875D4"
      },
      "rvas": {
        "LoD/PD2": "0x75D4"
      },
      "sizes": {
        "LoD/PD2": 8
      },
      "name": "UnlockFileHandle",
      "signature": "void UnlockFileHandle(void)",
      "calling_convention": "__stdcall",
      "comment": "Unlocks a file handle that was previously locked during seek operations.\n\nAlgorithm:\n1. Accepts file handle in EBX register (implicit parameter from caller)\n2. Calls __unlock_fhandle to release the lock on the file handle\n3. Returns to caller with EBX preserved\n\nParameters:\nEBX (implicit): File handle to unlock\n\nReturns:\nvoid - No return value, side effect is unlocking the file handle\n\nSpecial Cases:\n- EBX must contain valid file handle from prior __lock_fhandle call\n- This is a thin wrapper around __unlock_fhandle\n- Used in lseek operation to ensure file state consistency",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:d4c2d26a88b113bd75739659d4ef7dd5",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "d4c2d26a88b113bd75739659d4ef7dd5",
        "CFG": null,
        "PRO": "855bb04f3093cd03c6fa492c21b5b936"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "D2gfx_MNE_478855be1acc": {
      "addresses": {
        "LoD/PD2": "0x6FA83D16"
      },
      "rvas": {
        "LoD/PD2": "0x3D16"
      },
      "sizes": {
        "LoD/PD2": 444
      },
      "name": "WriteFileWithTextMode",
      "signature": "int WriteFileWithTextMode(int nFileDescriptor, char * pszBuffer, uint dwBufferSize)",
      "calling_convention": "__cdecl",
      "comment": "Writes data to file with automatic text-mode LF to CRLF conversion.\n\nAlgorithm:\n1. Load stack canary value and store XOR with local buffer address for overflow detection\n2. Check if buffer size is 0 - return immediately if empty\n3. Extract file descriptor table entry: fd table index = (fd >> 5), fd offset = (fd & 0x1f) * 0x24\n4. Check file attributes at +4 for write-in-progress flag (0x20) - seek to EOF if set\n5. Load file descriptor handle from table entry at offset 0\n6. Test binary mode flag at offset +4 for 0x80 bit:\n   - If binary mode (bit set): write entire buffer directly via WriteFile()\n   - If text mode (bit clear): convert buffer converting LF (0x0a) to CRLF (0x0d0a)\n7. For text mode conversion:\n   a. Use 1024-byte stack buffer at [EBP-0x64] for conversion output\n   b. Scan source buffer byte-by-byte looking for newlines\n   c. When newline found (0x0a), insert CR (0x0d) before it in output buffer\n   d. Track count of inserted CRs in dwNewlineCount variable\n   e. When conversion buffer fills (0x400 bytes), write to file via WriteFile()\n   f. Continue until all source bytes processed or WriteFile() fails\n8. Handle write result: if WriteFile() returns false, call GetLastError() to get error code\n9. If write successful: subtract newline count from bytes written for accurate return value\n10. If error: check for access denied (error 5) and set appropriate errno value\n11. Check for EOF marker (0x1a at start) with append mode flag (0x40) for special handling\n12. Verify stack canary XOR to detect buffer overflow - call ValidateSecurityCookie()\n13. Return bytes written or -1 on error\n\nParameters:\nfileDescriptor: Integer file descriptor index from open file table\npBuffer: Pointer to data buffer to write to file\nbufferSize: Number of bytes in buffer to write\n\nReturns:\nEAX: Count of bytes written if successful (minus newlines for text mode)\nEAX: -1 (0xFFFFFFFF) on error (check errno via __dosmaperr)\n\nSpecial Cases:\n- Handles both text-mode (LF\u2192CRLF conversion) and binary mode writes\n- Respects file attributes: write-in-progress (0x20), binary (0x80), append (0x40)\n- Uses 1024-byte stack conversion buffer for text mode processing\n- Detects EOF marker (0x1a) at start of buffer for append mode error handling\n- Stack canary protection against buffer overflow with XOR validation\n- File descriptor entry is 0x24 bytes, indexed by (fd >> 5) in global table at 0x6fa9e920",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:478855be1acc46abf6139addf3589574",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "478855be1acc46abf6139addf3589574",
        "CFG": "94cee6e9046b74d001073808d4b21f34",
        "PRO": "367f991d527ce5aa39caa16e5996388f"
      },
      "basic_block_counts": {
        "LoD/PD2": 49
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "D2gfx_MNE_0c1662f4a708": {
      "addresses": {
        "LoD/PD2": "0x6FA83F7D"
      },
      "rvas": {
        "LoD/PD2": "0x3F7D"
      },
      "sizes": {
        "LoD/PD2": 68
      },
      "name": "__getbuf",
      "signature": "void __getbuf(FILE * _File)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __getbuf\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:0c1662f4a708ed2312320502a9057d72",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "0c1662f4a708ed2312320502a9057d72",
        "CFG": "ff62e17f392c986e4932f13239e39412",
        "PRO": "dab6c9d7f78e0bae4a830fbf28aa9591"
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
    "D2gfx_MNE_faa86e79d9b1": {
      "addresses": {
        "LoD/PD2": "0x6FA83FC1"
      },
      "rvas": {
        "LoD/PD2": "0x3FC1"
      },
      "sizes": {
        "LoD/PD2": 42
      },
      "name": "__isatty",
      "signature": "int __isatty(int _FileHandle)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __isatty\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:faa86e79d9b1980bad4d322b9925b87c",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "faa86e79d9b1980bad4d322b9925b87c",
        "CFG": "bc042e4f56c5c862716dd36277cac9ef",
        "PRO": "781c39fd821ede4092947ad96d3b6371"
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
    "D2gfx_MNE_ff70d7fac254": {
      "addresses": {
        "LoD/PD2": "0x6FA840FA"
      },
      "rvas": {
        "LoD/PD2": "0x40FA"
      },
      "sizes": {
        "LoD/PD2": 47
      },
      "name": "__lock_file",
      "signature": "void __lock_file(FILE * _File)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __lock_file\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:ff70d7fac2548b5958f726d1eeb33c1c",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "ff70d7fac2548b5958f726d1eeb33c1c",
        "CFG": "80845e7377749fe62fdfa1726193a977",
        "PRO": "bdcc10310114e6a4a06fe796c9423f20"
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
    "D2gfx_MNE_2221715ad392": {
      "addresses": {
        "LoD/PD2": "0x6FA84129"
      },
      "rvas": {
        "LoD/PD2": "0x4129"
      },
      "sizes": {
        "LoD/PD2": 35
      },
      "name": "__lock_file2",
      "signature": "void __lock_file2(int _Index, void * _File)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __lock_file2\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:2221715ad392d22929a667a9021e3f90",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "2221715ad392d22929a667a9021e3f90",
        "CFG": "d525801d8d00f8589c4fa0f08b524029",
        "PRO": "126aa142a63674eb0fefb7d150b2c70c"
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
    "D2gfx_MNE_2b72785c7d09": {
      "addresses": {
        "LoD/PD2": "0x6FA84150"
      },
      "rvas": {
        "LoD/PD2": "0x4150"
      },
      "sizes": {
        "LoD/PD2": 139
      },
      "name": "_strlen",
      "signature": "size_t _strlen(char * _Str)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n _strlen\n\nLibrary: Visual Studio",
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
    "D2gfx_MNE_ec2f8cff08d7": {
      "addresses": {
        "LoD/PD2": "0x6FA841DB"
      },
      "rvas": {
        "LoD/PD2": "0x41DB"
      },
      "sizes": {
        "LoD/PD2": 96
      },
      "name": "___wctomb_mt",
      "signature": "int ___wctomb_mt(int param_1, LPSTR param_2, WCHAR param_3)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___wctomb_mt\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:ec2f8cff08d73195854c9319296e0953",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "ec2f8cff08d73195854c9319296e0953",
        "CFG": "c7d6543ece662e7a8daf636bba0df188",
        "PRO": "955495a0724dbc44d82ddb123ab59f3b"
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
    "D2gfx_MNE_45f246afe326": {
      "addresses": {
        "LoD/PD2": "0x6FA8423B"
      },
      "rvas": {
        "LoD/PD2": "0x423B"
      },
      "sizes": {
        "LoD/PD2": 39
      },
      "name": "_wctomb",
      "signature": "int _wctomb(char * _MbCh, wchar_t _WCh)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n _wctomb\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:45f246afe326e6d5962c59d89124cdf0",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "45f246afe326e6d5962c59d89124cdf0",
        "CFG": "90c4f17418cec0d76ed106d2d34ca67f",
        "PRO": "37280dc610c502d174b731ec21cff03f"
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
    "D2gfx_MNE_9fd359b66679": {
      "addresses": {
        "LoD/PD2": "0x6FA84262"
      },
      "rvas": {
        "LoD/PD2": "0x4262"
      },
      "sizes": {
        "LoD/PD2": 41
      },
      "name": "report_failure",
      "signature": "undefined report_failure(void)",
      "calling_convention": "__cdecl",
      "comment": "Handles critical security failure and process termination.\n\nAlgorithm:\n1. Initialize structured exception handling (SEH) prologue\n2. Call HandleSecurityFailure with failure code 1\n3. Clear exception frame register (EBP - 0x4)\n4. Set exception context state to negative one (-1)\n5. Prepare ExitProcess parameters on stack\n6. Call ExitProcess function pointer at offset 0x6fa8d118\n7. Exit with code 3 indicating critical security failure\n\nParameters:\n  None - void function with no parameters\n\nReturns:\n  Never - function calls ExitProcess(3) which terminates process\n\nSpecial Cases:\n  SEH prolog ensures exception safety during failure handling\n  Exit code 3 signals critical security violation\n  Unreachable code exists at 0x6fa8427f-0x6fa84282 for exception recovery",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:9fd359b66679d8b6a2f1c57a264fe596",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "9fd359b66679d8b6a2f1c57a264fe596",
        "CFG": "6f3c48c8a30820a9a8a6c4f4ad80c87c",
        "PRO": "7ce90bc572fa01b68727725acd0e40b4"
      },
      "basic_block_counts": {
        "LoD/PD2": 5
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "D2gfx_MNE_4efdd923a388": {
      "addresses": {
        "LoD/PD2": "0x6FA84293"
      },
      "rvas": {
        "LoD/PD2": "0x4293"
      },
      "sizes": {
        "LoD/PD2": 14
      },
      "name": "ValidateSecurityCookie",
      "signature": "void ValidateSecurityCookie(uint dwComputedCookie)",
      "calling_convention": "__fastcall",
      "comment": "Validates a computed security cookie against a stored expected value to prevent stack buffer overflow attacks.\n\nAlgorithm:\n1. Compare the computed cookie value (passed in ECX) with the expected security cookie stored at 0x6fa906e0\n2. If both values match, return successfully to caller (validation passed)\n3. If values do not match, jump to security violation handler at 0x6fa8429c\n4. Call report_failure() to handle the security violation\n5. Terminate execution (report_failure does not return)\n\nParameters:\n  dwComputedCookie (ECX, uint): The computed security cookie value to validate\n\nReturns:\n  void - Returns normally on successful validation; terminates on failure\n\nSpecial Cases:\n  - Success path: Returns at 0x6fa8429b via RET instruction\n  - Failure path: Calls report_failure() which terminates execution\n  - Global security cookie: 0x6fa906e0 (g_dwStackCanaryValue)\n  - Critical security function: Validates stack canary to detect buffer overflows",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:4efdd923a388be710585d381cbbbfb83",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "4efdd923a388be710585d381cbbbfb83",
        "CFG": "74c44fff4d24f318587f22fc1085febb",
        "PRO": "b854477ab48fd898103e91790b07e027"
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
    "D2gfx_MNE_6b07f716ad39": {
      "addresses": {
        "LoD/PD2": "0x6FA842B0"
      },
      "rvas": {
        "LoD/PD2": "0x42B0"
      },
      "sizes": {
        "LoD/PD2": 149
      },
      "name": "__aulldvrm",
      "signature": "undefined8 __aulldvrm(uint param_1, uint param_2, uint param_3, uint param_4)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Single Match\n __aulldvrm\n\nLibrary: Visual Studio",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:6b07f716ad39855b07502ac9a8f75c79",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "6b07f716ad39855b07502ac9a8f75c79",
        "CFG": "af8f947cc0ba76aa1d310b52a6bb33e8",
        "PRO": "5d1977a5b94d5441fa3dfc6502a8e323"
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
    "D2gfx_MNE_45d24cae1027": {
      "addresses": {
        "LoD/PD2": "0x6FA84345"
      },
      "rvas": {
        "LoD/PD2": "0x4345"
      },
      "sizes": {
        "LoD/PD2": 27
      },
      "name": "__callnewh",
      "signature": "int __callnewh(size_t _Size)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __callnewh\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:45d24cae1027649da4393ef4c4f0d99b",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "45d24cae1027649da4393ef4c4f0d99b",
        "CFG": "c514545fcce289b8241e149ad12d442a",
        "PRO": "1a239adda4bf919457849b2c86ab32e6"
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
    "D2gfx_MNE_288a4a209e47": {
      "addresses": {
        "LoD/PD2": "0x6FA84360"
      },
      "rvas": {
        "LoD/PD2": "0x4360"
      },
      "sizes": {
        "LoD/PD2": 72
      },
      "name": "___sbh_heap_init",
      "signature": "undefined4 ___sbh_heap_init(undefined4 param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___sbh_heap_init\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:288a4a209e4706fee9d14eabda44517a",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "288a4a209e4706fee9d14eabda44517a",
        "CFG": "e8304c2afda95740a391a275b6b161fd",
        "PRO": "9f1660d8118e5e49801b0cc962b48d16"
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
    "D2gfx_MNE_565997ae4f13": {
      "addresses": {
        "LoD/PD2": "0x6FA843A8"
      },
      "rvas": {
        "LoD/PD2": "0x43A8"
      },
      "sizes": {
        "LoD/PD2": 43
      },
      "name": "___sbh_find_block",
      "signature": "uint ___sbh_find_block(int param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___sbh_find_block\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:565997ae4f137ad77dea012c57abbb1d",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "565997ae4f137ad77dea012c57abbb1d",
        "CFG": "dc0623423d93fb21da8f1c1461d32590",
        "PRO": "7e7b1615ff60a64a4c38d7e5028de2e5"
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
    "D2gfx_MNE_8b97ebec1e2b": {
      "addresses": {
        "LoD/PD2": "0x6FA843D3"
      },
      "rvas": {
        "LoD/PD2": "0x43D3"
      },
      "sizes": {
        "LoD/PD2": 792
      },
      "name": "___sbh_free_block",
      "signature": "undefined ___sbh_free_block(uint * param_1, int param_2)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___sbh_free_block\n\nLibrary: Visual Studio 2003 Release",
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
      "basic_block_counts": {
        "LoD/PD2": 50
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "D2gfx_MNE_8f7df14e6456": {
      "addresses": {
        "LoD/PD2": "0x6FA846EB"
      },
      "rvas": {
        "LoD/PD2": "0x46EB"
      },
      "sizes": {
        "LoD/PD2": 183
      },
      "name": "___sbh_alloc_new_region",
      "signature": "undefined4 * ___sbh_alloc_new_region(void)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Single Match\n ___sbh_alloc_new_region\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:8f7df14e6456cd93f8028b09582e6071",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "8f7df14e6456cd93f8028b09582e6071",
        "CFG": "cb06ff47489f56c99a3330662b09491b",
        "PRO": "8514add82471994c76bbda44fb229d03"
      },
      "basic_block_counts": {
        "LoD/PD2": 10
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "D2gfx_MNE_c41f2d1f421c": {
      "addresses": {
        "LoD/PD2": "0x6FA847A2"
      },
      "rvas": {
        "LoD/PD2": "0x47A2"
      },
      "sizes": {
        "LoD/PD2": 262
      },
      "name": "___sbh_alloc_new_group",
      "signature": "int ___sbh_alloc_new_group(int param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___sbh_alloc_new_group\n\nLibrary: Visual Studio 2003 Release",
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
    "D2gfx_MNE_71e3adec8688": {
      "addresses": {
        "LoD/PD2": "0x6FA848A8"
      },
      "rvas": {
        "LoD/PD2": "0x48A8"
      },
      "sizes": {
        "LoD/PD2": 735
      },
      "name": "___sbh_resize_block",
      "signature": "undefined4 ___sbh_resize_block(uint * param_1, int param_2, int param_3)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___sbh_resize_block\n\nLibraries: Visual Studio 2003 Release, Visual Studio 2005 Release",
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
      "basic_block_counts": {
        "LoD/PD2": 54
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "D2gfx_MNE_fdd552c17b8c": {
      "addresses": {
        "LoD/PD2": "0x6FA84B87"
      },
      "rvas": {
        "LoD/PD2": "0x4B87"
      },
      "sizes": {
        "LoD/PD2": 764
      },
      "name": "___sbh_alloc_block",
      "signature": "int * ___sbh_alloc_block(uint * param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___sbh_alloc_block\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:fdd552c17b8cb0117d531882b003b7d1",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "fdd552c17b8cb0117d531882b003b7d1",
        "CFG": "e7a6cc0f7e2b744a49f409c722178a75",
        "PRO": "1559a57ade30b5f6ba57711be4cddc15"
      },
      "basic_block_counts": {
        "LoD/PD2": 63
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2gfx_MNE_378e464c3884": {
      "addresses": {
        "LoD/PD2": "0x6FA861E0"
      },
      "rvas": {
        "LoD/PD2": "0x61E0"
      },
      "sizes": {
        "LoD/PD2": 672
      },
      "name": "_memcpy",
      "signature": "void * _memcpy(void * _Dst, void * _Src, size_t _Size)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n _memcpy\n\nLibraries: Visual Studio 2003 Debug, Visual Studio 2003 Release",
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
      "basic_block_counts": {
        "LoD/PD2": 63
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "D2gfx_MNE_1c8e05375765": {
      "addresses": {
        "LoD/PD2": "0x6FA851CD"
      },
      "rvas": {
        "LoD/PD2": "0x51CD"
      },
      "sizes": {
        "LoD/PD2": 208
      },
      "name": "___freetlocinfo",
      "signature": "undefined ___freetlocinfo(void * param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___freetlocinfo\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:1c8e05375765f5055ce29f9161a94626",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "1c8e05375765f5055ce29f9161a94626",
        "CFG": "2a44c087b9d456adf3f7fe671334cd08",
        "PRO": "0fba8337ab4b1c20571910d09f9b88ca"
      },
      "basic_block_counts": {
        "LoD/PD2": 21
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2gfx_MNE_81fc8ecddc12": {
      "addresses": {
        "LoD/PD2": "0x6FA8529D"
      },
      "rvas": {
        "LoD/PD2": "0x529D"
      },
      "sizes": {
        "LoD/PD2": 193
      },
      "name": "___updatetlocinfo_lk",
      "signature": "int ___updatetlocinfo_lk(void)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Single Match\n ___updatetlocinfo_lk\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:81fc8ecddc12cc08d3d848c0224bdeb0",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "81fc8ecddc12cc08d3d848c0224bdeb0",
        "CFG": "392d205942cc2d85569365d80a19246a",
        "PRO": "471fa8a57174ab7b60c33565cbbc850e"
      },
      "basic_block_counts": {
        "LoD/PD2": 24
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "D2gfx_MNE_202d2c66c8a5": {
      "addresses": {
        "LoD/PD2": "0x6FA8535E"
      },
      "rvas": {
        "LoD/PD2": "0x535E"
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
        "PRO": "81252cc8fdc5c04e7c68f83eccf0fbeb"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "D2gfx_MNE_ef80c025e383": {
      "addresses": {
        "LoD/PD2": "0x6FA85399"
      },
      "rvas": {
        "LoD/PD2": "0x5399"
      },
      "sizes": {
        "LoD/PD2": 47
      },
      "name": "MapLocaleErrorCode",
      "signature": "uint MapLocaleErrorCode(uint dwLocaleId)",
      "calling_convention": "__stdcall",
      "comment": "Maps Windows locale/code page identifiers to error codes.\n\nAlgorithm:\n1. Compare input locale ID against 932 (0x3a4) - Japanese\n   If match, return 0x411 (Japanese error code)\n2. Compare against 936 (0x3a8) - Simplified Chinese\n   If match, return 0x804 (Chinese error code)\n3. Compare against 949 (0x3b5) - Korean\n   If match, return 0x412 (Korean error code)\n4. Compare against 950 (0x3b6) - Traditional Chinese (Taiwan)\n   If match, return 0x404 (Taiwan error code)\n5. Default case: return 0 (no error mapping)\n\nParameters:\n  localeCodePage (EAX input) - Windows locale/code page identifier\n\nReturns:\n  EAX - Error code mapped to locale (0x411, 0x804, 0x412, 0x404) or 0 if no mapping\n\nSpecial Cases:\n  - Input values are Windows LCID code page identifiers:\n    932 = Japanese, 936 = Simplified Chinese, 949 = Korean, 950 = Taiwan\n  - Return values are Windows error codes specific to locale initialization failures\n  - Unknown locales return 0 (no error mapping defined)\n  - Uses optimized jump table encoding with arithmetic comparisons",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:ef80c025e3831b06764dc8da4f7409c0",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "ef80c025e3831b06764dc8da4f7409c0",
        "CFG": "13f82bf08155c5d52e60aaf4f0bc8edb",
        "PRO": "510c8731d2ed770a518dbde211133926"
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
    "D2gfx_MNE_3586df3e31dd": {
      "addresses": {
        "LoD/PD2": "0x6FA853C8"
      },
      "rvas": {
        "LoD/PD2": "0x53C8"
      },
      "sizes": {
        "LoD/PD2": 41
      },
      "name": "InitializeCharacterClassTable",
      "signature": "void InitializeCharacterClassTable(void)",
      "calling_convention": "__cdecl",
      "comment": "Initializes all character classification and code page conversion tables to zero.\n\nAlgorithm:\n1. Clear g_byCharClassTable (64 DWORDs + 1 BYTE) using REP STOSD and STOSB\n2. Clear g_dwCodePageTableInitFlag to 0\n3. Clear g_dwLeadByteTableInitFlag to 0\n4. Clear g_dwSingleByteTableInitFlag to 0\n5. Clear g_dwConversionTableFlags (3 consecutive DWORDs) using STOSD\n\nParameters:\nNone - Takes no parameters\n\nReturns:\nvoid - No return value\n\nSpecial Cases:\n- The character class table is 257 bytes total (64 DWORDs = 256 bytes + 1 BYTE padding)\n- All initialization flags are reset simultaneously\n- This function is part of code page initialization sequence\n- Called during program startup via InitializeCodePageConversionTables",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:3586df3e31dd0bc0a688e61a43024ab7",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "3586df3e31dd0bc0a688e61a43024ab7",
        "CFG": null,
        "PRO": "a7b46ffcf5c98a3dd42a4d49f8e4db0d"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "D2gfx_MNE_9dba01f3a3f5": {
      "addresses": {
        "LoD/PD2": "0x6FA853F1"
      },
      "rvas": {
        "LoD/PD2": "0x53F1"
      },
      "sizes": {
        "LoD/PD2": 411
      },
      "name": "InitializeCharacterConversionTables",
      "signature": "void InitializeCharacterConversionTables(void)",
      "calling_convention": "__stdcall",
      "comment": "Algorithm:\n1. Load security cookie seed from global (0x6fa906e0) and XOR with stack buffer address for protection\n2. Call GetCPInfo with current codepage/locale value to determine if multibyte support available\n3. If codepage available (multibyte support):\n   a. Initialize charMapBuffer with identity mapping (charMapBuffer[i]=i for 0-255)\n   b. Set charMapBuffer[0]=space (0x20) character\n   c. Process all lead byte ranges from codepage info structure:\n      - For each range pair in cpInfo.LeadByte, mark lead bytes as space (0x20)\n      - Use REP STOSD for quad-word fill efficiency, REP STOSB for remainder\n   d. Call ___crtGetStringTypeA to classify all 256 characters (alpha, digit, control flags)\n   e. Call ConvertStringWithLocaleMapping twice to generate lowercase and uppercase maps\n   f. Loop through all 256 characters:\n      - Test character type flags (cTypeArray) for alphabetic vs numeric classification\n      - Set appropriate conversion flag in g_byCharClassTable: 0x10 for letters, 0x20 for digits\n      - Store conversion value from lowerCaseMap or upperCaseMap to g_byCharConversionTable\n4. If codepage unavailable (ASCII-only fallback):\n   a. Loop through all 256 characters\n   b. For A-Z (0x41-0x5A): set flag 0x10, store +0x20 conversion\n   c. For a-z (0x61-0x7A): set flag 0x20, store -0x20 conversion\n   d. For all others: store 0 conversion\n5. Validate security cookie via XOR with stack buffer address before return\n\nParameters:\nvoid (no parameters)\n\nReturns:\nvoid (all results stored in global tables starting at 0x6fa9d6c1)\n\nSpecial Cases:\n- Multibyte lead bytes mapped to space character (0x20) in intermediate charMapBuffer\n- Character classification flags stored at g_byCharClassTable + offset per character\n- Conversion values stored at g_byCharConversionTable + offset per character\n- Security cookie prevents stack buffer overflow\n- ASCII fallback provides minimal ASCII letter case conversion without locale support",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:9dba01f3a3f519a348d690b818dfa854",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "9dba01f3a3f519a348d690b818dfa854",
        "CFG": "c3748a83d55213e3bfdbfd86de565dce",
        "PRO": "b9e1fed0f3439975f7b33064b4ed7850"
      },
      "basic_block_counts": {
        "LoD/PD2": 44
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "D2gfx_MNE_3b865c2f933c": {
      "addresses": {
        "LoD/PD2": "0x6FA8558C"
      },
      "rvas": {
        "LoD/PD2": "0x558C"
      },
      "sizes": {
        "LoD/PD2": 404
      },
      "name": "InitializeCodePageConversionTables",
      "signature": "void InitializeCodePageConversionTables(uint dwCodePage)",
      "calling_convention": "__cdecl",
      "comment": "Initialize code page conversion tables and character classification lookup tables.\n\nAlgorithm:\n1. Load and validate security cookie (XOR with EBP)\n2. Check if code page parameter is zero (SBCS default path)\n3. If non-zero, search code page table at 0x6fa90890 for matching entry\n4. If found in table, use cached single-byte/lead-byte tables\n5. If not found, call GetCPInfo API to retrieve code page information\n6. On success, initialize character classification table (0x6fa9d6c0) with 0x100 bytes\n7. Process code page character ranges from table at 0x6fa908a0\n8. Mark character classes in table based on range definitions (0x6fa90888)\n9. For single-byte code pages, mark trail bytes 0x01-0xFF with class 0x08\n10. Call MapLocaleErrorCode to populate conversion tables\n11. Cache conversion table pointers at 0x6fa9d7d0\n12. Set initialization flags (0x6fa9d6b4, 0x6fa9d7c4)\n13. Call InitializeCharacterConversionTables to complete setup\n14. Validate security cookie on exit and return status\n\nParameters:\ncodePage (uint): Code page identifier (0 = SBCS default, other = specific code page ID)\n\nReturns:\nEAX: Status code (0 = success, -1 = error or security failure)\n\nSpecial Cases:\n- Code page 0 triggers SBCS fallback path\n- GetCPInfo failure returns early with error status\n- Character ranges are 2-byte pairs (start, end) terminated with 0x0000\n- Trail byte table requires explicit marking to distinguish from lead bytes\n- Security cookie validation on exit prevents stack corruption",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:3b865c2f933cac7b684f56d2d74a981a",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "3b865c2f933cac7b684f56d2d74a981a",
        "CFG": "ce4fc93e06b599e45d0292f276757311",
        "PRO": "bc9f1202e5ca6d908fd11590b1869db4"
      },
      "basic_block_counts": {
        "LoD/PD2": 39
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2gfx_MNE_3d9593887473": {
      "addresses": {
        "LoD/PD2": "0x6FA85720"
      },
      "rvas": {
        "LoD/PD2": "0x5720"
      },
      "sizes": {
        "LoD/PD2": 327
      },
      "name": "__setmbcp",
      "signature": "int __setmbcp(int _CodePage)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __setmbcp\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:3d95938874732b844e73905e6c952bdf",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "3d95938874732b844e73905e6c952bdf",
        "CFG": "d245bd9dbf65e94abcf0220b460866eb",
        "PRO": "5d5093f2cef3d8934cadd541804d3896"
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
    "D2gfx_MNE_a4ba30fe4414": {
      "addresses": {
        "LoD/PD2": "0x6FA85870"
      },
      "rvas": {
        "LoD/PD2": "0x5870"
      },
      "sizes": {
        "LoD/PD2": 30
      },
      "name": "___initmbctable",
      "signature": "undefined4 ___initmbctable(void)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Single Match\n ___initmbctable\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:a4ba30fe4414581a89a628d047ff2406",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "a4ba30fe4414581a89a628d047ff2406",
        "CFG": "1abbbed88598ab76171d956e8b753f75",
        "PRO": "eb5613e38f147742faa8dc6fce55f1b8"
      },
      "basic_block_counts": {
        "LoD/PD2": 3
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "D2gfx_MNE_cb39780517b1": {
      "addresses": {
        "LoD/PD2": "0x6FA85890"
      },
      "rvas": {
        "LoD/PD2": "0x5890"
      },
      "sizes": {
        "LoD/PD2": 96
      },
      "name": "_memset",
      "signature": "void * _memset(void * _Dst, int _Val, size_t _Size)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n _memset\n\nLibraries: Visual Studio 2003 Debug, Visual Studio 2003 Release, Visual Studio 2019 Release",
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
      "basic_block_counts": {
        "LoD/PD2": 10
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "D2gfx_MNE_70593f43ea0b": {
      "addresses": {
        "LoD/PD2": "0x6FA858F0"
      },
      "rvas": {
        "LoD/PD2": "0x58F0"
      },
      "sizes": {
        "LoD/PD2": 7
      },
      "name": "CopyStringFast",
      "signature": "char * CopyStringFast(char * szDest, char * szSrc)",
      "calling_convention": "__cdecl",
      "comment": "Fast string copy optimized for performance using word-aligned copying and magic pattern null detection.\n\nAlgorithm:\n1. Check source pointer alignment (lower 2 bits)\n2. Copy bytes one at a time until 4-byte word alignment is achieved\n3. Enter main loop that reads 4 bytes at a time from aligned source\n4. Use XOR magic pattern (0x7efefeff) to detect null bytes without branching\n5. When pattern match indicates null terminator in word, determine byte position\n6. Copy final 1-3 bytes including null terminator based on null position\n7. Return destination pointer for function chaining\n\nParameters:\npDest: Destination buffer pointer (must be writable)\npSrc: Source null-terminated string pointer\n\nReturns:\nchar * - Pointer to destination buffer (same as pDest)\n\nSpecial Cases:\nMagic number pattern: (value XOR 0xffffffff XOR (value + 0x7efefeff)) & 0x81010100\nTests for any 0x00 byte in 32-bit word without branching, detects null at byte 0, 1, 2, or 3\nUnaligned source addresses handled by prefix byte copying until 4-byte alignment\nNull terminator always copied to destination and function returns immediately after\n\nStructure Layout:\nNone - operates on arbitrary character buffers",
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
    "D2gfx_MNE_f1c393de2fac": {
      "addresses": {
        "LoD/PD2": "0x6FA85900"
      },
      "rvas": {
        "LoD/PD2": "0x5900"
      },
      "sizes": {
        "LoD/PD2": 232
      },
      "name": "OptimizedStringCopy",
      "signature": "char * OptimizedStringCopy(char * pDestination, char * pSource)",
      "calling_convention": "__cdecl",
      "comment": "Optimized string copy using SWAR (SIMD Within A Register) null-byte detection.\n\nAlgorithm:\n1. Align source pointer to 4-byte boundary by copying individual bytes until aligned (skip if already aligned)\n2. Scan source using 4-byte aligned reads with magic constant 0x7efefeff for null-byte detection\n3. Locate exact null-terminator position (byte 0, 1, 2, or 3) within the final dword containing null\n4. Align destination pointer to 4-byte boundary by copying individual bytes until aligned (skip if already aligned)\n5. Copy aligned source to aligned destination using 4-byte bulk dword transfers\n6. Use same magic constant null-byte detection pattern during destination copy\n7. When null-byte detected, determine which byte contains null (0-3) and copy only needed bytes\n8. Write null terminator to destination and return original destination pointer\n\nParameters:\n  pDestination: Pointer to destination buffer for copied string (char *)\n  pSource: Pointer to source null-terminated string (char *)\n\nReturns:\n  Returns pDestination pointer unchanged, matching standard strcpy() behavior\n\nSpecial Cases:\n  - Handles misaligned source and destination pointers independently\n  - Uses 0x7efefeff SWAR magic constant to detect null bytes without branches\n  - Final dword processed byte-by-byte to correctly handle null terminators at any position\n  - Aligns each pointer separately before bulk copying\n\nStructure Layout:\n  N/A - operates on byte/dword buffers without structure interpretation",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:f1c393de2fac70496494aea734de5675",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "f1c393de2fac70496494aea734de5675",
        "CFG": "1ea5c571f30a096d65a25d6671cdf534",
        "PRO": "9507df991f535c513ad9f49c8a2bd9cf"
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
    "D2gfx_STR_d73f4455ba8d": {
      "addresses": {
        "LoD/PD2": "0x6FA859E8"
      },
      "rvas": {
        "LoD/PD2": "0x59E8"
      },
      "sizes": {
        "LoD/PD2": 249
      },
      "name": "___crtMessageBoxA",
      "signature": "int ___crtMessageBoxA(LPCSTR _LpText, LPCSTR _LpCaption, UINT _UType)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___crtMessageBoxA\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "STR",
      "index": "STR:d73f4455ba8d6ae05bafe5684bccdb5a",
      "indexes": {
        "EXP": null,
        "STR": "d73f4455ba8d6ae05bafe5684bccdb5a",
        "API": null,
        "MNE": "17ea33ac44dc56c9bc7a10bf336c7377",
        "CFG": "f15d897f6c6c56e92d0b1d7c22e06024",
        "PRO": "338c647f3f0c37bf3e9ead2103546b18"
      },
      "basic_block_counts": {
        "LoD/PD2": 21
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "D2gfx_MNE_3c09a404c09b": {
      "addresses": {
        "LoD/PD2": "0x6FA85AF0"
      },
      "rvas": {
        "LoD/PD2": "0x5AF0"
      },
      "sizes": {
        "LoD/PD2": 292
      },
      "name": "_strncpy",
      "signature": "char * _strncpy(char * _Dest, char * _Source, size_t _Count)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n _strncpy\n\nLibrary: Visual Studio",
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
      "basic_block_counts": {
        "LoD/PD2": 35
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "D2gfx_MNE_4f2706676636": {
      "addresses": {
        "LoD/PD2": "0x6FA85C14"
      },
      "rvas": {
        "LoD/PD2": "0x5C14"
      },
      "sizes": {
        "LoD/PD2": 127
      },
      "name": "__free_osfhnd",
      "signature": "int __free_osfhnd(int param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __free_osfhnd\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:4f2706676636b43aedddd6b436caf92b",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "4f2706676636b43aedddd6b436caf92b",
        "CFG": "f73903fbb6cc9dbfde125a44617f0909",
        "PRO": "3ad7e5872587a694dad5cade723ce138"
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
    "D2gfx_MNE_82290fd4a986": {
      "addresses": {
        "LoD/PD2": "0x6FA85C93"
      },
      "rvas": {
        "LoD/PD2": "0x5C93"
      },
      "sizes": {
        "LoD/PD2": 65
      },
      "name": "__get_osfhandle",
      "signature": "intptr_t __get_osfhandle(int _FileHandle)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __get_osfhandle\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:82290fd4a986eda931e519e307e93b03",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "82290fd4a986eda931e519e307e93b03",
        "CFG": "c52a6791feb5482e7402cc5b5f725b60",
        "PRO": "4d21701c626175e1d34d32f74f699c1e"
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
    "D2gfx_MNE_fd78a1cdcfba": {
      "addresses": {
        "LoD/PD2": "0x6FA85CD4"
      },
      "rvas": {
        "LoD/PD2": "0x5CD4"
      },
      "sizes": {
        "LoD/PD2": 148
      },
      "name": "__lock_fhandle",
      "signature": "int __lock_fhandle(int _Filehandle)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __lock_fhandle\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:fd78a1cdcfba52796c1191ac28710e53",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "fd78a1cdcfba52796c1191ac28710e53",
        "CFG": "73c70e2fccbc6347bc43a33ccc1cab5e",
        "PRO": "472e58ccef6c317df4671288b370a36c"
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
    "D2gfx_MNE_a5b5a435a005": {
      "addresses": {
        "LoD/PD2": "0x6FA85D74"
      },
      "rvas": {
        "LoD/PD2": "0x5D74"
      },
      "sizes": {
        "LoD/PD2": 34
      },
      "name": "__unlock_fhandle",
      "signature": "void __unlock_fhandle(int _Filehandle)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __unlock_fhandle\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:a5b5a435a00574933ae7bc271f1b0178",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "a5b5a435a00574933ae7bc271f1b0178",
        "CFG": null,
        "PRO": "ad182ad9df6c94ee55c475cfdb4e97f8"
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
    "D2gfx_MNE_96b57c2abe5d": {
      "addresses": {
        "LoD/PD2": "0x6FA85D96"
      },
      "rvas": {
        "LoD/PD2": "0x5D96"
      },
      "sizes": {
        "LoD/PD2": 131
      },
      "name": "__lseeki64_lk",
      "signature": "undefined8 __lseeki64_lk(uint param_1, LONG param_2, LONG param_3, DWORD param_4)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __lseeki64_lk\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:96b57c2abe5dc5792785a0347b715545",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "96b57c2abe5dc5792785a0347b715545",
        "CFG": "ef353e1a6ec60e54c1a32cd883661c5e",
        "PRO": "61e5e1a4ccd3db17bd2f4d111dba17ed"
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
    "D2gfx_MNE_eb37c10c6d65": {
      "addresses": {
        "LoD/PD2": "0x6FA85E19"
      },
      "rvas": {
        "LoD/PD2": "0x5E19"
      },
      "sizes": {
        "LoD/PD2": 146
      },
      "name": "__fcloseall",
      "signature": "int __fcloseall(void)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __fcloseall\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:eb37c10c6d65e405db05e051d6664293",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "eb37c10c6d65e405db05e051d6664293",
        "CFG": "cc556cd0606f776bb7c8ed11c66d7626",
        "PRO": "356fb2d8ba16020d5fde2a86b246daf7"
      },
      "basic_block_counts": {
        "LoD/PD2": 10
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "D2gfx_MNE_f370c563e34e": {
      "addresses": {
        "LoD/PD2": "0x6FA85EB4"
      },
      "rvas": {
        "LoD/PD2": "0x5EB4"
      },
      "sizes": {
        "LoD/PD2": 93
      },
      "name": "__flush",
      "signature": "int __flush(FILE * _File)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __flush\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:f370c563e34e7403c5a45d10fafb5c93",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "f370c563e34e7403c5a45d10fafb5c93",
        "CFG": "dcc2895e6645853551312dcb493406ae",
        "PRO": "723cef05dc4545566db8dcb5aa3068be"
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
    "D2gfx_MNE_29a9619b77ee": {
      "addresses": {
        "LoD/PD2": "0x6FA85F11"
      },
      "rvas": {
        "LoD/PD2": "0x5F11"
      },
      "sizes": {
        "LoD/PD2": 46
      },
      "name": "__fflush_lk",
      "signature": "int __fflush_lk(FILE * param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __fflush_lk\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:29a9619b77ee062a7363cd1953a97c8b",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "29a9619b77ee062a7363cd1953a97c8b",
        "CFG": "42bdec2f11c73aa6056b6c694ab2bc19",
        "PRO": "961257c1bf280df6cff6bb8dcd5c0793"
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
    "D2gfx_MNE_fcfd56bf5d47": {
      "addresses": {
        "LoD/PD2": "0x6FA85F3F"
      },
      "rvas": {
        "LoD/PD2": "0x5F3F"
      },
      "sizes": {
        "LoD/PD2": 182
      },
      "name": "FlushAllOpenFiles",
      "signature": "int FlushAllOpenFiles(int nFlushMode)",
      "calling_convention": "__cdecl",
      "comment": "Flushes all open file buffers with mode-specific behavior.\n\nAlgorithm:\n1. Initialize SEH protection frame for exception handling\n2. Initialize result counters (successCount=0, errorStatus=0)\n3. Acquire global file table lock to prevent concurrent access\n4. Loop through all file handles from index 0 to count-1\n5. For each file, check if pointer is non-NULL and flags valid (0x83)\n6. Skip file if NULL or flags invalid, proceed to next iteration\n7. Acquire per-file lock before accessing file structure\n8. Re-check file flags after lock acquisition (flags & 0x83 != 0)\n9. If flushMode==1: call __fflush_lk and increment successCount on success\n10. If flushMode==0: call __fflush_lk only if writable (flags & 0x2), set error on -1\n11. Release per-file lock after processing\n12. Continue to next file in loop\n13. Release global file table lock after all files processed\n14. Return successCount if flushMode==1, else return errorStatus\n\nParameters:\n- flushMode (int): 1=flush all files count successes, 0=flush writable only report errors\n\nReturns:\n- Success mode (1): Count of successfully flushed files\n- Error mode (0): Returns -1 if any flush error occurs, 0 if all succeed",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:fcfd56bf5d47e09a4b8d1ac9f65fc89f",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "fcfd56bf5d47e09a4b8d1ac9f65fc89f",
        "CFG": "76ee64efd521ccdda93299f40f5aa2f2",
        "PRO": "8abe68452be5a6474ec546198c7b5d04"
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
    "D2gfx_MNE_903bbffc430f": {
      "addresses": {
        "LoD/PD2": "0x6FA85FDF"
      },
      "rvas": {
        "LoD/PD2": "0x5FDF"
      },
      "sizes": {
        "LoD/PD2": 17
      },
      "name": "UnlockFileAtIndex",
      "signature": "void UnlockFileAtIndex(int nFileIndex, void * pFileStream)",
      "calling_convention": "__stdcall",
      "comment": "Unlocks a file stream at the specified index by delegating to __unlock_file2.\n\nAlgorithm:\n1. Load global file handle array base pointer from g_pFileHandleArray\n2. Calculate file entry address using array offset: base + nFileIndex * 4 (4-byte stride for FILE*)\n3. Dereference to get the FILE* at that offset\n4. Push the FILE* pointer onto stack\n5. Push nFileIndex parameter onto stack\n6. Call __unlock_file2 with both parameters to release locks\n7. Return via __stdcall convention (callee cleanup)\n\nParameters:\n- nFileIndex (int): Zero-based index into g_pFileHandleArray for file to unlock\n- pFileStream (void*): Pointer to FILE structure being unlocked\n\nReturns:\n- void: No return value\n\nSpecial Cases:\n- This is a thin wrapper around __unlock_file2\n- Array stride is 4 bytes indicating pointer-sized elements (FILE* pointers)\n- Part of the file I/O locking system used during file close operations\n- Called from FlushAllOpenFiles to clean up file handles\n\nStructure Layout:\nFile Handle Array (g_pFileHandleArray):\n- Each element is a FILE* pointer (4 bytes on 32-bit system)\n- Indexed by file number/index\n- Provides O(1) lookup for open file streams",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:903bbffc430fd56e85fa79d0fb445513",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "903bbffc430fd56e85fa79d0fb445513",
        "CFG": null,
        "PRO": "7d3a24d23656de6c387d12440774ccd3"
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
    "D2gfx_MNE_4af6f4d1378e": {
      "addresses": {
        "LoD/PD2": "0x6FA86026"
      },
      "rvas": {
        "LoD/PD2": "0x6026"
      },
      "sizes": {
        "LoD/PD2": 102
      },
      "name": "___security_init_cookie",
      "signature": "void ___security_init_cookie(void)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___security_init_cookie\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:4af6f4d1378e3b27617b296b4a2b16cc",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "4af6f4d1378e3b27617b296b4a2b16cc",
        "CFG": "290674f0d3e957f3a47123ff526d6d59",
        "PRO": "82c5d9ee064ddfeedda9b90f74345cd5"
      },
      "basic_block_counts": {
        "LoD/PD2": 6
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "D2gfx_STR_6829c7e2ecf5": {
      "addresses": {
        "LoD/PD2": "0x6FA8608C"
      },
      "rvas": {
        "LoD/PD2": "0x608C"
      },
      "sizes": {
        "LoD/PD2": 321
      },
      "name": "ReportSecurityFailureToUser",
      "signature": "void ReportSecurityFailureToUser(int nFailureType)",
      "calling_convention": "__stdcall",
      "comment": "Handles runtime security failures by displaying error information to user and terminating process.\n\nAlgorithm:\n1. Initialize stack frame with security cookie validation via XOR against global cookie at 0x6fa906e0\n2. Check if custom exception handler is registered at g_pSecurityFailureHandler (0x6fa910f4)\n3. If custom handler exists: invoke handler with failureTypeCode parameter and exit(3)\n4. If no handler: determine error message based on failureTypeCode:\n   - failureTypeCode == 1: display buffer overrun error (szBufferOverrunErrorTitle)\n   - failureTypeCode != 1: display unknown security error (szUnknownSecurityErrorTitle)\n5. Retrieve module filename using GetModuleFileNameA, fallback to szUnknownProgramName if failed\n6. Validate module name length: if (strlen + 0xb) exceeds 0x3c (60 bytes), truncate with szEllipsisMarker\n7. Build error message by concatenating components using OptimizedStringCopy:\n   - Error title message\n   - szMessageDivider separator line\n   - szProgramPrompt + module filename\n   - szMessageDivider separator line\n   - Detailed error explanation message\n8. Display MessageBox with combined error message and szRuntimeLibraryTitle, style 0x12010\n9. Call __exit(3) to terminate process immediately (no return)\n\nParameters:\nfailureTypeCode (int): Security failure type indicator\n  1 = Buffer overrun detected (stack or heap)\n  Other values = Unknown/generic security failure\n\nReturns:\nNone - function terminates via __exit(3) call, never returns to caller\n\nSpecial Cases:\n- Stack frame uses 0x118 (280) bytes for local buffers (szModuleFilename array is 0x104/260 bytes)\n- Implements stack canary validation via XOR cookie mechanism to prevent return address hijacking\n- Custom exception handler mechanism allows application-specific failure handling before exit\n- Module name truncated if exceeds 0x3c bytes to prevent buffer overflow in error message construction\n- __stdcall calling convention: failureTypeCode on stack, callee cleanup via RET 0x4\n\nStructure Layout:\nStack Frame Layout (EBP-relative):\n  Offset  Size  Field Name                  Type            Description\n  -0x1c   4     stackSecurityCookie         uint            XOR'd cookie for stack canary\n  -0x20   1     moduleNameInitFlag          byte            Initialization flag\n  -0x24   280   szModuleFilename            char[260]       Buffer for module path from GetModuleFileNameA\n  -0x118  varies pMessageBuilderBuffer      char*           Pointer to stack buffer for message construction\n  EBP+8   4     ehReturnAddress             void*           SEH exception handler registration\n  EBP+12  4     failureTypeCode             int             Failure code from caller",
      "name_source": "LoD/PD2",
      "method": "STR",
      "index": "STR:6829c7e2ecf5617d1af04a2d6d84fcdc",
      "indexes": {
        "EXP": null,
        "STR": "6829c7e2ecf5617d1af04a2d6d84fcdc",
        "API": null,
        "MNE": "fb8791c79d0f02127c874f5d44290f32",
        "CFG": "19efeacb1c9d9dd18ddc75b15dac67ba",
        "PRO": "e6d2e34250a19b565ffbc83696bc6053"
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
    "D2gfx_MNE_6b4ad6d2941b": {
      "addresses": {
        "LoD/PD2": "0x6FA8651D"
      },
      "rvas": {
        "LoD/PD2": "0x651D"
      },
      "sizes": {
        "LoD/PD2": 400
      },
      "name": "___free_lc_time",
      "signature": "undefined ___free_lc_time(undefined4 * param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___free_lc_time\n\nLibrary: Visual Studio 2003 Release",
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
    "D2gfx_MNE_f70a35b7fba7": {
      "addresses": {
        "LoD/PD2": "0x6FA866AD"
      },
      "rvas": {
        "LoD/PD2": "0x66AD"
      },
      "sizes": {
        "LoD/PD2": 95
      },
      "name": "___free_lconv_num",
      "signature": "undefined ___free_lconv_num(undefined4 * param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___free_lconv_num\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:f70a35b7fba7d58d54c96ad387278a4c",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "f70a35b7fba7d58d54c96ad387278a4c",
        "CFG": "cbfd3d0c7425038f32cd25a3cfec4b02",
        "PRO": "f3dee295e6e023fcee8064e8021ea5c8"
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
    "D2gfx_MNE_470047ed1f92": {
      "addresses": {
        "LoD/PD2": "0x6FA8670C"
      },
      "rvas": {
        "LoD/PD2": "0x670C"
      },
      "sizes": {
        "LoD/PD2": 217
      },
      "name": "___free_lconv_mon",
      "signature": "undefined ___free_lconv_mon(int param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___free_lconv_mon\n\nLibrary: Visual Studio 2003 Release",
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
      "basic_block_counts": {
        "LoD/PD2": 23
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2gfx_MNE_5f5a2dadfb6e": {
      "addresses": {
        "LoD/PD2": "0x6FA867F0"
      },
      "rvas": {
        "LoD/PD2": "0x67F0"
      },
      "sizes": {
        "LoD/PD2": 70
      },
      "name": "_strcspn",
      "signature": "size_t _strcspn(char * _Str, char * _Control)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n _strcspn\n\nLibrary: Visual Studio",
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
    "D2gfx_MNE_cf6e169535cd": {
      "addresses": {
        "LoD/PD2": "0x6FA86840"
      },
      "rvas": {
        "LoD/PD2": "0x6840"
      },
      "sizes": {
        "LoD/PD2": 135
      },
      "name": "_strcmp",
      "signature": "int _strcmp(char * _Str1, char * _Str2)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n _strcmp\n\nLibrary: Visual Studio 2003 Release",
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
      "basic_block_counts": {
        "LoD/PD2": 21
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "D2gfx_MNE_7cec3aaa3bf0": {
      "addresses": {
        "LoD/PD2": "0x6FA868D0"
      },
      "rvas": {
        "LoD/PD2": "0x68D0"
      },
      "sizes": {
        "LoD/PD2": 184
      },
      "name": "_memcmp",
      "signature": "int _memcmp(void * _Buf1, void * _Buf2, size_t _Size)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n _memcmp\n\nLibraries: Visual Studio 2003 Debug, Visual Studio 2003 Release",
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
      "basic_block_counts": {
        "LoD/PD2": 26
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "D2gfx_MNE_fe7518f9cbca": {
      "addresses": {
        "LoD/PD2": "0x6FA86988"
      },
      "rvas": {
        "LoD/PD2": "0x6988"
      },
      "sizes": {
        "LoD/PD2": 421
      },
      "name": "___crtGetStringTypeA",
      "signature": "BOOL ___crtGetStringTypeA(_locale_t _Plocinfo, DWORD _DWInfoType, LPCSTR _LpSrcStr, int _CchSrc, LPWORD _LpCharType, int _Code_page, BOOL _BError)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___crtGetStringTypeA\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:fe7518f9cbcae43d3194d5d079593073",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "fe7518f9cbcae43d3194d5d079593073",
        "CFG": "57a1818e074489c73b5b752558048ce6",
        "PRO": "7f14cc2a0f8ab60a20f51dd6aaa8be44"
      },
      "basic_block_counts": {
        "LoD/PD2": 33
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 7
      }
    },
    "D2gfx_MNE_1ca444181aa4": {
      "addresses": {
        "LoD/PD2": "0x6FA86B50"
      },
      "rvas": {
        "LoD/PD2": "0x6B50"
      },
      "sizes": {
        "LoD/PD2": 57
      },
      "name": "_strncmp",
      "signature": "int _strncmp(char * _Str1, char * _Str2, size_t _MaxCount)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n _strncmp\n\nLibraries: Visual Studio 2003 Debug, Visual Studio 2003 Release",
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
    "D2gfx_MNE_262b55d4b1f2": {
      "addresses": {
        "LoD/PD2": "0x6FA86B90"
      },
      "rvas": {
        "LoD/PD2": "0x6B90"
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
    "D2gfx_MNE_9202742c31e7": {
      "addresses": {
        "LoD/PD2": "0x6FA86BD0"
      },
      "rvas": {
        "LoD/PD2": "0x6BD0"
      },
      "sizes": {
        "LoD/PD2": 912
      },
      "name": "ConvertStringWithLocaleAndCodePage",
      "signature": "uint ConvertStringWithLocaleAndCodePage(uint sourceLocale, uint mapFlags, char * sourceString, uint sourceLength, char * outputBuffer, int outputSize, uint targetCodePage, int options)",
      "calling_convention": "__cdecl",
      "comment": "Converts a source string from one locale/codepage to another with optional locale-aware character mapping.\n\nAlgorithm:\n1. Initialize Unicode support detection by testing LCMapStringW availability\n2. Validate source length by scanning for null terminator if length indicates string bounds\n3. Based on Unicode support availability, execute one of two conversion paths:\n   - Path A (Unicode enabled): Convert source string to UTF-16, apply locale mapping, convert back to target codepage\n   - Path B (Unicode disabled or error): Use direct ANSI conversion with intermediate codepage if source differs from target\n4. Unicode Path A:\n   a. Call MultiByteToWideChar to convert source string to UTF-16 wide character buffer (uses targetCodePage if provided)\n   b. Allocate dynamic memory if stack space insufficient for wide character buffer\n   c. Apply locale-specific character mapping using LCMapStringW on wide character buffer with specified mapFlags\n   d. If mapFlags 0x400 clear (not output direct mapping): Allocate second buffer, apply second LCMapStringW, convert result to target codepage via WideCharToMultiByte\n   e. If mapFlags 0x400 set (output direct mapping): Copy mapping result directly to output buffer if size permits\n5. ANSI Path B:\n   a. Check if source codepage equals target codepage; if match, apply LCMapStringA directly\n   b. If codepages differ: Use ConvertStringBetweenCodepages to convert source string from source codepage to intermediate codepage\n   c. Allocate working buffer, apply LCMapStringA with mapping, convert back to target codepage\n6. Cleanup: Free all dynamically allocated temporary buffers\n7. Return character count of final conversion (0 on error)\n\nParameters:\nsourceLocale (uint) - Input locale for character mapping operations; uses g_dwDefaultLocale if 0\nmapFlags (uint) - LCMapStringA/W flags controlling case conversion, accent removal, etc.; bit 0x400 controls output format\nsourceString (char*) - Input string to convert\nsourceLength (uint) - Input string length in bytes; adjusted to actual length if null terminator found before length\noutputBuffer (char*) - Destination buffer for converted string\noutputSize (int) - Size of destination buffer in bytes; must accommodate output if 0 interpreted as \"size not checked\"\ntargetCodePage (uint) - Output code page (e.g., 932 for Shift-JIS, 950 for Big5); uses g_dwDefaultCodePage if 0\noptions (int) - Conversion options; non-zero enables flag 0x8 (error on invalid chars) in MultiByteToWideChar\n\nReturns:\nNumber of characters in final output buffer on success; 0 on error (allocation failure, invalid locale, unsupported codepage)\n\nSpecial Cases:\n- If sourceLength bytes end before null terminator, length adjusted to actual string length\n- Unicode support detected once and cached in g_dwUnicodeSupported (0=unknown, 1=enabled, 2=disabled)\n- If targetCodePage is 0, defaults to g_dwDefaultCodePage\n- If sourceLocale is 0, defaults to g_dwDefaultLocale\n- mapFlags 0x400 optimization: output from LCMapStringW copied directly to outputBuffer (assumes buffer large enough)\n- If source codepage equals target codepage: skips intermediate conversion, applies mapping directly via LCMapStringA\n- Memory allocation uses alloca for small buffers (<=0x5c bytes), malloc for larger allocations with automatic cleanup\n- All wide character buffers allocated with 4-byte alignment: (charCount*2+3) & 0xfffffffc",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:9202742c31e7fad9c07478efa934202a",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "9202742c31e7fad9c07478efa934202a",
        "CFG": "8183a7f0607acf623a593eb6dc2898ff",
        "PRO": "2fa82a885b7b21deeda5062e7ae2b880"
      },
      "basic_block_counts": {
        "LoD/PD2": 77
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 8
      }
    },
    "D2gfx_MNE_eb7ebe8853ab": {
      "addresses": {
        "LoD/PD2": "0x6FA86FA6"
      },
      "rvas": {
        "LoD/PD2": "0x6FA6"
      },
      "sizes": {
        "LoD/PD2": 76
      },
      "name": "__fclose_lk",
      "signature": "int __fclose_lk(FILE * param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __fclose_lk\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:eb7ebe8853ab4246d611f1ee5af2c48e",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "eb7ebe8853ab4246d611f1ee5af2c48e",
        "CFG": "9ee740eae2758b00f904633bf0c5e501",
        "PRO": "59cc5e5d7e9efa61c62c9b0e2b890a3a"
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
    "D2gfx_MNE_c2c985aace1b": {
      "addresses": {
        "LoD/PD2": "0x6FA86FF2"
      },
      "rvas": {
        "LoD/PD2": "0x6FF2"
      },
      "sizes": {
        "LoD/PD2": 70
      },
      "name": "_fclose",
      "signature": "int _fclose(FILE * _File)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n _fclose\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:c2c985aace1b860e9b2c7a02eacdf425",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "c2c985aace1b860e9b2c7a02eacdf425",
        "CFG": "ad9a3b392fcc54daf4951f4d77bab78e",
        "PRO": "0900b81e5c79afbfa69a5f63724808fc"
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
    "D2gfx_MNE_843e3db8ac56": {
      "addresses": {
        "LoD/PD2": "0x6FA87043"
      },
      "rvas": {
        "LoD/PD2": "0x7043"
      },
      "sizes": {
        "LoD/PD2": 177
      },
      "name": "__commit",
      "signature": "int __commit(int _FileHandle)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __commit\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:843e3db8ac5607bba3d919f4ee9bcace",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "843e3db8ac5607bba3d919f4ee9bcace",
        "CFG": "c64338b35f4925b491810d5442b0e1a1",
        "PRO": "a561dd229e0a5e35bf206607a9ea67c9"
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
    "D2gfx_MNE_cb7271f23b18": {
      "addresses": {
        "LoD/PD2": "0x6FA87100"
      },
      "rvas": {
        "LoD/PD2": "0x7100"
      },
      "sizes": {
        "LoD/PD2": 78
      },
      "name": "___ascii_stricmp",
      "signature": "int ___ascii_stricmp(char * _Str1, char * _Str2)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___ascii_stricmp\n\nLibraries: Visual Studio 2003 Debug, Visual Studio 2003 Release",
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
    "D2gfx_MNE_1bacf15d4212": {
      "addresses": {
        "LoD/PD2": "0x6FA8714E"
      },
      "rvas": {
        "LoD/PD2": "0x714E"
      },
      "sizes": {
        "LoD/PD2": 227
      },
      "name": "__resetstkoflw",
      "signature": "int __resetstkoflw(void)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __resetstkoflw\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:1bacf15d421243740ab5a96b430ce3dc",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "1bacf15d421243740ab5a96b430ce3dc",
        "CFG": "6a2c6063242729d398ada1dbe6ac7b2b",
        "PRO": "31e6dd745508ac7e7c438fa952787a61"
      },
      "basic_block_counts": {
        "LoD/PD2": 16
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "D2gfx_MNE_78a86de15981": {
      "addresses": {
        "LoD/PD2": "0x6FA87231"
      },
      "rvas": {
        "LoD/PD2": "0x7231"
      },
      "sizes": {
        "LoD/PD2": 136
      },
      "name": "_atol",
      "signature": "long _atol(char * _Str)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n _atol\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:78a86de15981e3f1c945cde9fbd4be9b",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "78a86de15981e3f1c945cde9fbd4be9b",
        "CFG": "f50e5479bfa840a829213102aed3c4ee",
        "PRO": "451179e85c2cf17b8f3986eecd429e08"
      },
      "basic_block_counts": {
        "LoD/PD2": 21
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2gfx_MNE_138cb9be9d7c": {
      "addresses": {
        "LoD/PD2": "0x6FA872B9"
      },
      "rvas": {
        "LoD/PD2": "0x72B9"
      },
      "sizes": {
        "LoD/PD2": 71
      },
      "name": "GetLocaleDefaultCode",
      "signature": "void GetLocaleDefaultCode(LCID localeId)",
      "calling_convention": "__cdecl",
      "comment": "Retrieves the default ANSI code page for a specified locale.\n\nAlgorithm:\n1. Initialize security cookie by XORing global cookie with stack frame address\n2. Allocate 6-byte buffer on stack for code page string\n3. Call GetLocaleInfoA with LOCALE_IDEFAULTANSICODEPAGE (0x1004) to retrieve locale code page\n4. If GetLocaleInfoA succeeds, convert string buffer to integer using _atol\n5. Verify security cookie integrity before function return\n\nParameters:\n  LCID localeId - The locale identifier specifying which locale's code page to retrieve\n\nReturns:\n  void - Function does not return a value; operates for side effects\n\nSpecial Cases:\n  - If GetLocaleInfoA returns 0, the function skips _atol conversion and returns error code 0xFFFFFFFF in EAX\n  - Security cookie validation prevents stack buffer overflow exploitation\n  - Code page string is stored in 6-byte buffer (enough for decimal representation of code pages up to 65535)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:138cb9be9d7caeaaa6cff721ddf1f5fa",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "138cb9be9d7caeaaa6cff721ddf1f5fa",
        "CFG": "e6239802a5b3e3dd1f1be91f0d5c374d",
        "PRO": "2b7ee2ed533ada25ae1d43eebe0f4f52"
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
    "D2gfx_MNE_a82412e86c7e": {
      "addresses": {
        "LoD/PD2": "0x6FA87300"
      },
      "rvas": {
        "LoD/PD2": "0x7300"
      },
      "sizes": {
        "LoD/PD2": 451
      },
      "name": "ConvertStringBetweenCodepages",
      "signature": "uint ConvertStringBetweenCodepages(uint sourceCodePage, uint targetCodePage, char * sourceString, uint * pSourceLength, LPSTR targetBuffer, int targetBufferSize)",
      "calling_convention": "__cdecl",
      "comment": "Converts a string between different Windows code pages using wide character intermediate format.\n\nAlgorithm:\n1. Verify source and target code pages are different; exit immediately if identical\n2. Query GetCPInfo for source code page to verify validity and determine MaxCharSize\n3. Query GetCPInfo for target code page to verify validity and determine MaxCharSize\n4. If both code pages have MaxCharSize == 1 (single-byte), set optimization flag\n5. If source length is -1 (null-terminated), call strlen to calculate actual string length and add 1\n6. For multi-byte conversions, call MultiByteToWideChar with query mode (NULL buffer) to determine wide char buffer size needed\n7. Allocate wide character buffer (stack if <100 bytes, else heap)\n8. Initialize wide character buffer with _memset\n9. Call MultiByteToWideChar to convert source string to UTF-16 format\n10. If target buffer provided, call WideCharToMultiByte to convert wide chars directly to target buffer\n11. If no target buffer provided, call WideCharToMultiByte with NULL to determine output size\n12. Allocate heap memory for converted result string\n13. Call WideCharToMultiByte to perform final conversion to target code page\n14. If source length was -1, update *pSourceLength with output character count\n15. Free any heap-allocated buffers\n16. Return output character count in EAX, or 0 on error\n\nParameters:\n- sourceCodePage: Windows code page identifier for source string (e.g., 1252, 932, 65001)\n- targetCodePage: Windows code page identifier for target encoding (e.g., 1252, 932, 65001)\n- sourceString: Pointer to input string encoded in sourceCodePage\n- pSourceLength: Pointer to source length in bytes; -1 means null-terminated string\n- targetBuffer: Output buffer for converted string; NULL to allocate and return new buffer\n- targetBufferSize: Size of targetBuffer in bytes (ignored if targetBuffer is NULL)\n\nReturns:\n- Success (non-zero): Number of characters in converted output (including null terminator)\n- Failure (zero): Conversion error or allocation failure\n\nSpecial Cases:\n- Codepages identical: Returns immediately without conversion\n- sourceCodePage or targetCodePage invalid: Returns 0\n- Both codepages single-byte: Enables optimization for faster conversion\n- targetBuffer NULL: Allocates heap memory for result; caller must free returned pointer\n- sourceLength -1: Indicates null-terminated input; output length stored back to *pSourceLength\n- Allocation failure: Returns NULL/0; existing buffers properly freed",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:a82412e86c7e059d3af6ea9d376e2875",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "a82412e86c7e059d3af6ea9d376e2875",
        "CFG": "81c39b208974ac6c9218e664489883be",
        "PRO": "aa03c89786ce0468d54ee28bd1796c9a"
      },
      "basic_block_counts": {
        "LoD/PD2": 63
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 6
      }
    },
    "D2gfx_MNE_1819fca98b14": {
      "addresses": {
        "LoD/PD2": "0x6FA874DA"
      },
      "rvas": {
        "LoD/PD2": "0x74DA"
      },
      "sizes": {
        "LoD/PD2": 131
      },
      "name": "__close_lk",
      "signature": "undefined4 __close_lk(uint param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __close_lk\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:1819fca98b14dcf51dff412defb1fa98",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "1819fca98b14dcf51dff412defb1fa98",
        "CFG": "9500af2f143a2d3834ce5f07053858f9",
        "PRO": "bf0cd87fa3c4880c14b210531c83ee5a"
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
    "D2gfx_MNE_b5e8d68191f2": {
      "addresses": {
        "LoD/PD2": "0x6FA8755D"
      },
      "rvas": {
        "LoD/PD2": "0x755D"
      },
      "sizes": {
        "LoD/PD2": 144
      },
      "name": "__close",
      "signature": "int __close(int _FileHandle)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __close\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:b5e8d68191f204e2d43adbcf540da123",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "b5e8d68191f204e2d43adbcf540da123",
        "CFG": "661b2abc615a7cfef1d7c22a6acb0d5d",
        "PRO": "f4b81e70abfd387ddf30caeb5b8ec2c1"
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
    "D2gfx_MNE_f38bb98de0ca": {
      "addresses": {
        "LoD/PD2": "0x6FA875F8"
      },
      "rvas": {
        "LoD/PD2": "0x75F8"
      },
      "sizes": {
        "LoD/PD2": 43
      },
      "name": "__freebuf",
      "signature": "void __freebuf(FILE * _File)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __freebuf\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:f38bb98de0cae7e771d97b2937aba094",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "f38bb98de0cae7e771d97b2937aba094",
        "CFG": "ea03c6407b4d091868dce8d0baf95212",
        "PRO": "129d77d31b891c9523d1955fbefba481"
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
    "D2gfx_MNE_93d0dc9fd831": {
      "addresses": {
        "LoD/PD2": "0x6FA87623"
      },
      "rvas": {
        "LoD/PD2": "0x7623"
      },
      "sizes": {
        "LoD/PD2": 119
      },
      "name": "___isctype_mt",
      "signature": "uint ___isctype_mt(void * this, int param_1, int param_2, uint param_3)",
      "calling_convention": "__thiscall",
      "comment": "Library Function - Single Match\n ___isctype_mt\n\nLibrary: Visual Studio 2003 Release",
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
      "basic_block_counts": {
        "LoD/PD2": 9
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 4
      }
    },
    "D2gfx_MNE_d54b31472f74": {
      "addresses": {
        "LoD/PD2": "0x6FA876A0"
      },
      "rvas": {
        "LoD/PD2": "0x76A0"
      },
      "sizes": {
        "LoD/PD2": 52
      },
      "name": "__allmul",
      "signature": "longlong __allmul(uint param_1, int param_2, uint param_3, int param_4)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Single Match\n __allmul\n\nLibrary: Visual Studio",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:d54b31472f74b078be31f20f65c7b2d3",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "d54b31472f74b078be31f20f65c7b2d3",
        "CFG": "667714027c789a8b486a563a19e4b634",
        "PRO": "3eabd37b619c8c857e7d42508a357bb6"
      },
      "basic_block_counts": {
        "LoD/PD2": 3
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 4
      }
    },
    "D2gfx_MNE_ecf4fe5a7e47": {
      "addresses": {
        "LoD/PD2": "0x6FA876E0"
      },
      "rvas": {
        "LoD/PD2": "0x76E0"
      },
      "sizes": {
        "LoD/PD2": 97
      },
      "name": "___ascii_strnicmp",
      "signature": "int ___ascii_strnicmp(char * _Str1, char * _Str2, size_t _MaxCount)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___ascii_strnicmp\n\nLibraries: Visual Studio 2003 Debug, Visual Studio 2003 Release",
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
    "D2gfx_MNE_3ecdb5e459e2": {
      "addresses": {
        "LoD/PD2": "0x6FA87750"
      },
      "rvas": {
        "LoD/PD2": "0x7750"
      },
      "sizes": {
        "LoD/PD2": 5
      },
      "name": "DecrementValue",
      "signature": "int DecrementValue(int nUnused, int nValue)",
      "calling_convention": "__fastcall",
      "comment": "Setting prototype: int DecrementValue(int nUnused, int nValue)",
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
    "D2gfx_MNE_e3e7225badfc": {
      "addresses": {
        "LoD/PD2": "0x6FA878BC"
      },
      "rvas": {
        "LoD/PD2": "0x78BC"
      },
      "sizes": {
        "LoD/PD2": 6
      },
      "name": "RtlUnwind",
      "signature": "void RtlUnwind(PVOID TargetFrame, PVOID TargetIp, PEXCEPTION_RECORD ExceptionRecord, PVOID ReturnValue)",
      "calling_convention": "__stdcall",
      "comment": "Thunk function that delegates to the actual RtlUnwind implementation.\n\nAlgorithm:\n1. Jump to the actual RtlUnwind function implementation via pointer indirection\n2. The actual implementation is loaded at runtime from g_pRtlUnwindImpl\n\nParameters:\nTargetFrame: PVOID - Frame pointer to target for stack unwinding\nTargetIp: PVOID - Instruction pointer to return to after unwinding\nExceptionRecord: PEXCEPTION_RECORD - Exception record containing exception details\nReturnValue: PVOID - Value to return from unwinding\n\nReturns:\nvoid - This function does not return normally; control transfers to TargetIp\n\nSpecial Cases:\nThis is a thunk wrapper that performs indirect jumps to the actual implementation. The actual RtlUnwind semantics are defined by the Microsoft C runtime exception handling mechanism. This function is called during stack unwinding when exiting nested exception handlers.",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:e3e7225badfcf3c2e051c42d71d7237a",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "e3e7225badfcf3c2e051c42d71d7237a",
        "CFG": null,
        "PRO": "08ad83d48608045113c32e66db90b7f6"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "D2gfx_MNE_3a966d378a12": {
      "addresses": {
        "LoD/PD2": "0x6FA8785A"
      },
      "rvas": {
        "LoD/PD2": "0x785A"
      },
      "sizes": {
        "LoD/PD2": 61
      },
      "name": "~type_info",
      "signature": "void ~type_info(type_info * this)",
      "calling_convention": "__thiscall",
      "comment": "Library Function - Single Match\n public: virtual __thiscall type_info::~type_info(void)\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:3a966d378a126a76a245d88e9b060455",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "3a966d378a126a76a245d88e9b060455",
        "CFG": "58f038befe5bbad46706be039b30588a",
        "PRO": "65a4d016a0c4bd915eaf066a72d989a2"
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
    "D2gfx_MNE_fcd666aa0beb": {
      "addresses": {
        "LoD/PD2": "0x6FA878A0"
      },
      "rvas": {
        "LoD/PD2": "0x78A0"
      },
      "sizes": {
        "LoD/PD2": 28
      },
      "name": "ScalarDeletingDestructor",
      "signature": "void * ScalarDeletingDestructor(type_info * this, type_info * pThis, uint bDeleteObject)",
      "calling_convention": "__thiscall",
      "comment": "Setting prototype: void * ScalarDeletingDestructor(type_info *pThis, uint bDeleteObject)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:fcd666aa0beb6eec15da06c485365b59",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "fcd666aa0beb6eec15da06c485365b59",
        "CFG": "e67ee52de705150869e2ef2baa9939af",
        "PRO": "fa7794653567332e53edd286ac59d4fd"
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
    "D2gfx_MNE_a5c53e09069a": {
      "addresses": {
        "LoD/PD2": "0x6FA878D0"
      },
      "rvas": {
        "LoD/PD2": "0x78D0"
      },
      "sizes": {
        "LoD/PD2": 25
      },
      "name": "ShowD2GfxErrorMessageBox",
      "signature": "int ShowD2GfxErrorMessageBox(char * szErrorMessage)",
      "calling_convention": "__stdcall",
      "comment": "Display a Diablo II graphics error message using a Windows message box.\n\nAlgorithm:\n1. Call MessageBoxA with error message string\n2. Set parent window to NULL (desktop)\n3. Use title string \"D2Gfx.DLL\" from data section\n4. Set flags to MB_ICONEXCLAMATION | MB_APPLMODAL (0x2010)\n5. Return 1 to indicate success\n\nParameters:\npErrorMessage: Pointer to null-terminated error string to display\n\nReturns:\nReturns 1 (success) regardless of user button selection\n\nSpecial Cases:\n- This is a simple wrapper around Windows MessageBoxA\n- The parent window handle is NULL, making the dialog application-modal\n- Used for displaying D2Gfx.dll initialization or rendering errors",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:a5c53e09069a3cbd3f14c736c4627d39",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "a5c53e09069a3cbd3f14c736c4627d39",
        "CFG": null,
        "PRO": "e192a846737da6a18315a150fa000325"
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
    "D2gfx_MNE_6aa86ec09ed7": {
      "addresses": {
        "LoD/PD2": "0x6FA878F0"
      },
      "rvas": {
        "LoD/PD2": "0x78F0"
      },
      "sizes": {
        "LoD/PD2": 16
      },
      "name": "TerminateCurrentProcess",
      "signature": "void TerminateCurrentProcess(void)",
      "calling_convention": "__stdcall",
      "comment": "Terminates the current process immediately.\n\nAlgorithm:\n1. Retrieve the handle to the current process via GetCurrentProcess\n2. Call TerminateProcess with the process handle and exit code -1\n3. Function does not return (process is terminated)\n\nParameters:\nNone\n\nReturns:\nDoes not return - process is terminated with exit code -1\n\nSpecial Cases:\n- Exit code is -1 (0xFFFFFFFF), indicating abnormal termination\n- This is typically called from error handlers or fatal conditions\n- No cleanup is performed before termination\n- Process termination is immediate and cannot be prevented\n\nStructure Layout:\nN/A - no structure access",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:6aa86ec09ed704c2fa671b5f49de77d0",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "6aa86ec09ed704c2fa671b5f49de77d0",
        "CFG": null,
        "PRO": "3e1c5674e1c8446c34b099eaeccae200"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "D2gfx_STR_223f446ba4dc": {
      "addresses": {
        "LoD/PD2": "0x6FA87910"
      },
      "rvas": {
        "LoD/PD2": "0x7910"
      },
      "sizes": {
        "LoD/PD2": 114
      },
      "name": "HandleAssertionFailure",
      "signature": "bool HandleAssertionFailure(void)",
      "calling_convention": "__stdcall",
      "comment": "Handles assertion failures by invoking optional callback, displaying error dialog, and handling user response.\n\nAlgorithm:\n1. Load global callback function pointer from g_pfnAssertionCallback\n2. If callback is registered (non-NULL), invoke it to perform pre-dialog cleanup\n3. Allocate 512-byte stack buffer for error message formatting\n4. Format assertion error message using wsprintfA with file and line information\n5. Call MessageBoxA to display error dialog with Retry/Cancel buttons\n6. Test user response: if Retry (3), proceed to step 7; if Cancel (4), proceed to step 8; otherwise proceed to step 8\n7. If Retry selected: Get current process handle via GetCurrentProcess, terminate with exit code 0xFFFFFFFF (-1), return true\n8. If Cancel or other response: Return false to allow execution to continue\n\nParameters:\nNone - Function has no explicit parameters. Callback address in g_pfnAssertionCallback acts as implicit global state.\n\nReturns:\nbool - Returns true if user selected Retry (process will be terminated immediately via TerminateProcess)\nbool - Returns false if user selected Cancel or any other response (allows execution to continue)\n\nSpecial Cases:\n- MessageBox flags 0x52212 = MB_RETRYCANCEL (0x00002) | MB_TASKMODAL (0x00200) | 0x50000\n- Dialog is centered on screen with NULL window handle\n- Process termination uses exit code 0xFFFFFFFF (-1) to indicate assertion failure\n- Global callback g_pfnAssertionCallback may be NULL (safely skipped if not registered)\n- Error message buffer is 512 bytes allocated on stack (offset -0x200 from stack frame)",
      "name_source": "LoD/PD2",
      "method": "STR",
      "index": "STR:223f446ba4dc89ad022ef5577899b4a7",
      "indexes": {
        "EXP": null,
        "STR": "223f446ba4dc89ad022ef5577899b4a7",
        "API": null,
        "MNE": "5a687908f8a4d403eafd20c027eb8bf5",
        "CFG": "d2f0c9b853189ba00328390d42b83a84",
        "PRO": "89640140ffbb3aec9b44ecae45a73a49"
      },
      "basic_block_counts": {
        "LoD/PD2": 6
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "D2gfx_MNE_b5629b4d48f3": {
      "addresses": {
        "LoD/PD2": "0x6FA87990"
      },
      "rvas": {
        "LoD/PD2": "0x7990"
      },
      "sizes": {
        "LoD/PD2": 37
      },
      "name": "TerminateWithD2GfxError",
      "signature": "void TerminateWithD2GfxError(LPCSTR pErrorMessage)",
      "calling_convention": "__stdcall",
      "comment": "Displays a fatal error message dialog and terminates the current process.\n\nAlgorithm:\n1. Accept error message string pointer in EAX register\n2. Display error dialog using MessageBoxA with D2Gfx DLL title\n3. Call GetCurrentProcess to obtain current process handle\n4. Terminate the process with exit code 0xFFFFFFFF (-1)\n5. Return zero (unreachable due to process termination)\n\nParameters:\npErrorMessage - Pointer to null-terminated error message string displayed in dialog\n\nReturns:\nvoid - Function does not return; process is terminated\n\nSpecial Cases:\n- Uses __stdcall calling convention with EAX implicit parameter\n- Dialog uses MB_YESNO | MB_DEFBUTTON1 style (0x2010 = 0x4 | 0x2000)\n- Exit code 0xFFFFFFFF indicates fatal error/forced termination\n- Function references D2Gfx DLL name at 0x6fa8e300\n\nStructure Layout:\nNo structured data accessed in this function",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:b5629b4d48f367068efe0a60d48819eb",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "b5629b4d48f367068efe0a60d48819eb",
        "CFG": null,
        "PRO": "efdf0caa95724aa54df6213c068f018d"
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
    "D2gfx_STR_33bd722168bf": {
      "addresses": {
        "LoD/PD2": "0x6FA879C0"
      },
      "rvas": {
        "LoD/PD2": "0x79C0"
      },
      "sizes": {
        "LoD/PD2": 116
      },
      "name": "InitializeErrorHandler",
      "signature": "void InitializeErrorHandler(uint dwErrorCode)",
      "calling_convention": "__stdcall",
      "comment": "Initializes error handler and validates handler function pointers before error message formatting.\n\nAlgorithm:\n1. Load handler base pointer from global data (0x6fa9d670)\n2. If handler is null, skip to final setup at address 0x6fa87a13\n3. Enter critical section lock at 0x6fa9d648 for thread-safe access\n4. Load handler count/value from 0x6fa9d680, apply bitwise logic if count <= 0\n5. Loop through handler items if count is positive:\n   - Load handler function pointer from indexed position\n   - Push format string parameter and call handler function\n   - If handler returns non-zero error, jump to abort sequence\n   - Load next handler pointer from data table at 0x6fa9d678\n   - Continue loop while counter is positive\n6. Exit critical section lock at 0x6fa9d648\n7. Call final handler setup at address 0x6fa878bc with format string and additional parameters\n8. If handler returns error, jump directly to LeaveCriticalSection and abort\n\nParameters:\n- pFormatString (EBP+0x8): Format string pointer passed to error handlers; typically error message template\n\nReturns:\n- void (function cleans up stack and returns via __stdcall)\n\nSpecial Cases:\n- If handler pointer at 0x6fa9d670 is null, skips critical section and loop, goes directly to final setup\n- Handler count logic at 0x6fa87a00-0x6fa87e1: Uses conditional assignment with DEC/AND to ensure non-negative count\n- Handler failure at 0x6fa879f6: If handler returns non-zero, aborts with LeaveCriticalSection cleanup",
      "name_source": "LoD/PD2",
      "method": "STR",
      "index": "STR:33bd722168bf830bd5a5faa52b36b420",
      "indexes": {
        "EXP": null,
        "STR": "33bd722168bf830bd5a5faa52b36b420",
        "API": null,
        "MNE": "8df9490d4337bf01b3d09984128eee05",
        "CFG": "1aaca039d81195473c903d623cac4497",
        "PRO": "19d1d88a96aee6f76a05066c509b5abe"
      },
      "basic_block_counts": {
        "LoD/PD2": 13
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "api_calls": {
        "LoD/PD2": [
          "CopyMemoryWithAlignment"
        ]
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2gfx_MNE_875dbff72cb1": {
      "addresses": {
        "LoD/PD2": "0x6FA87A40"
      },
      "rvas": {
        "LoD/PD2": "0x7A40"
      },
      "sizes": {
        "LoD/PD2": 84
      },
      "name": "ClearMessageList",
      "signature": "void ClearMessageList(void)",
      "calling_convention": "__stdcall",
      "comment": "Clears all message entries from a global message list and destroys the associated critical section.\n\nAlgorithm:\n1. Enter critical section at DAT_6fa9d648 to acquire exclusive access to the message list\n2. Load first entry pointer from DAT_6fa9d680 (list head)\n3. Test if entry pointer is valid (non-zero and positive value)\n4. Save entry pointer in ESI register before removal (RemoveListEntryCore will modify list)\n5. Call RemoveListEntryCore to unlink the entry from the list structure\n6. Call GetExportedFunction_Ordinal403 with saved entry, cleanup string reference, 0xfffffffe marker, and 0\n7. Jump back to step 2 to process next entry in the list\n8. Exit critical section after all entries have been cleared from list\n9. Destroy critical section lock object at DAT_6fa9d648\n10. Clear DAT_6fa9d670 flag to 0 to mark list as destroyed\n11. Return to caller with all cleanup complete\n\nParameters:\nnone - void function takes no parameters\n\nReturns:\nvoid - Function completes all cleanup operations synchronously and returns no value",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:875dbff72cb1092ab9a7d9bffdc8924d",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "875dbff72cb1092ab9a7d9bffdc8924d",
        "CFG": "e10086733b4f2d3736c4d7402c9a8d19",
        "PRO": "47fd6bb0cefd1a6b48b8b8d17bc01ba6"
      },
      "basic_block_counts": {
        "LoD/PD2": 12
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "api_calls": {
        "LoD/PD2": [
          "DeallocateMemoryBlock"
        ]
      }
    },
    "D2gfx_MNE_309aec1248c1": {
      "addresses": {
        "LoD/PD2": "0x6FA87AA0"
      },
      "rvas": {
        "LoD/PD2": "0x7AA0"
      },
      "sizes": {
        "LoD/PD2": 92
      },
      "name": "DisplayGraphicsErrorDialog",
      "signature": "uint DisplayGraphicsErrorDialog(uint dwErrorCode)",
      "calling_convention": "__cdecl",
      "comment": "Displays a graphics error dialog with a formatted error message.\n\nAlgorithm:\n1. Allocate 1024 bytes (0x400) on stack for buffers\n2. Call InitializeErrorHandler with error code parameter\n3. Format error message using wvsprintfA with varargs\n4. Display error dialog using MessageBoxA with MB_ICONERROR flag (0x2010)\n5. Set return value to 1 (success indicator)\n6. Clean up stack and return\n\nParameters:\ndwErrorCode [uint]: Error code value to display in error message\n\nReturns:\nuint: Returns 1 (TRUE) indicating dialog was displayed successfully\n\nSpecial Cases:\n- Uses fixed stack buffers (512 bytes each for message and format strings)\n- Dialog title pulled from global string resource at 0x6fa8e300\n- MB_ICONERROR (0x2010) displays error icon in dialog\n- Function pointers to MessageBoxA and wvsprintfA loaded from IAT",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:309aec1248c1b94b575aa5fabd160174",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "309aec1248c1b94b575aa5fabd160174",
        "CFG": "7cc0218256416fa324a756050a6e12a7",
        "PRO": "eb5baaffaea06e6b86c7b5c5e841f66d"
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
    "D2gfx_MNE_303a16dd4c90": {
      "addresses": {
        "LoD/PD2": "0x6FA87B00"
      },
      "rvas": {
        "LoD/PD2": "0x7B00"
      },
      "sizes": {
        "LoD/PD2": 104
      },
      "name": "FatalErrorExit",
      "signature": "void FatalErrorExit(uint dwErrorCode)",
      "calling_convention": "__cdecl",
      "comment": "Displays a fatal error message and terminates the process.\n\nAlgorithm\n1. Allocate 1024 bytes on stack for message buffers\n2. Initialize error handler with custom error formatting\n3. Format error message using wvsprintfA with error code parameter\n4. Display formatted message in MessageBox (modal dialog, styles 0x2010)\n5. Retrieve current process handle via GetCurrentProcess()\n6. Terminate the current process with TerminateProcess()\n7. Code after TerminateProcess is unreachable\n\nParameters\ndwErrorCode: Error code (uint) displayed in message and passed to TerminateProcess\n\nReturns\nvoid - Function never returns; process is terminated immediately\n\nStructure Layout\nabMessageBuffer: byte[512] at ESP+0xc - Formatted error message\nabFormatBuffer: byte[512] at ESP+0x410 - Format string buffer",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:303a16dd4c902c24875cfb07f7777004",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "303a16dd4c902c24875cfb07f7777004",
        "CFG": null,
        "PRO": "0fb58838957a104ab484733ee71dc9a9"
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
    "D2gfx_MNE_467593c25f6d": {
      "addresses": {
        "LoD/PD2": "0x6FA87B70"
      },
      "rvas": {
        "LoD/PD2": "0x7B70"
      },
      "sizes": {
        "LoD/PD2": 121
      },
      "name": "TriggerFatalError",
      "signature": "DWORD TriggerFatalError(DWORD errorCode)",
      "calling_convention": "__cdecl",
      "comment": "Displays a fatal error dialog and terminates the process if user chooses to exit.\n\nAlgorithm:\n1. Call InitializeErrorHandler to prepare error context from errorCode\n2. Format error message using wvsprintfA with format string and arguments from stack\n3. Display message box dialog with \"D2Gfx.DLL\" title and MB_YESNO | MB_ICONEXCLAMATION (0x2215) flags\n4. Check if user clicked \"Retry\" (button ID 4)\n5. If user selected Retry, return 1 to allow caller to retry operation\n6. If user selected another button or No, call GetCurrentProcess and TerminateProcess with exit code 0xFFFFFFFF\n7. Return 0 if process termination path taken (unreachable in practice)\n\nParameters:\n- errorCode (DWORD): Error code passed to InitializeErrorHandler to provide error context\n\nReturns:\n- DWORD: 1 if user clicked \"Retry\" button (IDRETRY), 0 if process terminated (unreachable)\n\nSpecial Cases:\n- Dialog flags 0x2215 = MB_YESNO (3) | MB_ICONEXCLAMATION (0x30) | MB_DEFBUTTON2 (0x100) | MB_APPLMODAL (0x2000) | ... with additional flags\n- Return value 4 indicates IDRETRY button was clicked\n- If user does not click Retry, process termination is fatal and function does not return\n- Format string and variadic arguments passed via stack at ESP+8 and beyond",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:467593c25f6d85dfd73427680b5b43eb",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "467593c25f6d85dfd73427680b5b43eb",
        "CFG": "8bcfe68be77bcf1a96fd65035c083440",
        "PRO": "184d3d438be860b5cad22b5b4632bd7f"
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
    "D2gfx_MNE_286df436b4a1": {
      "addresses": {
        "LoD/PD2": "0x6FA87BF0"
      },
      "rvas": {
        "LoD/PD2": "0x7BF0"
      },
      "sizes": {
        "LoD/PD2": 44
      },
      "name": "InitializeMessageList",
      "signature": "void InitializeMessageList(void)",
      "calling_convention": "__stdcall",
      "comment": "One-time initialization of message list infrastructure including synchronization and cleanup handlers.\n\nAlgorithm:\n1. Load initialization flag from DAT_6fa9d670\n2. If flag is 0 (not yet initialized):\n   a. Initialize critical section at DAT_6fa9d648 for thread-safe message list access\n   b. Register ClearMessageList function with atexit for cleanup on program termination\n   c. Set initialization flag to 1 to prevent re-initialization\n3. Return with no value\n\nParameters:\nNone\n\nReturns:\nvoid\n\nSpecial Cases:\n- Uses double-checked locking pattern to ensure one-time initialization\n- Critical section is used for thread-safe access to the message list\n- ClearMessageList is called automatically when the program exits",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:286df436b4a11cf7b837ea8338f68a59",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "286df436b4a11cf7b837ea8338f68a59",
        "CFG": "2c706c4d67a00273e8f44eca61bc7769",
        "PRO": "773c7b63a8e047b58ded61107dcce0b3"
      },
      "basic_block_counts": {
        "LoD/PD2": 3
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "D2gfx_MNE_fe130b8ce836": {
      "addresses": {
        "LoD/PD2": "0x6FA87C20"
      },
      "rvas": {
        "LoD/PD2": "0x7C20"
      },
      "sizes": {
        "LoD/PD2": 92
      },
      "name": "InitializeMessageSystem",
      "signature": "void InitializeMessageSystem(HandlerType * pMessageHandler)",
      "calling_convention": "__stdcall",
      "comment": "Initializes the message system with thread synchronization and callback registration.\n\nAlgorithm:\n1. Check if message system already initialized (g_dwMessageSystemInitialized == 0)\n2. If not initialized: Initialize critical section (g_MessageSystemCriticalSection) for thread safety\n3. If not initialized: Register cleanup handler using _atexit(ClearMessageList)\n4. If not initialized: Set initialization flag (g_dwMessageSystemInitialized = 1)\n5. Enter critical section to protect message queue access\n6. Create auto message source from g_MessageQueue with no initial parameters\n7. Store pMessageHandler callback at offset +8 in message source structure\n8. Leave critical section via indirect jump (function epilogue)\n\nParameters:\n- pMessageHandler (HandlerType *): Callback handler object to associate with message source\n\nReturns:\n- void: Function returns via __stdcall convention (callee cleans stack)\n\nSpecial Cases:\n- Initialization check prevents multiple critical section initialization\n- _atexit registration ensures cleanup even on abnormal termination\n- Thread-safe access via critical section prevents race conditions during initialization\n- messageHandler stored at fixed offset +8 in message source structure",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:fe130b8ce836859b3f55fecec24b5b29",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "fe130b8ce836859b3f55fecec24b5b29",
        "CFG": "8f87c31656cb4d867ca492e31cb2d365",
        "PRO": "133b69110cdb086ca65641c693136d02"
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
    "D2gfx_MNE_fdad073544ac": {
      "addresses": {
        "LoD/PD2": "0x6FA8CBA0"
      },
      "rvas": {
        "LoD/PD2": "0xCBA0"
      },
      "sizes": {
        "LoD/PD2": 5
      },
      "name": "ThunkToExternalFunction_0x7b662930",
      "signature": "void ThunkToExternalFunction_0x7b662930(void)",
      "calling_convention": "__cdecl",
      "comment": "Thunk function that provides a local entry point for an external function.\nThis is a thin wrapper with no local logic, used for function pointer dispatch.\n\nAlgorithm:\n1. Jump unconditionally to external function at 0x7b662930\n2. All caller parameters pass through unchanged\n3. Return value from external function passes through unchanged\n\nParameters:\n[All parameters passed through unchanged to external function]\n\nReturns:\n[Return value from external function at 0x7b662930]\n\nSpecial Cases:\nThis thunk is referenced from function pointer tables for indirect dispatch.",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:fdad073544ac1586678f808b3470f76a",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "fdad073544ac1586678f808b3470f76a",
        "CFG": null,
        "PRO": "e68b6b378dc2e999dda1e7c2aeacd5bc"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "D2gfx_MNE_6a8f3235f294": {
      "addresses": {
        "LoD/PD2": "0x6FA87C88"
      },
      "rvas": {
        "LoD/PD2": "0x7C88"
      },
      "sizes": {
        "LoD/PD2": 46
      },
      "name": "DispatchGraphicsVtable0x7c",
      "signature": "void DispatchGraphicsVtable0x7c(void * this, uint dwRenderState, uint dwDisplayFlags, uint dwGraphicsCmd1, uint dwGraphicsCmd2, uint dwGraphicsCmd3, uint dwGraphicsCmd4, uint dwGraphicsCmd5)",
      "calling_convention": "__thiscall",
      "comment": "Setting prototype: void DispatchGraphicsVtable0x7c(void * this, uint dwRenderState, uint dwDisplayFlags, uint dwGraphicsCmd1, uint dwGraphicsCmd2, uint dwGraphicsCmd3, uint dwGraphicsCmd4, uint dwGraphicsCmd5)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:6a8f3235f294d7f055be83bf338dca3a",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "6a8f3235f294d7f055be83bf338dca3a",
        "CFG": null,
        "PRO": "b7b9a2ea777c80f6a54fae7f1c10d596"
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
    "D2gfx_MNE_7d5eb63aede8": {
      "addresses": {
        "LoD/PD2": "0x6FA8B360"
      },
      "rvas": {
        "LoD/PD2": "0xB360"
      },
      "sizes": {
        "LoD/PD2": 49
      },
      "name": "RestoreAppBarWindows",
      "signature": "void RestoreAppBarWindows(void)",
      "calling_convention": "__stdcall",
      "comment": "Setting prototype: void RestoreAppBarWindows(void)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:7d5eb63aede808968c80aa2e933c26a7",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "7d5eb63aede808968c80aa2e933c26a7",
        "CFG": "87293770fff7dd02aae145b197058be3",
        "PRO": "e9abec2ca79bd6d6dcdd0c3dcb6d522a"
      },
      "basic_block_counts": {
        "LoD/PD2": 10
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "D2gfx_MNE_2a2fb685db82": {
      "addresses": {
        "LoD/PD2": "0x6FA87D00"
      },
      "rvas": {
        "LoD/PD2": "0x7D00"
      },
      "sizes": {
        "LoD/PD2": 159
      },
      "name": "HideTaskbarAndAppBarWindows",
      "signature": "undefined HideTaskbarAndAppBarWindows(void)",
      "calling_convention": "__stdcall",
      "comment": "Hides taskbar and appbar windows to enable fullscreen rendering.\n\nAlgorithm:\n1. Check if fullscreen mode is already enabled via g_dwFullscreenModeEnabled\n2. If enabled, skip window hiding (early exit optimization)\n3. Initialize AppBarData structure with size 0x24 bytes and callback window handle\n4. Loop through 4 appbar edges (0=left, 1=top, 2=right, 3=bottom)\n5. For each edge, call SHAppBarMessage(7, &AppBarData) to retrieve appbar window handle\n6. Store retrieved window handle in AppBarWindowRecord array at current edge offset\n7. If valid window found, retrieve current placement via GetWindowPlacement()\n8. Store placement data at offset +4 in the record (44 bytes: WINDOWPLACEMENT)\n9. Hide the window using ShowWindow(hWnd, SW_HIDE=0)\n10. Advance to next record (stride 0x30 = 48 bytes per record)\n11. Increment edge counter and repeat until all 4 edges processed\n12. Return with registers restored\n\nParameters:\n  void - No parameters. Uses global g_dwFullscreenModeEnabled flag and g_AppBarWindowRecords array.\n\nReturns:\n  void - No return value. Modifies windows and updates g_AppBarWindowRecords array.\n\nSpecial Cases:\n  - Early exit if fullscreen mode already enabled (g_dwFullscreenModeEnabled == 1)\n  - Safely handles missing windows (checks for null HWND after SHAppBarMessage call)\n  - Uses register calling convention with callee cleanup\n\nStructure Layout:\nAppBarWindowRecord (0x30 = 48 bytes per entry):\n  Offset  Size  Field Name    Type                Description\n  -----   ----  -----------   ----                -----------\n  0x00    0x04  hWnd          HWND                Window handle from SHAppBarMessage\n  0x04    0x2c  placement     WINDOWPLACEMENT    44-byte window placement structure",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:2a2fb685db8243b990b6abe1f5f9043f",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "2a2fb685db8243b990b6abe1f5f9043f",
        "CFG": "635876a80d61047c7dd28db0170065c3",
        "PRO": "7a2a8884337a9d53e076af9af6855624"
      },
      "basic_block_counts": {
        "LoD/PD2": 11
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "D2gfx_API_c01fa6e1a170": {
      "addresses": {
        "LoD/PD2": "0x6FA8B920"
      },
      "rvas": {
        "LoD/PD2": "0xB920"
      },
      "sizes": {
        "LoD/PD2": 121
      },
      "name": "CallGraphicsVtable_0x48WithErrorCheck",
      "signature": "undefined CallGraphicsVtable_0x48WithErrorCheck(void)",
      "calling_convention": "__stdcall",
      "comment": "Calls graphics library vtable method at offset 0x48 with error handling and fallback.\nAlgorithm:\n 1. Load graphics library pointer from global g_pGraphicsLibrary\n 2. Test if graphics library is initialized\n 3. Retrieve error message resource ID 0x316 via GetErrorMessageResource\n 4. Display error message using DisplayErrorMessage\n 5. Terminate application with _exit(-1)\n 6. Retrieve graphics object pointer from stack parameter\n 7. Call vtable method at offset 0x48\n 8. Return to caller with stack cleanup\nParameters:\n Implicit graphics object pointer in ECX or stack\nReturns:\n void (delegates to graphics vtable or terminates)",
      "name_source": "LoD/PD2",
      "method": "API",
      "index": "API:c01fa6e1a170b59bdfbcc5c6da6138f7",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": "c01fa6e1a170b59bdfbcc5c6da6138f7",
        "MNE": "cda64c0c75d09fc607ae9377ab6bcaed",
        "CFG": "4829319e2a49e5c4df0979448cd2dd26",
        "PRO": "19f238ce249fdf89b4f1fc031d08f8a5"
      },
      "basic_block_counts": {
        "LoD/PD2": 22
      },
      "loop_counts": {
        "LoD/PD2": 0
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
    "D2gfx_MNE_f1bb9983d9dc": {
      "addresses": {
        "LoD/PD2": "0x6FA87F00"
      },
      "rvas": {
        "LoD/PD2": "0x7F00"
      },
      "sizes": {
        "LoD/PD2": 11
      },
      "name": "CallGraphicsVtable_0xd4",
      "signature": "undefined CallGraphicsVtable_0xd4(void)",
      "calling_convention": "__stdcall",
      "comment": "Invokes graphics subsystem virtual method at fixed vtable offset 0xd4.\n\nAlgorithm:\n1. Load global graphics library base pointer from address 0x6fa91268 (g_pGraphicsLibrary)\n2. Verify graphics library pointer is loaded into EAX register via MOV instruction\n3. Calculate virtual method address by adding offset 0xd4 to graphics library base\n4. Dereference the calculated address to obtain function pointer from vtable\n5. Perform indirect jump to the resolved method address via JMP dword ptr instruction\n6. Method executes with full control (tail-call optimization, no return to wrapper)\n7. Graphics subsystem operation completes and returns to original caller\n8. This wrapper pattern is used for consistent vtable dispatch across all graphics operations\n\nParameters:\n  (none): Function takes no parameters, relies on global graphics library state\n\nReturns:\n  void: Function does not return; it performs a tail-call jump to virtual method\n\nSpecial Cases:\n  - Uses tail-call optimization via JMP instead of CALL, so function never returns\n  - Offset 0xd4 corresponds to dword index 53 in the graphics vtable\n  - Vtable method must be responsible for all cleanup and return to original caller\n  - Global g_pGraphicsLibrary must be initialized before calling this function",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:f1bb9983d9dc1f8301d508469cee24d7",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "f1bb9983d9dc1f8301d508469cee24d7",
        "CFG": null,
        "PRO": "eba342bd98afd446744cc2b12bc97517"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "D2gfx_MNE_c7caf568d623": {
      "addresses": {
        "LoD/PD2": "0x6FA87F50"
      },
      "rvas": {
        "LoD/PD2": "0x7F50"
      },
      "sizes": {
        "LoD/PD2": 26
      },
      "name": "CheckGraphicsAndParameter",
      "signature": "bool CheckGraphicsAndParameter(void)",
      "calling_convention": "__stdcall",
      "comment": "Validates graphics library initialization and fullscreen mode setting.\n\nAlgorithm:\n1. Load graphics library pointer from global g_pGraphicsLibrary at offset 0x6fa91268\n2. Test if graphics library pointer is null (zero)\n3. If null, clear EAX and return false immediately (graphics not initialized)\n4. If graphics library is initialized, continue to fullscreen mode check\n5. Load fullscreen mode flag from global g_dwFullscreenModeEnabled at offset 0x6fa9125c\n6. Clear EAX and test if fullscreen mode is zero\n7. Use SETZ instruction to set AL to 1 if fullscreen is disabled (zero), 0 if enabled\n8. Return boolean result in EAX\n\nParameters:\n  None - function takes no parameters and uses only global data\n\nReturns:\n  bool: FALSE (0) if graphics library is not initialized, otherwise returns TRUE if fullscreen mode is disabled and FALSE if enabled\n\nSpecial Cases:\n  - Function returns immediately false if graphics library is null without checking fullscreen mode\n  - Returns the inverse of fullscreen mode flag (true when fullscreen is disabled)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:c7caf568d62303da4e067e68e8f6cf29",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "c7caf568d62303da4e067e68e8f6cf29",
        "CFG": "8f793f81eebf6b1a28e081f351d196b1",
        "PRO": "cf992b64823165e338ba8bcf21cc4973"
      },
      "basic_block_counts": {
        "LoD/PD2": 3
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "D2gfx_MNE_7b4de9f0cf35": {
      "addresses": {
        "LoD/PD2": "0x6FA8B8F0"
      },
      "rvas": {
        "LoD/PD2": "0xB8F0"
      },
      "sizes": {
        "LoD/PD2": 6
      },
      "name": "GetWindowHandleValue",
      "signature": "HWND GetWindowHandleValue(void)",
      "calling_convention": "__stdcall",
      "comment": "Retrieve the window handle value from the global callback window variable.\n\nAlgorithm:\n1. Load the HWND value stored in the global g_hCallbackWindow variable\n2. Return the loaded HWND to the caller\n\nParameters:\nNone\n\nReturns:\nHWND - The window handle of the callback window, or NULL if window not yet created\n\nSpecial Cases:\n- Returns NULL (0x00000000) if the window has not been created yet\n- Window handle is shared across all module operations that need window access\n- Value is initialized by CreateMainGameWindow and cleared by CleanupGraphicsAndWindow",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:7b4de9f0cf357b113d12e0c7e214792b",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "7b4de9f0cf357b113d12e0c7e214792b",
        "CFG": null,
        "PRO": "aafbd7abb818143d3e5e83e36530f362"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "D2gfx_MNE_0f26f5ebbb65": {
      "addresses": {
        "LoD/PD2": "0x6FA8B280"
      },
      "rvas": {
        "LoD/PD2": "0xB280"
      },
      "sizes": {
        "LoD/PD2": 12
      },
      "name": "SetDataValue",
      "signature": "void SetDataValue(uint dwDesiredDisplayMode)",
      "calling_convention": "__stdcall",
      "comment": "Sets the desired display mode for the graphics engine.\n\nAlgorithm:\n1. Load the desiredDisplayMode parameter from the stack (ESP+4)\n2. Store the mode value to the global display mode variable\n3. Return to caller with stack cleanup\n\nParameters:\ndesiredDisplayMode (uint): The new display mode to set (0=windowed, non-zero=fullscreen)\n\nReturns:\nvoid - Updates global display state variable\n\nSpecial Cases:\n- Used by the display synchronization system to queue mode change requests\n- The actual mode change is applied by SynchronizeDisplayMode() function\n- __stdcall calling convention: caller cleans up 4-byte parameter from stack\n\nGlobal Variables:\ng_dwDesiredDisplayMode: The global variable storing the requested display mode value",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:0f26f5ebbb6562741331dd6e6bdd0342",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "0f26f5ebbb6562741331dd6e6bdd0342",
        "CFG": null,
        "PRO": "5f4343ef809ce5c29ab95963e4490874"
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
    "D2gfx_MNE_c61015522767": {
      "addresses": {
        "LoD/PD2": "0x6FA87FD0"
      },
      "rvas": {
        "LoD/PD2": "0x7FD0"
      },
      "sizes": {
        "LoD/PD2": 22
      },
      "name": "GetScreenDimensions",
      "signature": "undefined GetScreenDimensions(void)",
      "calling_convention": "__stdcall",
      "comment": "Wrapper function that retrieves the current screen dimensions from the graphics subsystem.\n\nAlgorithm:\n1. Save return address on stack\n2. Call external graphics subsystem function at address 0x7b941960\n3. Receive dimension data from the external graphics subsystem\n4. Return control to the calling function\n\nParameters:\n  None: This function accepts no explicit parameters and operates on a global graphics context\n\nReturns:\n  void: Returns to caller after invoking the external graphics subsystem function\n\nSpecial Cases:\n  This is a thin wrapper that delegates all work to an external graphics library at 0x7b941960",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:c61015522767419637354f5155e74113",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "c61015522767419637354f5155e74113",
        "CFG": null,
        "PRO": "add4bebc1212978f3a0e68f98dc2b5ca"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "D2gfx_MNE_55852887d12e": {
      "addresses": {
        "LoD/PD2": "0x6FA88070"
      },
      "rvas": {
        "LoD/PD2": "0x8070"
      },
      "sizes": {
        "LoD/PD2": 36
      },
      "name": "InitializeShowCursorOnce",
      "signature": "void InitializeShowCursorOnce(void)",
      "calling_convention": "__stdcall",
      "comment": "Initialize cursor display on first call, then skip on subsequent invocations.\n\nAlgorithm:\n1. Load and check initialization flag at 0x6fa90cf8\n2. If already initialized (non-zero), skip to exit\n3. Otherwise, save ESI register on stack\n4. Load function pointer from 0x6fa8d170 (points to ShowCursor)\n5. Call ShowCursor function with parameter 1 (enable cursor)\n6. Test return value in EAX\n7. If negative (error), retry the call in a loop\n8. Set initialization flag to 1 to prevent future calls\n9. Restore ESI register and return\n\nParameters:\nNone\n\nReturns:\nvoid - No return value. Sets global state via side effect.\n\nSpecial Cases:\n- Uses retry loop if ShowCursor returns negative value\n- Global flag prevents function re-execution\n- ESI register saved/restored to preserve caller state\n- Function pointer indirection allows runtime configuration",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:55852887d12e56b727d5e9fc6364d88f",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "55852887d12e56b727d5e9fc6364d88f",
        "CFG": "45c780e25955422bd64054a72a26c4f0",
        "PRO": "efe38cbfa15adaeda3c0be0e60661e46"
      },
      "basic_block_counts": {
        "LoD/PD2": 6
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "D2gfx_MNE_cd93b2473ed6": {
      "addresses": {
        "LoD/PD2": "0x6FA880A0"
      },
      "rvas": {
        "LoD/PD2": "0x80A0"
      },
      "sizes": {
        "LoD/PD2": 36
      },
      "name": "HideShowCursorCompletely",
      "signature": "void HideShowCursorCompletely(void)",
      "calling_convention": "__stdcall",
      "comment": "Hide all instances of the cursor display.\n\nThis function completely hides the cursor by repeatedly calling ShowCursor(0) \nuntil the return value is negative (indicating all cursor instances are hidden). \nIt manages a global flag to track whether cursor hiding has been performed, \npreventing redundant operations and coordinating with InitializeShowCursorOnce \nwhich performs the inverse operation (showing cursor on startup).\n\nAlgorithm:\n1. Load cursor hide/show state flag from global memory at 0x6fa90cf8\n2. Check if flag is non-zero (cursor hiding already performed)\n3. If flag is set, skip to exit (early return optimization)\n4. Save ESI register on stack to preserve caller state\n5. Load function pointer from 0x6fa8d170 (points to ShowCursor API)\n6. Enter loop to hide all cursor instances:\n   a. Push 0 as parameter (hide cursor)\n   b. Call ShowCursor(0) indirectly via function pointer in ESI\n   c. Test EAX return value (negative = all instances hidden)\n   d. If return >= 0, continue loop for next cursor instance\n   e. If return < 0, exit loop (all instances hidden)\n7. Clear the flag at 0x6fa90cf8 to 0 (reset state for re-enabling later)\n8. Restore ESI register from stack\n9. Return to caller\n\nParameters:\nNone\n\nReturns:\nvoid - No return value. Modifies global state as side effect.\n\nSpecial Cases:\n- ShowCursor(0) decrements internal cursor counter; returns count before decrement\n- Negative return (-1) indicates last visible cursor instance was hidden\n- Loop continues until return value is negative\n- Global flag prevents multiple executions but allows re-execution after reset\n- Function pointer indirection at 0x6fa8d170 allows API substitution at runtime\n- Called from CreateMainGameWindow after window initialization to hide cursor in fullscreen\n- Paired with InitializeShowCursorOnce for cursor lifecycle management\n- ESI register saved/restored ensures no caller state corruption\n\nGlobal Variables:\n- 0x6fa90cf8: Cursor hide/show state flag (0=cursor shown, 1=cursor hidden)\n- 0x6fa8d170: Function pointer to ShowCursor API (typically kernel32.dll!ShowCursor)\n\nAPI Dependencies:\n- ShowCursor(nShow): Windows API to control cursor visibility",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:cd93b2473ed633e40ce3f552a9392105",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "cd93b2473ed633e40ce3f552a9392105",
        "CFG": "fe1da1c93249e59196e888d919db0835",
        "PRO": "58303f793369c438e157a10693473668"
      },
      "basic_block_counts": {
        "LoD/PD2": 8
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "D2gfx_API_15b2b03a25dd": {
      "addresses": {
        "LoD/PD2": "0x6FA880D0"
      },
      "rvas": {
        "LoD/PD2": "0x80D0"
      },
      "sizes": {
        "LoD/PD2": 442
      },
      "name": "CenterWindowAndStoreRect",
      "signature": "uint CenterWindowAndStoreRect(HWND hWindowHandle)",
      "calling_convention": "__stdcall",
      "comment": "Setting prototype: uint CenterWindowAndStoreRect(HWND hWindowHandle)",
      "name_source": "LoD/PD2",
      "method": "API",
      "index": "API:15b2b03a25dd2137e0e0ae1d0fefb973",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": "15b2b03a25dd2137e0e0ae1d0fefb973",
        "MNE": "241027c8ba28d49546f65e8cae12b806",
        "CFG": "60e789c6e4b37faf7528d41e89594656",
        "PRO": "a89079a51df655fa36ad35e41243d544"
      },
      "basic_block_counts": {
        "LoD/PD2": 11
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "api_calls": {
        "LoD/PD2": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "GetScreenDimensions",
          "GetScreenDimensions"
        ]
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2gfx_MNE_75d5af7712da": {
      "addresses": {
        "LoD/PD2": "0x6FA88290"
      },
      "rvas": {
        "LoD/PD2": "0x8290"
      },
      "sizes": {
        "LoD/PD2": 53
      },
      "name": "ConditionalExitOrCallback",
      "signature": "void ConditionalExitOrCallback(int nShouldHideCursor)",
      "calling_convention": "__stdcall",
      "comment": "Setting prototype: void ConditionalExitOrCallback(int nShouldHideCursor)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:75d5af7712da313506f69f6aa4e96113",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "75d5af7712da313506f69f6aa4e96113",
        "CFG": "13d5bf8464f8840683f9cc5bb010ea15",
        "PRO": "c092c8cbf65a1ad798a649795e33a18f"
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
    "D2gfx_API_4dc0fda924b7": {
      "addresses": {
        "LoD/PD2": "0x6FA88360"
      },
      "rvas": {
        "LoD/PD2": "0x8360"
      },
      "sizes": {
        "LoD/PD2": 339
      },
      "name": "InitializeWindowAndCallGraphicsVtable",
      "signature": "int InitializeWindowAndCallGraphicsVtable(HWND hWindow, int nDisplayMode)",
      "calling_convention": "__stdcall",
      "comment": "Algorithm:\n1. Validate graphics library pointer is initialized\n2. Check if window handle and display mode are unchanged, return early if so\n3. Capture current fullscreen mode state\n4. Update global window handle with new value\n5. If fullscreen mode enabled, adjust window rectangle and reposition window\n6. Call graphics library virtual function at offset 0x24 (typically mode change handler)\n7. Initialize display settings post-mode change\n8. Return result from graphics vtable method\n\nParameters:\nhWindow: HWND - New window handle to associate with graphics system\nnDisplayMode: int - Display mode flags or parameters (0=no change)\n\nReturns:\nint - Status/return code from graphics vtable call at +0x24\n\nSpecial Cases:\n- Returns 1 immediately if display mode is 0 AND window handle unchanged\n- Fullscreen mode adjustment involves window rect calculation using screen dimensions\n- Graphics library validation is critical; missing library causes exit(-1)\n- Function uses __stdcall calling convention (4 + 4 = 8 bytes cleanup)",
      "name_source": "LoD/PD2",
      "method": "API",
      "index": "API:4dc0fda924b74083d5262d06c9053d29",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": "4dc0fda924b74083d5262d06c9053d29",
        "MNE": "90186f81939c3399eb6b3c457f263b2d",
        "CFG": "05083eb7182084670ae6ba5988d9c5f4",
        "PRO": "5c9ed55b05d1fa7e8910d5479a4c6fbb"
      },
      "basic_block_counts": {
        "LoD/PD2": 13
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "api_calls": {
        "LoD/PD2": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "GetScreenDimensions"
        ]
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "D2gfx_API_9dd106e861fe": {
      "addresses": {
        "LoD/PD2": "0x6FA884C0"
      },
      "rvas": {
        "LoD/PD2": "0x84C0"
      },
      "sizes": {
        "LoD/PD2": 224
      },
      "name": "SynchronizeDisplayMode",
      "signature": "void SynchronizeDisplayMode(void)",
      "calling_convention": "__stdcall",
      "comment": "Synchronizes the display mode between desired and current states.\n\nAlgorithm:\n1. Load desired display mode from global variable g_dwDesiredDisplayMode\n2. Compare desired mode with current mode (DAT_6fa9d66c) - exit if equal\n3. Load and test main window handle (g_hCallbackWindow) - exit if null\n4. Load and test graphics vtable pointer (g_pGraphicsLibrary) - exit if null\n5. If graphics vtable is null, fetch error message for resource ID 0x167\n6. Display error dialog with error message and exit with code -1\n7. Test desired mode value: if 0 (windowed), skip IsIconic check; if non-zero (fullscreen), check IsIconic\n8. If window is minimized (iconic), exit without making changes\n9. Update current mode variable (DAT_6fa9d66c) to match desired mode\n10. If mode is 0 (windowed transition): call HideTaskbarAndAppBarWindows(), loop ShowCursor(0) until return < 0\n11. If mode non-zero (fullscreen transition): call ShowWindow with SW_SHOW(6), RestoreAppBarWindows(), loop ShowCursor(1) until return >= 0\n12. Call graphics vtable function at offset +0x14, passing current mode as parameter\n13. If windowed mode (DAT_6fa9d66c == 0), call graphics vtable at offset +0x70 then InitializeDisplaySettings()\n14. Return to caller\n\nParameters:\nNone - Function uses global variables for input/output:\n- g_dwDesiredDisplayMode (uint): Target display mode (0=windowed, non-zero=fullscreen)\n- g_hCallbackWindow (HWND): Main application window handle for mode switching\n- g_pGraphicsLibrary (void*): Graphics engine vtable pointer for rendering calls\n\nReturns:\nvoid - Function synchronizes display state and applies graphics mode changes. On error (null vtable), exits program with code -1.\n\nSpecial Cases:\n- Error condition: Resource ID 0x167 used when graphics vtable is uninitialized\n- Cursor visibility counter: ShowCursor() maintains internal counter; windowed requires final return < 0, fullscreen requires final return >= 0\n- Window minimized: Fullscreen transitions are skipped if window is iconic (minimized); windowed transitions proceed regardless\n- Vtable offsets: Offset +0x14 applies mode change to all states; offset +0x70 is finalization only for windowed transitions\n- Windowed finalization: InitializeDisplaySettings() called only when transitioning TO windowed mode",
      "name_source": "LoD/PD2",
      "method": "API",
      "index": "API:9dd106e861fe266bfefd1b13f883b97d",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": "9dd106e861fe266bfefd1b13f883b97d",
        "MNE": "7158a675018e630dea569d41169a63d1",
        "CFG": "191711e7ce495a05e352832741d20ccd",
        "PRO": "794e506d0384516618247e7e6d94e791"
      },
      "basic_block_counts": {
        "LoD/PD2": 18
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "api_calls": {
        "LoD/PD2": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "RestoreAppBarWindows",
          "HideTaskbarAndAppBarWindows"
        ]
      }
    },
    "D2gfx_STR_baeeb6b93e8a": {
      "addresses": {
        "LoD/PD2": "0x6FA885A0"
      },
      "rvas": {
        "LoD/PD2": "0x85A0"
      },
      "sizes": {
        "LoD/PD2": 774
      },
      "name": "InitializeMainGameWindow",
      "signature": "int InitializeMainGameWindow(int nFullscreenMode, HWND hParentWindow)",
      "calling_convention": "__stdcall",
      "comment": "Initializes the main game window and graphics system for Diablo II.\n\nAlgorithm:\n1. Check for existing Diablo II instance using FindWindowA - if found, display error and return 0\n2. Verify graphics library is loaded (g_pGraphicsLibrary != NULL), else error exit with code 0x8e\n3. Verify callback window not already created (g_hCallbackWindow == NULL), else error exit with code 0x8f\n4. Store fullscreen mode flag and parent window handle to globals\n5. Get screen dimensions via GetScreenDimensions() and store in rect.bottom\n6. Determine window style based on fullscreen mode: 0xcb0000 for fullscreen, 0x80080000 for windowed\n7. For display mode 5 (stretched), use 0x86080000 style instead\n8. Adjust window rect using AdjustWindowRectEx with style and extended style 0x40000 (WS_EX_APPWINDOW)\n9. Calculate actual window width/height from adjusted rect coordinates\n10. For fullscreen mode: center window on desktop by calculating X/Y offsets\n11. For display mode 4 (windowed): set X/Y to 0 and use system metrics for width/height (minimum 800x600)\n12. If screen width < 800 pixels: initialize 8bpp DEVMODE structure for 800x600 and apply via ChangeDisplaySettingsA\n13. Create window using CreateWindowExA with calculated parameters\n14. If window creation fails: get error code, display graphics error dialog, return 0\n15. Show window (SW_SHOW), update window, set focus, optimize GDI batch limit to 1\n16. Hide/show cursor via HideShowCursorCompletely()\n17. Initialize graphics via vtable method at offset 0xc (g_pGraphicsLibrary[3])\n18. If graphics init returns 0 (failure): set g_dwErrorCode = 1, restore cursor, destroy window, set window to NULL\n19. Initialize display settings with InitializeDisplaySettings()\n20. Set window position (WS_NOMOVE | WS_NOSIZE = 2) to ensure proper final placement\n21. Return graphics initialization result (0=failure, nonzero=success)\n\nParameters:\nnFullscreenMode: 1 for fullscreen mode, 0 for windowed mode\nhParentWindow: Handle to parent window (typically application instance)\n\nReturns:\nint: Nonzero if graphics initialization successful, 0 if any initialization step fails\n\nSpecial Cases:\n- Existing Diablo II instance detected: displays \"Only one copy of Diablo II may run at a time\" error\n- Graphics library not loaded: exits with error code 0x8e\n- Callback window already exists: exits with error code 0x8f\n- Screen resolution < 800x600: forces 8bpp 800x600 display mode\n- Graphics initialization failure: cleans up window resources and marks error flag\n- Window creation failure: GetLastError() code passed to DisplayGraphicsErrorDialog()\n\nStructure Layout:\nDEVMODE (dmSize=0x9c, 156 bytes)\nOffset  Size  Field                Type       Description\n0       32    dmDeviceName         char[32]   Device name (cleared in loop)\n32      2     dmSpecVersion        WORD       Spec version\n34      2     dmDriverVersion      WORD       Driver version\n36      2     dmSize               WORD       Size of structure (0x9c)\n...\n156     4     dmFields             DWORD      0x1c0000 - fields in use\n156     4     dmBitsPerPel         DWORD      8 (8-bit per pixel color)\n156     4     dmPelsWidth          DWORD      800 (pixel width)\n156     4     dmPelsHeight         DWORD      600 (pixel height)",
      "name_source": "LoD/PD2",
      "method": "STR",
      "index": "STR:baeeb6b93e8ae880caa225127d7ee500",
      "indexes": {
        "EXP": null,
        "STR": "baeeb6b93e8ae880caa225127d7ee500",
        "API": "4dc0fda924b74083d5262d06c9053d29",
        "MNE": "bdb451b888399a703bf4a3a16d4aa532",
        "CFG": "2aba21aef4706a837a5dab39ba05c769",
        "PRO": "66e349b94c2231d4be3755a4bcfa4aad"
      },
      "basic_block_counts": {
        "LoD/PD2": 33
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "api_calls": {
        "LoD/PD2": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "GetScreenDimensions"
        ]
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "D2gfx_MNE_aaca3fe15668": {
      "addresses": {
        "LoD/PD2": "0x6FA888B0"
      },
      "rvas": {
        "LoD/PD2": "0x88B0"
      },
      "sizes": {
        "LoD/PD2": 11
      },
      "name": "GetValueAfterFunctionCall",
      "signature": "undefined4 GetValueAfterFunctionCall(void)",
      "calling_convention": "__stdcall",
      "comment": "Getter for current display mode value.\n\nAlgorithm:\n1. Calls SynchronizeDisplayMode() \n2. Loads g_dwCurrentDisplayMode value\n3. Returns value in EAX\n\nParameters:\n(void) - no parameters\n\nReturns:\nDWORD in EAX with current display mode\n\nNotes:\nDepends on SynchronizeDisplayMode() execution",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:aaca3fe15668675c808ffe97fd4a7c1b",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "aaca3fe15668675c808ffe97fd4a7c1b",
        "CFG": null,
        "PRO": "6143068a858e2fa2ef9a6675ec3b88df"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "D2gfx_STR_3075993bd842": {
      "addresses": {
        "LoD/PD2": "0x6FA888C0"
      },
      "rvas": {
        "LoD/PD2": "0x88C0"
      },
      "sizes": {
        "LoD/PD2": 116
      },
      "name": "RestoreDisplayModeAfterVideo",
      "signature": "void RestoreDisplayModeAfterVideo(DWORD displayMode)",
      "calling_convention": "__stdcall",
      "comment": "Restores display mode after video playback.\n\nAlgorithm:\n  1. Validate global display context pointer is initialized (0x6fa91268)\n  2. If context null, trigger fatal error 699 (\"odelete\" - object deletion error)\n  3. Call display cleanup function at 0x6fa884c0\n  4. Check fullscreen mode flag at 0x6fa9d66c\n  5. If windowed mode (flag == 0), resize window to specified display mode\n     - Call Ordinal_10060(displayMode, 1) to perform resize\n     - Fatal exit with error message if resize fails\n  6. If fullscreen mode (flag != 0), store display mode to global at 0x6fa91260\n  7. Call display context refresh function pointer at offset +0x70\n\nParameters:\n  displayMode (DWORD) - Display mode value (0 for standard restoration)\n\nReturns:\n  void - Fatal exits on error conditions\n\nSpecial Cases:\n  - Fatal error 699 if display context not initialized\n  - Fatal error with \"Failed to resize window after...\" if resize fails\n  - Different behavior for windowed vs fullscreen modes\n  - Called after cinematic video playback to restore game display state\n\nGlobal References:\n  - 0x6fa91268: Display context pointer (validated non-null)\n  - 0x6fa9d66c: Fullscreen mode flag (0=windowed, 1=fullscreen)\n  - 0x6fa91260: Display mode storage for fullscreen mode",
      "name_source": "LoD/PD2",
      "method": "STR",
      "index": "STR:3075993bd842872b08741f6f1d662939",
      "indexes": {
        "EXP": null,
        "STR": "3075993bd842872b08741f6f1d662939",
        "API": "bee80d09074cf3fe87f23e28a33c473f",
        "MNE": "ca01e1aca2d43d0f2b3015caf072494f",
        "CFG": "a5d844376fad8170a5461fe6986de86c",
        "PRO": "63a74dd270dbff2eb3a994295d9db4b6"
      },
      "basic_block_counts": {
        "LoD/PD2": 7
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "api_calls": {
        "LoD/PD2": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "InitializeWindowAndCallGraphicsVtable",
          "ValidateAndInitializeParameter"
        ]
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2gfx_MNE_0434425e6f3f": {
      "addresses": {
        "LoD/PD2": "0x6FA88940"
      },
      "rvas": {
        "LoD/PD2": "0x8940"
      },
      "sizes": {
        "LoD/PD2": 33
      },
      "name": "InitializeTileLineStrideLookupTable",
      "signature": "void InitializeTileLineStrideLookupTable(void)",
      "calling_convention": "__stdcall",
      "comment": "Setting prototype: void InitializeTileLineStrideLookupTable(void)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:0434425e6f3f2ec81de36715c7ee7c6d",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "0434425e6f3f2ec81de36715c7ee7c6d",
        "CFG": "9300648c49d18a79bd4ffa7e447c1b5e",
        "PRO": "2482aca8729b5fd5c6a9453e25a9b850"
      },
      "basic_block_counts": {
        "LoD/PD2": 5
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "D2gfx_MNE_8677cb8e1fa9": {
      "addresses": {
        "LoD/PD2": "0x6FA88970"
      },
      "rvas": {
        "LoD/PD2": "0x8970"
      },
      "sizes": {
        "LoD/PD2": 198
      },
      "name": "InitializeDifficultyConfig",
      "signature": "void InitializeDifficultyConfig(int nDifficultyMode, int nBaseValue)",
      "calling_convention": "__fastcall",
      "comment": "Initialize difficulty configuration: Load mode, compute adjustments, store 18 config globals.\n\nAlgorithm:\n1. Load difficulty mode from g_dwDifficultyMode global\n2. Subtract 0x2f from nBaseValue for base offset\n3. Clear ECX accumulator\n4. If mode==1: compute halved adjustment with SAR (divide by 2)\n5. If mode==2: compute half value with division\n6. Store 18 configuration DWORDs with offsets and adjustments\n7. Write magic values 0xfffffff0, 0xffffffe0 for negative offset constants\n8. Return void with all globals updated\n\nParameters:\nnDifficultyMode: int, difficulty level (1=easy, 2=normal, other=hard)\nnBaseValue: int, base configuration offset value\n\nReturns:\nvoid (no return value, modifies 18 global configuration variables)\n\nSpecial Cases:\nDifficulty 1: SAR shift (divide by 2)\nDifficulty 2: Division for half value\nMagic constants: 0xfffffff0 (-16), 0xffffffe0 (-32)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:8677cb8e1fa90ef9ec2338bc7b8b2c21",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "8677cb8e1fa90ef9ec2338bc7b8b2c21",
        "CFG": "8720adbc2f5f8db2f9b7a6c9ca7bc1c1",
        "PRO": "79b8f079560e48ee8d865325af756e0c"
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
    "D2gfx_MNE_8aaa895f0abc": {
      "addresses": {
        "LoD/PD2": "0x6FA88A40"
      },
      "rvas": {
        "LoD/PD2": "0x8A40"
      },
      "sizes": {
        "LoD/PD2": 865
      },
      "name": "RenderTileWithColorLookup",
      "signature": "void RenderTileWithColorLookup(byte * pDestBuffer, int nStartX, int nDeltaX, int nStartY, int nDeltaY, int nRowCount, byte byShiftBits)",
      "calling_convention": "__stdcall",
      "comment": "Renders a single tile using command-encoded pixel data with color lookup blending\n\nAlgorithm:\n1. Calculate initial color lookup row address from shifted X,Y coordinates using base address 0x6fa95450\n2. Main loop for each tile row (nRowCount iterations):\n   a. Read command bytes: skipCount [0], pixelCount [1]\n   b. If both skipCount and pixelCount are 0 (EOL marker):\n      - Load row stride from 0x6fa9477c, advance destination buffer\n      - Update X and Y coordinates by adding deltas (nDeltaX, nDeltaY)\n      - Recalculate color lookup row address using new coordinates\n      - Decrement row count and continue to next iteration\n   c. If pixelCount > 0:\n      - Advance destination and lookup pointers by skipCount bytes\n      - Use indexed jump table dispatch based on pixelCount value (1-32)\n      - Process pixels sequentially via fall-through switch cases\n      - For each pixel: lookup_value[offset] = LUT[command_pixel + (lookup_value[offset] * 256)]\n      - This performs palette-based blending using color lookup table at 0x6fa91678\n   d. After switch completes, advance all pointers by pixelCount bytes\n3. Continue main loop until nRowCount reaches 0\n4. Return with stack cleanup\n\nParameters:\n- pDestBuffer: Pointer to destination tile pixel buffer (32x32 byte array, typically starts at tile row)\n- nStartX: Starting X coordinate (shifted right by nShiftBits to calculate lookup row)\n- nDeltaX: X coordinate increment per row advance\n- nStartY: Starting Y coordinate (shifted right by nShiftBits to calculate lookup row)\n- nDeltaY: Y coordinate increment per row advance\n- nRowCount: Number of tile rows to process (typically 0xF=15 or 0x20=32)\n- nShiftBits: Right-shift amount for coordinate calculation (typically 7 or 8, used to scale X/Y)\n\nReturns: void (no return value, modifies destination buffer in-place)\n\nSpecial Cases:\n- Command (0x00, 0x00) signals end-of-row and forces lookup recalculation\n- pixelCount=0 with non-zero skipCount creates transparent gap (skip bytes)\n- Fall-through switch (case 0x20 down to case 1) processes all 32 possible pixel counts\n- Color lookup table at 0x6fa91678 enables palette remapping and visual effects\n- Stride offset at 0x6fa9477c allows non-contiguous tile row spacing\n- Base lookup address 0x6fa95450 contains palette/color data at 32-byte boundaries",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:8aaa895f0abcca00cf521631e78bc067",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "8aaa895f0abcca00cf521631e78bc067",
        "CFG": "ecb957e5108d8baa2335e59c45455ed1",
        "PRO": "6a3d7be57505ed993e8abad502e5e420"
      },
      "basic_block_counts": {
        "LoD/PD2": 48
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 7
      }
    },
    "D2gfx_MNE_99f9612c9e06": {
      "addresses": {
        "LoD/PD2": "0x6FA88E30"
      },
      "rvas": {
        "LoD/PD2": "0x8E30"
      },
      "sizes": {
        "LoD/PD2": 409
      },
      "name": "DecodeRLEDataStream",
      "signature": "void DecodeRLEDataStream(void * this, void * pOutputBuffer, int iterationCount, byte * pEncodedData)",
      "calling_convention": "__thiscall",
      "comment": "Setting prototype: void DecodeRLEDataStream(void * pOutputBuffer, int iterationCount, byte * pEncodedData)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:99f9612c9e066173144a4f632523e0ad",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "99f9612c9e066173144a4f632523e0ad",
        "CFG": "7ab0d5002ef8a1c3541fd42952aef160",
        "PRO": "2c131124064b6834b0c4ade724828151"
      },
      "basic_block_counts": {
        "LoD/PD2": 44
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 4
      }
    },
    "D2gfx_MNE_cdef74b8ae16": {
      "addresses": {
        "LoD/PD2": "0x6FA89050"
      },
      "rvas": {
        "LoD/PD2": "0x9050"
      },
      "sizes": {
        "LoD/PD2": 843
      },
      "name": "RenderTileWithMultiSourceLookup",
      "signature": "void RenderTileWithMultiSourceLookup(void * this, void * pRenderSurface, int nXCoordSource, int nYCoordSource, int nXDelta, int nYDelta)",
      "calling_convention": "__thiscall",
      "comment": "Setting prototype: void RenderTileWithMultiSourceLookup(void* this, void* pRenderSurface, int nXCoordSource, int nYCoordSource, int nXDelta, int nYDelta)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:cdef74b8ae16a80587312543684cd1b9",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "cdef74b8ae16a80587312543684cd1b9",
        "CFG": "866ceea169b5f39334ef0ea7fc6b9acb",
        "PRO": "75f6674c41daad5c13d37263a13fad5f"
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
    "D2gfx_MNE_12ed9951fd8e": {
      "addresses": {
        "LoD/PD2": "0x6FA893E0"
      },
      "rvas": {
        "LoD/PD2": "0x93E0"
      },
      "sizes": {
        "LoD/PD2": 401
      },
      "name": "CopyLookupTableDataToDestination",
      "signature": "void CopyLookupTableDataToDestination(int nDestBaseOffset)",
      "calling_convention": "__stdcall",
      "comment": "Setting prototype: void CopyLookupTableDataToDestination(int nDestBaseOffset)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:12ed9951fd8ee7aea066da03d5bf16d4",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "12ed9951fd8ee7aea066da03d5bf16d4",
        "CFG": "a5fad410a190dce503726d1cf12c5a5e",
        "PRO": "c2b298151eae6f21b98551617479618f"
      },
      "basic_block_counts": {
        "LoD/PD2": 21
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2gfx_MNE_ae0328de6d67": {
      "addresses": {
        "LoD/PD2": "0x6FA895C0"
      },
      "rvas": {
        "LoD/PD2": "0x95C0"
      },
      "sizes": {
        "LoD/PD2": 87
      },
      "name": "DispatchTileRenderer",
      "signature": "void DispatchTileRenderer(void * this, RenderDevice * pRenderDevice, TileRenderConfig * pTileConfig, void * pRenderSurface, int nRenderFlags)",
      "calling_convention": "__thiscall",
      "comment": "Setting prototype: void DispatchTileRenderer(RenderDevice *pRenderDevice, TileRenderConfig *pTileConfig, void *pRenderSurface, int nRenderFlags)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:ae0328de6d6759f7744a858aa1079a43",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "ae0328de6d6759f7744a858aa1079a43",
        "CFG": "162d65c343290eaea378660ecd014ebc",
        "PRO": "05bee7d008778a9820e37afe6bee3689"
      },
      "basic_block_counts": {
        "LoD/PD2": 4
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 5
      }
    },
    "D2gfx_MNE_2158f027dd80": {
      "addresses": {
        "LoD/PD2": "0x6FA89620"
      },
      "rvas": {
        "LoD/PD2": "0x9620"
      },
      "sizes": {
        "LoD/PD2": 59
      },
      "name": "DecodeTileData",
      "signature": "void DecodeTileData(TileRenderConfig * pTileConfig)",
      "calling_convention": "__fastcall",
      "comment": "Decodes tile pixel data using either RLE compression or lookup table format.\n\nAlgorithm:\n1. Load tile configuration flags from EAX+0x8 to check encoding method\n2. Extract tile index from stack parameter via MOVZX and bit shift operations\n3. Calculate lookup table base address: ((tile_index >> 3) << 8) + g_TilePixelBlendTable\n4. Test RLE flag (bit 2) in configuration flags field\n5. If RLE flag set (non-zero): Call DecodeRLEDataStream with ECX=0xf (tile size parameter)\n6. If RLE flag clear (zero): Call CopyLookupTableDataToDestination to copy pre-decoded data\n7. Return to caller (RET 0x4 removes 4-byte parameter from stack)\n\nParameters:\n- pTileConfig (ECX): Pointer to TileRenderConfig structure containing configuration flags and encoded tile data pointer\n\nReturns:\n- void: Function returns void after decoding completes\n\nSpecial Cases:\n- RLE flag bit location: +0x8 byte, bit 2 (mask 0x4)\n- Magic constant 0xf: Passed to RLE decoder, indicates tile size or format type\n- Lookup table stride: 256 bytes (0x100) per tile index\n- Base address: g_TilePixelBlendTable at 0x6fa91678\n- Calling convention: __fastcall (first parameter in ECX register)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:2158f027dd805cdf33c0260ae0d19c27",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "2158f027dd805cdf33c0260ae0d19c27",
        "CFG": "c0ab582983ce59d1bd818528e3313dd2",
        "PRO": "fbd0d13a3ccb1e341c4246ee07389d1b"
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
    "D2gfx_MNE_a2801cbe0f45": {
      "addresses": {
        "LoD/PD2": "0x6FA89E90"
      },
      "rvas": {
        "LoD/PD2": "0x9E90"
      },
      "sizes": {
        "LoD/PD2": 1017
      },
      "name": "DecodeTileRLEData",
      "signature": "void DecodeTileRLEData(byte * pSourceBuffer, int nTileX, int nDestOffset, int nStartPixelX, int nStrideX, int nStartPixelY, int nStrideY, int nMaxWidth, byte byNumRows)",
      "calling_convention": "__stdcall",
      "comment": "Decodes RLE-compressed tile data and applies palette remapping via lookup table.\n\nAlgorithm:\n1. Initialize tile grid pointer from startPixelX and startPixelY using numRows bit shift\n2. Enter main loop to process maxWidth RLE commands\n3. For each RLE command:\n   a. Read 2-byte header: runLength (byte 0) and dataByte (byte 1)\n   b. Increment source pointer by 2 bytes\n   c. If both bytes are 0 (empty run): increment tile counter, advance X/Y coordinates, recalculate tile grid pointer, continue\n   d. If non-empty run: validate tileX against g_dwScreenMaxExtent boundary\n   e. Add runLength and dataByte to offset calculations\n   f. Check tileX against g_dwClipLowerBound threshold\n   g. If within bounds: calculate copy bounds using g_dwClipOffsetLeft and g_dwClipOffsetRight\n   h. Use unrolled switch (1-32 cases) to copy pixels via palette lookup table g_TilePixelBlendTable\n   i. Each pixel lookup: index = [source_byte] + [tile_grid_byte] * 256\n   j. If outside bounds: advance pointers without palette lookup\n4. Loop until processedTiles >= maxWidth\n5. Clean up stack and return\n\nParameters:\npSourceBuffer: Pointer to RLE-encoded source data (2 bytes per command)\ntileX: X coordinate of starting tile\ndestBufferOrContext: Destination buffer base address for pixel output\nstartPixelX: Initial X coordinate within tile (scaled by numRows shift)\nstrideX: Horizontal stride between tile increments\nstartPixelY: Initial Y coordinate within tile (scaled by numRows shift)\nstrideY: Vertical stride between tile increments\nmaxWidth: Number of RLE commands to process in main loop\nnumRows: Bit shift amount for coordinate scaling (zoom level 0-4, 1:1 to 1:16 scale)\n\nReturns: void (modifies destination buffer in place)\n\nSpecial Cases:\n- Empty runs: Both RLE bytes 0x00 skip tile processing, increment tile counter\n- Boundary checking: Validates tileX against g_dwScreenMaxExtent before processing non-empty runs\n- Palette remapping: 256x256 lookup table remaps source pixels based on tile grid palette\n- Clipping: Left/right bounds prevent out-of-bounds writes for tiles at screen edges\n- Switch fall-through: Unrolled 32-case switch implements fast bulk copy with fallthrough\n- Coordinate scaling: numRows controls shift bits for zoom/scaling operations\n\nStructure Layout:\nTile Grid (g_GradientLookupTable at 0x6fa95450):\n  Offset | Size  | Name          | Type        | Description\n  -------|-------|---------------|-------------|------------------\n  0x0    | 32KB  | tileGrid      | byte[1024]  | 32x32 grid of tiles, 32 bytes per row\n\nPalette Lookup (g_TilePixelBlendTable at 0x6fa91678):\n  Offset | Size  | Name          | Type        | Description\n  -------|-------|---------------|-------------|------------------\n  0x0    | 64KB  | lutTable      | byte[65536] | 256x256 matrix: [src] + [pal]*256",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:a2801cbe0f452b056e4bd2ec06e41dd6",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "a2801cbe0f452b056e4bd2ec06e41dd6",
        "CFG": "f69c19f1167366113cb1452f6b297fe4",
        "PRO": "5263bed08b36cb78bdb1858b7ec9083c"
      },
      "basic_block_counts": {
        "LoD/PD2": 56
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 9
      }
    },
    "D2gfx_MNE_92b1b748e72f": {
      "addresses": {
        "LoD/PD2": "0x6FA8A310"
      },
      "rvas": {
        "LoD/PD2": "0xA310"
      },
      "sizes": {
        "LoD/PD2": 574
      },
      "name": "CopyWithLookupTransform",
      "signature": "void CopyWithLookupTransform(void * this, void * pDecoderState, void * pbyFrameBuffer, int nSrcIndex, int nBaseAddress, int nStride, int iterations)",
      "calling_convention": "__thiscall",
      "comment": "Algorithm:\n1. Validate stride parameter > 0; if not, return immediately\n2. Initialize row counter to 0, current row offset to baseAddress\n3. Loop for each stride iteration:\n   a. Load two control bytes from current row position (byte0, byte1)\n   b. If both bytes == 0: skip row (empty), increment counter, continue\n   c. Otherwise process row:\n      - Validate srcIndex < g_dwScreenMaxExtent (max rows in buffer)\n      - Calculate transformed pixel index = baseAddress + byte0\n      - Check if srcIndex < g_dwClipLowerBound (in visible region)\n      - If in bounds: simple advance without copy (optimize visible data)\n      - If outside: execute lookup-based copy using Duff's device (0x20 cases)\n      - Copy loop: for each pixel, read source byte, use as index into ESI table\n      - Duff's switch enables 0x20 case fallthrough for variable-length copy\n   d. Increment row counter, advance base offset by g_dwVideoBufferStride\n4. Loop until rowCounter >= stride\n5. Return (no return value, transforms data in-place)\n\nParameters:\n  pDecoder (ECX): Decoder state/context object (implicit this parameter)\n  pDestBuffer (stack): Destination frame buffer for transformed pixels\n  srcIndex (stack): Current row/section index (0-based row number)\n  baseAddress (stack): Base memory offset for current stripe (row * stride)\n  stride (stack): Number of iterations/rows to process per call (0xF = 15)\n  iterations (stack): Stripe iteration count (controls loop limit)\n  ESI (implicit): Lookup translation table (palette/transformation LUT)\n\nReturns:\n  void - Transformation applied directly to pDestBuffer, no return value\n\nSpecial Cases:\n  - Empty rows: Control bytes (0,0) cause row skip (no pixel write)\n  - Bounds checking: Multiple guards prevent out-of-bounds reads/writes\n  - Sparse data: WriteOffset calculation handles partial regions\n  - Duff's device: 32-case unrolled loop at 0x6fa8a3dc for fast copy\n  - Magic numbers: \n    * 0xF (15): Standard stripe size for video row processing\n    * 0x1F (31): Maximum unroll count in Duff's device\n    * g_dwVideoBufferStride: Stride between rows (typically 320 or 640)\n    * g_dwScreenMaxExtent: Max valid row index (clip height)\n    * g_dwClipLowerBound: Visible region start (clip top)\n    * g_dwClipOffsetLeft: Clip left margin offset\n    * g_dwClipOffsetRight: Clip right margin offset",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:92b1b748e72f0f602cb90af882220ee7",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "92b1b748e72f0f602cb90af882220ee7",
        "CFG": "92fb1e7593e1bd5293abb0b1cfccde31",
        "PRO": "daeaa8e2c8ab80fb2884cf2eafa79407"
      },
      "basic_block_counts": {
        "LoD/PD2": 72
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 7
      }
    },
    "D2gfx_MNE_1e2959559333": {
      "addresses": {
        "LoD/PD2": "0x6FA8A5D0"
      },
      "rvas": {
        "LoD/PD2": "0xA5D0"
      },
      "sizes": {
        "LoD/PD2": 385
      },
      "name": "ProcessTileDrawing",
      "signature": "void ProcessTileDrawing(void * this, RenderDevice * pRenderer, TileRenderConfig * pTileConfig, int nTileBuffer, int nPixelOffset, int nDrawFlags)",
      "calling_convention": "__thiscall",
      "comment": "Decodes and renders a tile graphic to the destination video buffer, supporting both RLE-compressed and uncompressed tile data.\n\nAlgorithm:\n1. Extract tile bounds from EAX parameter (minX, minY, maxX, maxY as 32-bit ints)\n2. Calculate X stride (maxX - minX) and Y stride (maxY - minY) in tile coordinates\n3. Convert tile coordinates to pixel coordinates by shifting left 4 bits\n4. Check compression flag at pTileContext+0x8 bit 2 (0x4 mask)\n5. If RLE compressed: Call DecodeTileRLEData with tile parameters and return\n6. If uncompressed: Iterate through tile layers (0 to min(15, max_layers))\n7. For each layer: Calculate palette source address, validate pixel range, copy pixels\n8. Increment layer offsets by stride and repeat until all layers processed\n\nParameters:\n  pRenderer (ECX/__thiscall): Render context object (tile rendering state)\n  pTileConfig: TileRenderConfig structure with tile bounds and data pointer\n    +0x0: minX (int) - Minimum X coordinate in tile space\n    +0x4: minY (int) - Minimum Y coordinate in tile space\n    +0x8: maxX (int) - Maximum X coordinate in tile space, bit 2 = RLE flag\n    +0xC: maxY (int) - Maximum Y coordinate in tile space\n    +0x10: pTileData (byte*) - Pointer to tile pixel data buffer\n  pTileBuffer: Offset into tile data buffer for this tile\n  pixelOffset: Destination pixel offset in video buffer\n  drawFlags: Drawing configuration flags (reserved/unused in main path)\n\nReturns:\n  void (no return value)\n\nSpecial Cases:\n  - RLE Compression Flag: Bit 2 of flags byte (0x4) triggers alternate RLE decoder\n  - Layer Clamping: Layer count limited to minimum of (g_dwScreenMaxExtent - pRenderer) and 15\n  - Pixel Range Validation: Start and end offsets clamped to valid range using branchless min/max\n  - Copy Range: Only copies pixels where start < end after clamping\n  - Palette Remapping: Each pixel is looked up through g_TilePixelBlendTable using palette index\n  - Stride Calculations: X and Y strides multiplied by 32 for palette address calculation\n\nStructure Layout:\n  Offset  Size  Field Name              Type      Description\n  ------  ----  --------------------    -------   --------------------------------\n  0x0000   4     minX                   int       Minimum tile X coordinate\n  0x0004   4     minY                   int       Minimum tile Y coordinate  \n  0x0008   4     maxX_flags             int       Max X coord, bit 2 = RLE flag\n  0x000C   4     maxY                   int       Maximum tile Y coordinate\n  0x0010   4     pTileData              byte*     Pointer to tile pixel data",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:1e29595593335ed8a1b29ea3230e3ffc",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "1e29595593335ed8a1b29ea3230e3ffc",
        "CFG": "0289efeb82c41be65fe876cd0af1377e",
        "PRO": "80a3e461e5924a07388470f3e2673623"
      },
      "basic_block_counts": {
        "LoD/PD2": 20
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 6
      }
    },
    "D2gfx_MNE_9002127cd7e7": {
      "addresses": {
        "LoD/PD2": "0x6FA8A760"
      },
      "rvas": {
        "LoD/PD2": "0xA760"
      },
      "sizes": {
        "LoD/PD2": 284
      },
      "name": "CopyPixelsWithPaletteLookup",
      "signature": "void CopyPixelsWithPaletteLookup(void * this, void * pSurface, int nPixelOffset, int nSourceY, int nSourceX, uint nPaletteShift)",
      "calling_convention": "__thiscall",
      "comment": "Copies pixels from surface buffer to video buffer with palette-based color transformation\n\nAlgorithm:\n1. Load surface flags from pSurface[+0x8] and test bit 0x4 for transformed copy mode\n2. If bit 0x4 set, delegate entire operation to CopyWithLookupTransform helper and return\n3. For direct palette copy path:\n   a. Calculate strip index range: min_strip = max(0, g_dwClipLowerBound - nSourceY), max_strip = min(15, g_dwScreenMaxExtent - nSourceY)\n   b. Initialize destination buffer pointer to this + (g_dwVideoBufferStride * min_strip)\n4. For each strip index from min_strip to max_strip:\n   a. Load strip destination offset from g_dwaDestOffsetTable[strip]\n   b. Load strip source offset from g_dwaSourceOffsetTable[strip] + pSurface[+0x10]\n   c. Calculate negated pixel offset for clipping: iPixelOffsetNegated = -(nPixelOffset + dest_offset)\n   d. Clamp minimum offset to max(0, g_dwClipOffsetLeft + iPixelOffsetNegated)\n   e. Load maximum copy size from g_dwaCopySizeTable[strip]\n   f. Clamp maximum size to g_dwClipOffsetRight + iPixelOffsetNegated\n   g. Calculate final copy length: max(0, clamped_max - clamped_min)\n   h. For each source pixel in range:\n      - Load source pixel byte at (source_base + offset)\n      - Transform pixel via palette: g_TilePixelBlendTable[pixel + ((nSourceX >> 3 & 0x1f) << 8)]\n      - Write transformed byte to destination buffer\n      - Advance both pointers by 1\n   i. Advance destination buffer by g_dwVideoBufferStride for next strip iteration\n5. Return void\n\nParameters:\n  this (ECX) - Implicit this pointer to rendering context/surface object\n  pSurface - Pointer to surface structure (pixel data at offset +0x10, flags at offset +0x8)\n  nPixelOffset - Base offset into source pixel buffer for clipping calculations\n  nSourceY - Source Y coordinate for strip boundary calculations\n  nSourceX - Source X coordinate (>> 3 & 0x1f extracts palette bank 0-31)\n  nPaletteShift - Palette bank multiplier (unused in direct copy path)\n\nReturns:\n  void - No return value\n\nSpecial Cases:\n  - Maximum 15 strips processed per call (enforced by clamp to 0xf)\n  - Palette lookup indexed as: g_TilePixelBlendTable[pixel_byte + (bank << 8)]\n  - Palette bank selection: (nSourceX >> 3) & 0x1f gives 32 possible banks with 256 colors each\n  - Transformed copy mode (bit 0x4) bypasses all strip/clipping logic and delegates to CopyWithLookupTransform\n  - Multiple levels of clipping: strip range, source offset, copy size all clamped independently\n  - No error checking - assumes valid pointers and bounds from caller\n\nStructure Layout:\n  pSurface structure offsets:\n    Offset  Size  Field           Type     Description\n    +0x08   1     dwFlags         byte     Surface flags (bit 0x4 = transformed copy mode)\n    +0x10   4     pPixelData      void*    Pointer to source pixel buffer",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:9002127cd7e7ef52c38080c69f0cc570",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "9002127cd7e7ef52c38080c69f0cc570",
        "CFG": "4ea2f7e3f2ac5a5b18a5b59c11a5c4ce",
        "PRO": "8c43760562863f884b68702e40a1cfa1"
      },
      "basic_block_counts": {
        "LoD/PD2": 25
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 6
      }
    },
    "D2gfx_MNE_22ff2af72981": {
      "addresses": {
        "LoD/PD2": "0x6FA8A960"
      },
      "rvas": {
        "LoD/PD2": "0xA960"
      },
      "sizes": {
        "LoD/PD2": 647
      },
      "name": "ProcessTileRenderingBatch",
      "signature": "void ProcessTileRenderingBatch(int * pTileArray, int xOffset, int yOffset, int * pPaletteData)",
      "calling_convention": "__fastcall",
      "comment": "Processes a batch of tiles for rendering with palette-based color mapping and lighting effects.\n\nAlgorithm:\n1. Calculate base video buffer offset using stride multiplied by yOffset\n2. Iterate through each tile in pTileArray, tracked by tile count at offset 0x14\n3. Load tile data pointer from pTileArray[0x15] for current tile\n4. Extract tile X/Y coordinates (stored as shorts at tile data offsets 0x0 and 0x2)\n5. Calculate world-space X (tile X + xOffset) and Y (tile Y + yOffset)\n6. Validate tile is enabled (test bit 0 of boundary flag at offset +0x8)\n7. Validate world coordinates within render bounds (check against g_dwConfig values)\n8. Determine lighting mode: if g_dwTileBufferInitFlag == 0, compute lighting deltas\n9. Calculate luminance differences between palette RGB components at offsets 0x1b, 0x1e, 0x33, 0x36\n10. If luminance delta sum < 10 or game state != 0, use simple color lookup\n11. Otherwise compute averaged lighting components across 4 palette entries\n12. Dispatch renderer based on bounds: out-of-bounds calls full validation (CopyPixelsWithPaletteLookup)\n    in-bounds calls optimized renderers (DecodeTileData for lighting, DispatchTileRenderer for standard)\n13. Continue until all tiles processed\n\nParameters:\n- pTileArray: int * - Tile array base; offset 0x14 = tile count, 0x15 = tile data pointer\n- xOffset: int - X coordinate offset for world space transformation\n- yOffset: int - Y coordinate offset for world space transformation  \n- pPaletteData: int * - Palette table pointer (RGB entries, 3 bytes per index)\n\nReturns:\n- void - No return value; modifies video buffer through render device calls\n\nSpecial Cases:\n- Tile buffer init flag (g_dwTileBufferInitFlag) determines lighting computation vs simple lookup\n- Game state flag (dwGameState) overrides lighting delta threshold (10-unit limit)\n- Boundary checks use 4 distinct globals: g_dwConfigValue0/1/2/8/9/10, g_dwBaseValueOffset, g_TileLineStrideLookupTableEnd\n- Out-of-bounds tiles use full validation renderer; in-bounds use fast path\n- Luminance delta threshold of 10 prevents lighting computation on low-contrast tiles\n- Each tile data entry is 0x14 bytes; iteration increments by this stride",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:22ff2af72981281776e4c714bf2d2dce",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "22ff2af72981281776e4c714bf2d2dce",
        "CFG": "ee4f405e4c35509af8d85e629410d275",
        "PRO": "36de4fd8718f09085f902287a28e240c"
      },
      "basic_block_counts": {
        "LoD/PD2": 52
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 4
      }
    },
    "D2gfx_MNE_5483acfde82b": {
      "addresses": {
        "LoD/PD2": "0x6FA8B2D0"
      },
      "rvas": {
        "LoD/PD2": "0xB2D0"
      },
      "sizes": {
        "LoD/PD2": 15
      },
      "name": "IsHighResolutionDisplay",
      "signature": "bool IsHighResolutionDisplay(void)",
      "calling_convention": "__stdcall",
      "comment": "Determines if the current display mode is high resolution.\n\nAlgorithm:\n1. Load the current display mode value from g_dwCurrentDisplayMode global variable\n2. Zero-extend the value into EAX for comparison\n3. Compare the display mode against threshold value 4\n4. Set AL to 1 if mode >= 4 (high resolution), 0 otherwise\n5. Return the boolean result through AL register\n\nParameters:\n  (none - function takes no parameters)\n\nReturns:\n  BOOL: TRUE (1) if display mode >= 4 indicating high resolution, FALSE (0) if mode < 4\n\nSpecial Cases:\n  - Display modes 0 through 3 are considered standard resolution\n  - Display modes 4 and above are considered high resolution\n  - Global g_dwCurrentDisplayMode is accessed by 17+ functions for display configuration",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:5483acfde82be5a955723d35564f5d51",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "5483acfde82be5a955723d35564f5d51",
        "CFG": null,
        "PRO": "54c13781b66c4841ffe68689ebcfbfad"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "D2gfx_MNE_c926c5fa3561": {
      "addresses": {
        "LoD/PD2": "0x6FA8ADC0"
      },
      "rvas": {
        "LoD/PD2": "0xADC0"
      },
      "sizes": {
        "LoD/PD2": 15
      },
      "name": "CallGraphicsVtable_0x28",
      "signature": "undefined CallGraphicsVtable_0x28(void)",
      "calling_convention": "__stdcall",
      "comment": "Calls graphics virtual table method at offset 0x28 - thin wrapper for graphics subsystem.\nThis function invokes a method from the graphics library's virtual table.\nAlgorithm:\n1. Load implicit parameter from stack (ESP+0x4) into ECX register\n2. Load global graphics library pointer from g_pGraphicsLibrary at 0x6fa91268\n3. Access virtual table at graphics library base address\n4. Call method at offset 0x28 via indirect call [EAX + 0x28]\n5. Return to caller with stack cleanup (RET 0x4)\nParameters:\nIMPLICIT: First parameter in ECX - graphics-related context or data pointer\nReturns:\nvoid - No return value, thin wrapper delegates to graphics virtual table method\nSpecial Cases:\nGraphics library pointer must be initialized before calling this function",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:c926c5fa3561290d7d9e247edf967da1",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "c926c5fa3561290d7d9e247edf967da1",
        "CFG": null,
        "PRO": "9aa22390e4b59791b06e5f6c168deabb"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "D2gfx_MNE_773a5ec8a9b3": {
      "addresses": {
        "LoD/PD2": "0x6FA8ADD0"
      },
      "rvas": {
        "LoD/PD2": "0xADD0"
      },
      "sizes": {
        "LoD/PD2": 23
      },
      "name": "CallGraphicsVtable_0x1cAnd0x20",
      "signature": "undefined4 CallGraphicsVtable_0x1cAnd0x20(void)",
      "calling_convention": "__stdcall",
      "comment": "Invokes graphics library virtual table methods at offsets 0x1c and 0x20 sequentially.\n\nAlgorithm:\n1. Load the graphics library pointer from g_pGraphicsLibrary global variable\n2. Call the graphics method at virtual table offset 0x1c with no parameters\n3. Load the graphics library pointer again from g_pGraphicsLibrary\n4. Call the graphics method at virtual table offset 0x20 with no parameters\n5. Set return value to 1 (success code)\n6. Return to caller with EAX = 0x1\n\nParameters:\n  None\n\nReturns:\n  int: Always returns 1 (0x1) indicating successful execution\n\nSpecial Cases:\n  - No error checking performed on graphics method calls\n  - Both methods execute unconditionally regardless of individual results\n  - Graphics library pointer is reloaded from memory twice\n  - Used by graphics initialization and display synchronization routines",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:773a5ec8a9b3054dff4086eec9434a05",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "773a5ec8a9b3054dff4086eec9434a05",
        "CFG": null,
        "PRO": "b5e3a02bdb4c7397cae3df9b052a78c6"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "D2gfx_MNE_d772e9331874": {
      "addresses": {
        "LoD/PD2": "0x6FA8ADF0"
      },
      "rvas": {
        "LoD/PD2": "0xADF0"
      },
      "sizes": {
        "LoD/PD2": 29
      },
      "name": "CallGraphicsVtableWithParams_0x18",
      "signature": "void CallGraphicsVtableWithParams_0x18(uint dwUnused, uint dwParam2, byte bFlags, uint dwParam4)",
      "calling_convention": "__stdcall",
      "comment": "Graphics subsystem wrapper that invokes offset 0x18 method from graphics library vtable.\n\nAlgorithm:\n1. Load graphics library pointer from g_pGraphicsLibrary global\n2. Retrieve vtable method at offset 0x18 (typically graphics operation handler)\n3. Pass parameters nParam2 and nParam4 to the vtable method\n4. Return to caller\n\nParameters:\n- dwUnused (uint): First stack parameter, loaded but not passed to vtable method\n- nParam2 (uint): Second parameter, passed as first argument to vtable method\n- bFlags (byte): Third parameter, loaded into DL register (typically graphics state flags)\n- nParam4 (uint): Fourth parameter, passed as second argument to vtable method\n\nReturns:\n- void: No return value (void function)\n\nSpecial Cases:\n- The first parameter (dwUnused) is loaded into EAX but only used as a temporary; the actual value passed to the graphics method comes from memory reloads\n- Parameters are accessed via ESP-relative offsets due to __stdcall calling convention\n- Callee is responsible for cleaning up 0x10 bytes (4 DWORDs) from stack",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:d772e9331874c1ee60a55429b1147e20",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "d772e9331874c1ee60a55429b1147e20",
        "CFG": null,
        "PRO": "b41504ac0ddb5067978bf46d3ffcce40"
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
    "D2gfx_MNE_dce33428f6fb": {
      "addresses": {
        "LoD/PD2": "0x6FA8AE10"
      },
      "rvas": {
        "LoD/PD2": "0xAE10"
      },
      "sizes": {
        "LoD/PD2": 66
      },
      "name": "InitializeGraphicsLookupTables",
      "signature": "void InitializeGraphicsLookupTables(uint * pSourceData)",
      "calling_convention": "__stdcall",
      "comment": "Setting prototype: void InitializeGraphicsLookupTables(uint * pSourceData)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:dce33428f6fb0125f3ce698dc6049d6d",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "dce33428f6fb0125f3ce698dc6049d6d",
        "CFG": "adc640a3489c603170b20e3511a8313a",
        "PRO": "c7ea5d6b5d6acad123656d51a92534f9"
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
    "D2gfx_MNE_27932ca97e24": {
      "addresses": {
        "LoD/PD2": "0x6FA8AE60"
      },
      "rvas": {
        "LoD/PD2": "0xAE60"
      },
      "sizes": {
        "LoD/PD2": 104
      },
      "name": "InitializeGameConfiguration",
      "signature": "void InitializeGameConfiguration(void * pGameContext, int nGameMode, int nDifficultyLevel, void * pConfigData)",
      "calling_convention": "__fastcall",
      "comment": "Initializes game configuration settings including game mode and difficulty level.\n\nAlgorithm:\n1. Store input parameters to global configuration variables (context, mode, difficulty, config)\n2. Compare current game mode against cached value (g_dwCachedGameMode at 0x6fa9d684)\n3. If game mode has changed:\n   a. Calculate initial stride value as negated mode multiplied by 32 (left shift by 5 bits for offset scaling)\n   b. Fill mode lookup table from 0x6fa948d0 to 0x6fa95440 with incrementing stride values\n   c. Update cached mode value to prevent redundant reinitializations\n4. Compare current difficulty mode against cached value (g_nCachedDifficultyMode at 0x6fa91270)\n5. If difficulty has changed, call InitializeDifficultyConfig to reinitialize difficulty settings\n6. Return void\n\nParameters:\n- pGameContext (void*): Pointer to game execution context stored at g_pGameExecutionContext (0x6fa94778)\n- nGameMode (int): Game mode identifier, cached at g_dwCachedGameMode (0x6fa9d684)\n- nDifficultyLevel (int): Current difficulty level, stored at g_nDifficultyLevel (0x6fa94780)\n- pConfigData (void*): Pointer to configuration data, stored at g_pConfigurationData (0x6fa94784)\n\nReturns:\nvoid - No return value\n\nSpecial Cases:\n- Mode table initialization only occurs if nGameMode differs from cached value at 0x6fa9d684\n- Mode lookup table spans from 0x6fa948d0 to 0x6fa95440 (approximately 0x1570 bytes / ~343 DWORDs)\n- Each table entry is 4 bytes; loop advances pointer by 4-byte stride\n- Difficulty initialization skipped if current difficulty equals cached value at 0x6fa91270\n- Stride calculation uses negation (NEG instruction) to produce negative offsets for reverse indexing\n- Table entries increment by gameMode value for each position, creating linear stride progression",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:27932ca97e2411d714465d121dcd253c",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "27932ca97e2411d714465d121dcd253c",
        "CFG": "9a0189bfdbed819fe6bcab0b0499108c",
        "PRO": "1fabde1e09b5e40f33a52eb92d1d836f"
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
    "D2gfx_STR_6127f2312a4c": {
      "addresses": {
        "LoD/PD2": "0x6FA8AEE0"
      },
      "rvas": {
        "LoD/PD2": "0xAEE0"
      },
      "sizes": {
        "LoD/PD2": 125
      },
      "name": "InitializeDisplaySettings",
      "signature": "void InitializeDisplaySettings(void)",
      "calling_convention": "__stdcall",
      "comment": "Initialize display contrast and gamma settings\n\nAlgorithm:\n1. Load current display mode from g_dwCurrentDisplayMode global\n2. Calculate contrast value: 0x64 (100) if mode==4, else 0\n3. Convert comparison result using DEC/AND instructions for bit manipulation\n4. Call configuration function to set Contrast parameter with calculated value\n5. Load graphics library pointer and call vtable[0x30] to apply contrast\n6. Call configuration function to set Gamma parameter to 0x9b (155)\n7. Load gamma result from buffer and store at g_dwGammaResult global\n8. Test if gamma is zero, skip redundant store if true\n9. Load graphics library pointer and call vtable[0x58] to apply gamma\n10. Clean up stack and return\n\nParameters:\nNone (takes parameters via stack - contrast/gamma from callers)\n\nReturns:\nvoid - No return value\n\nSpecial Cases:\n- Display mode 4 enables full contrast (100), other modes get contrast=0\n- Magic number 0x64 (100): Contrast intensity threshold specific to mode 4\n- Magic number 0x9b (155): Gamma configuration parameter hard-coded value\n- Gamma test optimization: TEST ECX skips redundant assignment if gamma=0\n\nCalled By:\n- InitializeMainGameWindow: Sets up display after window creation\n- InitializeWindowAndCallGraphicsVtable: Applies settings with new graphics context\n- SynchronizeDisplayMode: Resyncs settings when display mode changes\n\nGraphics Library Vtable Offsets:\n- Offset 0x30: Apply contrast settings function\n- Offset 0x58: Apply gamma settings function",
      "name_source": "LoD/PD2",
      "method": "STR",
      "index": "STR:6127f2312a4c9f9a851c2b98d2a82843",
      "indexes": {
        "EXP": null,
        "STR": "6127f2312a4c9f9a851c2b98d2a82843",
        "API": null,
        "MNE": "682ab6a8c673aa4e212cdb99f45c6f57",
        "CFG": "32cc5fbb4712c24868082309b63e1213",
        "PRO": "f3ce2228e5a2c37b611f2c3af2a186d6"
      },
      "basic_block_counts": {
        "LoD/PD2": 4
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "D2gfx_MNE_7e8b5db44cc9": {
      "addresses": {
        "LoD/PD2": "0x6FA8AF60"
      },
      "rvas": {
        "LoD/PD2": "0xAF60"
      },
      "sizes": {
        "LoD/PD2": 23
      },
      "name": "InitializeGraphicsAndLookupTables",
      "signature": "void InitializeGraphicsAndLookupTables(void)",
      "calling_convention": "__cdecl",
      "comment": "Initializes graphics subsystem and lookup tables.\n\nAlgorithm:\n1. Load graphics virtual table pointer from global g_pGraphicsLibrary (0x6fa91268)\n2. Call graphics vtable method at offset 0x74 to initialize graphics subsystem\n3. Load graphics lookup table data pointer from global (0x6fa94788) into EAX\n4. Tail-call InitializeGraphicsLookupTables() with lookup table pointer in EAX\n\nParameters:\npGraphicsData (IMPLICIT via EAX): Pointer to graphics lookup table data\n\nReturns:\nvoid\n\nSpecial Cases:\n- Wrapper orchestrates graphics initialization via tail-call optimization\n- Lookup table pointer at 0x6fa94788 is a static graphics resource\n- Graphics vtable method at offset 0x74 initializes rendering system\n- Note: Decompiler creates phantom variable in_stack_00000004 for tail-call parameter;\n  this is a known Ghidra limitation and cannot be eliminated",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:7e8b5db44cc99af04abe0a5bb92571cd",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "7e8b5db44cc99af04abe0a5bb92571cd",
        "CFG": "7aacd61a1d81f3299fa55646a3677b47",
        "PRO": "ab60d6064418a94a9f85c7d58fa66fb4"
      },
      "basic_block_counts": {
        "LoD/PD2": 2
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "D2gfx_MNE_9d3000780292": {
      "addresses": {
        "LoD/PD2": "0x6FA8AF80"
      },
      "rvas": {
        "LoD/PD2": "0xAF80"
      },
      "sizes": {
        "LoD/PD2": 16
      },
      "name": "InitializeGameDataAndResetState",
      "signature": "void InitializeGameDataAndResetState(void)",
      "calling_convention": "__stdcall",
      "comment": "Initializes game data tables and resets render state flag\n\nAlgorithm:\n1. Call InitializeAndValidateDataTable() to initialize and validate the 0x4000-byte\n   gradient lookup table at 0x6fa95450 with checksums\n2. Clear render state flag at 0x6fa94778 by setting it to 0\n3. Return to caller\n\nParameters:\nNone - operates on global game data structures\n\nReturns:\nvoid - exits with error code -1 if table validation fails in InitializeAndValidateDataTable\n\nSpecial Cases:\n- Initialization failure: If table validation fails, InitializeAndValidateDataTable calls\n  DisplayErrorMessage and exits the entire process with code -1\n- Global state: Clearing 0x6fa94778 resets the render/tile processing state used by\n  rendering functions like RenderTilePixelsWithComposition and BlitIndexedImageWithLookupTable\n- Buffer layout: The 0x4000-byte table consists of 32 chunks of 0x400 bytes (32x32 gradient rows)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:9d30007802926c303ae27211bfc3adfb",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "9d30007802926c303ae27211bfc3adfb",
        "CFG": null,
        "PRO": "3245d463118c932000e60ecd4a2ccdb8"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "D2gfx_MNE_d092968b6d2f": {
      "addresses": {
        "LoD/PD2": "0x6FA8BAD0"
      },
      "rvas": {
        "LoD/PD2": "0xBAD0"
      },
      "sizes": {
        "LoD/PD2": 22
      },
      "name": "InvokeGraphicsVtableMethod0xD0",
      "signature": "void InvokeGraphicsVtableMethod0xD0(void * pParam1, void * pParam2)",
      "calling_convention": "__stdcall",
      "comment": "Invokes a graphics library virtual method at vtable offset 0xD0.\n\nAlgorithm:\n1. Load g_pGraphicsLibrary pointer from global data at address 0x6fa91268\n2. Add offset 0xD0 to the base graphics library pointer\n3. Dereference the resulting address to fetch function pointer from vtable\n4. Load first parameter from ESP+0x4 into ECX register\n5. Load second parameter from ESP+0x8 into EDX register\n6. Execute indirect call through the fetched function pointer\n7. Return to caller with __stdcall callee cleanup (RET 0x8)\n\nParameters:\n  pParam1: void* - First parameter for graphics method\n  pParam2: void* - Second parameter for graphics method\n\nReturns:\n  void - No return value\n\nSpecial Cases:\n  - Requires g_pGraphicsLibrary to be initialized\n  - Uses __stdcall convention with callee cleanup\n  - If graphics library pointer is NULL, will crash",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:d092968b6d2f10526b1ce8ac8b703c25",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "d092968b6d2f10526b1ce8ac8b703c25",
        "CFG": null,
        "PRO": "56982dbc8f8ec7290212dd31cb4f131d"
      },
      "basic_block_counts": {
        "LoD/PD2": 2
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "D2gfx_MNE_8b4918f11433": {
      "addresses": {
        "LoD/PD2": "0x6FA8AFB8"
      },
      "rvas": {
        "LoD/PD2": "0xAFB8"
      },
      "sizes": {
        "LoD/PD2": 24
      },
      "name": "CallGraphicsVtable_0x94",
      "signature": "void CallGraphicsVtable_0x94(uint dwParam)",
      "calling_convention": "__fastcall",
      "comment": "Calls graphics subsystem virtual method at offset 0x94 from global vtable pointer.\n\nThis function serves as a thin wrapper that dispatches to the graphics engine's vtable method at offset 0x94. It loads the global graphics vtable pointer from the module's data segment and invokes the corresponding virtual function with the provided parameter.\n\nAlgorithm:\n1. Load global graphics vtable pointer from 0x6fa91268 into EAX\n2. Push EAX to preserve it across function call\n3. Push ECX to preserve register state\n4. Load parameter from stack into ECX (fastcall first argument)\n5. Load second argument EDX from stack (fastcall second argument)\n6. Call virtual method at offset 0x94 from vtable pointer\n7. Return to caller, cleaning 0x10 bytes from stack\n\nParameters:\n- dwParam (uint): First parameter passed via ECX (fastcall convention), passed to graphics vtable method\n\nReturns:\n- void (no return value)\n\nSpecial Cases:\n- The RET 0x10 instruction indicates this is a __stdcall wrapper that cleans 16 bytes from the stack, suggesting the function expects 4 dword arguments from caller\n- The graphics vtable is accessed through a global pointer, indicating graphics state is managed globally\n- Offset 0x94 in the vtable corresponds to a specific graphics operation",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:8b4918f11433a5d23ba92e0864b5ac8c",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "8b4918f11433a5d23ba92e0864b5ac8c",
        "CFG": null,
        "PRO": "171c887010285950c9846a7cbbda5968"
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
    "D2gfx_MNE_7a6ae38e7a35": {
      "addresses": {
        "LoD/PD2": "0x6FA8AFD8"
      },
      "rvas": {
        "LoD/PD2": "0xAFD8"
      },
      "sizes": {
        "LoD/PD2": 22
      },
      "name": "CallGraphicsVtable_0x90",
      "signature": "void CallGraphicsVtable_0x90(uint dwX, uint dwY, uint dwFlags)",
      "calling_convention": "__stdcall",
      "comment": "Setting prototype: void CallGraphicsVtable_0x90(uint dwX, uint dwY, uint dwFlags)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:7a6ae38e7a35df8f688a114b31aed852",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "7a6ae38e7a35df8f688a114b31aed852",
        "CFG": null,
        "PRO": "df80317e8842220add61bbbbaac1876d"
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
    "D2gfx_MNE_3c6069195c1e": {
      "addresses": {
        "LoD/PD2": "0x6FA8BB58"
      },
      "rvas": {
        "LoD/PD2": "0xBB58"
      },
      "sizes": {
        "LoD/PD2": 29
      },
      "name": "CallGraphicsVtable_0x98",
      "signature": "void CallGraphicsVtable_0x98(uint dwReserved1, uint dwReserved2, uint dwGraphicsParam)",
      "calling_convention": "__stdcall",
      "comment": "Calls graphics vtable method at offset 0x98\n\nAlgorithm:\n1. Invokes virtual method at offset 0x98 of the global graphics vtable (g_pGraphicsLibrary)\n2. Passes the third parameter (dwGraphicsParam) as the sole argument to the vtable method\n3. Returns control to caller\n\nParameters:\n- dwReserved1 (uint): Unused parameter, ignored by function\n- dwReserved2 (uint): Unused parameter, ignored by function\n- dwGraphicsParam (uint): Primary parameter passed to graphics vtable method at offset 0x98\n\nReturns:\n- void: No return value\n\nSpecial Cases:\n- Only the third parameter is passed to the virtual method; first two parameters are unused\n- Vtable method is resolved at runtime from g_pGraphicsLibrary\n- Callee cleanup of 0x14 (20 bytes) indicates 3 additional stack-based parameters expected by caller",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:3c6069195c1e5aa9e56fdfca471a40f0",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "3c6069195c1e5aa9e56fdfca471a40f0",
        "CFG": null,
        "PRO": "4ae3f51b5c75de16d5969bfc2596bf86"
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
    "D2gfx_MNE_e6c49af345a9": {
      "addresses": {
        "LoD/PD2": "0x6FA8BB28"
      },
      "rvas": {
        "LoD/PD2": "0xBB28"
      },
      "sizes": {
        "LoD/PD2": 34
      },
      "name": "InvokeGraphicsVtableMethod_0x88",
      "signature": "void InvokeGraphicsVtableMethod_0x88(void * this, void * pGraphicsObj, uint dwParam1, uint dwParam2, uint dwParam3)",
      "calling_convention": "__thiscall",
      "comment": "Graphics Library Virtual Method Wrapper\n\nAlgorithm:\n1. Load graphics library pointer from global g_pGraphicsLibrary\n2. Get virtual method at offset 0x88 from library instance\n3. Call vtable method with parameters dwParam2, dwParam3, and implicit this\n4. Return to caller\n\nParameters:\n  this - Graphics object instance (implicit in __thiscall)\n  pGraphicsObj - Graphics object pointer\n  dwParam1 - First parameter\n  dwParam2 - Second parameter passed to vtable\n  dwParam3 - Third parameter passed to vtable\n\nReturns:\n  void - No explicit return value",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:e6c49af345a935f50a3d2d149f111157",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "e6c49af345a935f50a3d2d149f111157",
        "CFG": null,
        "PRO": "f447cde9488e6144dbd4eb069e1585bd"
      },
      "basic_block_counts": {
        "LoD/PD2": 4
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 8
      }
    },
    "D2gfx_MNE_048196c0e544": {
      "addresses": {
        "LoD/PD2": "0x6FA8B0B8"
      },
      "rvas": {
        "LoD/PD2": "0xB0B8"
      },
      "sizes": {
        "LoD/PD2": 39
      },
      "name": "DispatchGraphicsVtableMethod0x80",
      "signature": "void DispatchGraphicsVtableMethod0x80(void * this, GraphicsObject * pThis, GraphicsObject * pGraphicsContext, uint dwVtableMethod, uint dwParam2, uint dwParam3, uint dwParam4, uint dwParam5)",
      "calling_convention": "__thiscall",
      "comment": "Setting prototype: void DispatchGraphicsVtableMethod0x80(GraphicsObject * pThis, GraphicsObject * pGraphicsCtx, uint dwVtableMethod, uint dwParam2, uint dwParam3, uint dwParam4, uint dwParam5)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:048196c0e54428985c2d6912f114df39",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "048196c0e54428985c2d6912f114df39",
        "CFG": null,
        "PRO": "a8cb2eb87d69750015286cc2135fc8b2"
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
    "D2gfx_MNE_81ecaa00ece7": {
      "addresses": {
        "LoD/PD2": "0x6FA8B0E0"
      },
      "rvas": {
        "LoD/PD2": "0xB0E0"
      },
      "sizes": {
        "LoD/PD2": 24
      },
      "name": "CallGraphicsVtableOffset0x78",
      "signature": "void CallGraphicsVtableOffset0x78(GraphicsObject * pGraphicsLib, int nParam2, int nParam3)",
      "calling_convention": "__stdcall",
      "comment": "Setting prototype: void CallGraphicsVtableOffset0x78(GraphicsObject* pGraphicsLib, int nParam2, int nParam3)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:81ecaa00ece79f92ccd43f50a449f14c",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "81ecaa00ece79f92ccd43f50a449f14c",
        "CFG": null,
        "PRO": "b8810c322a35dc69c89e05a5168640d9"
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
    "D2gfx_MNE_0abdfd137b3b": {
      "addresses": {
        "LoD/PD2": "0x6FA8B100"
      },
      "rvas": {
        "LoD/PD2": "0xB100"
      },
      "sizes": {
        "LoD/PD2": 26
      },
      "name": "CallGraphicsVtable_0x74AndCleanup",
      "signature": "undefined CallGraphicsVtable_0x74AndCleanup(void)",
      "calling_convention": "__stdcall",
      "comment": "Setting prototype: void CallGraphicsVtable_0x74AndCleanup(uint pGraphicsContext)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:0abdfd137b3b6a2e80be73354f71ac46",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "0abdfd137b3b6a2e80be73354f71ac46",
        "CFG": null,
        "PRO": "7454cc984ee9f2142f75d3bbb55a903b"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "D2gfx_MNE_11618bde6f4f": {
      "addresses": {
        "LoD/PD2": "0x6FA8B120"
      },
      "rvas": {
        "LoD/PD2": "0xB120"
      },
      "sizes": {
        "LoD/PD2": 56
      },
      "name": "CopyBufferAndCallGraphicsVtable_0x70",
      "signature": "void CopyBufferAndCallGraphicsVtable_0x70(uint * pSourceBuffer)",
      "calling_convention": "__stdcall",
      "comment": "Setting prototype: void CopyBufferAndCallGraphicsVtable_0x70(uint * pSourceBuffer)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:11618bde6f4fbc58e1e98db849798b08",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "11618bde6f4fbc58e1e98db849798b08",
        "CFG": "e0cc0190add0739fe135c9b9d7285356",
        "PRO": "d8f9b3872b3b48659a6b97e632488fd8"
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
    "D2gfx_MNE_9c087099454e": {
      "addresses": {
        "LoD/PD2": "0x6FA8B160"
      },
      "rvas": {
        "LoD/PD2": "0xB160"
      },
      "sizes": {
        "LoD/PD2": 25
      },
      "name": "HandleDllInitialization",
      "signature": "int HandleDllInitialization(int nResetMode)",
      "calling_convention": "__stdcall",
      "comment": "Handles DLL initialization and window handle management.\n\nAlgorithm:\n1. Retrieve the reset mode parameter from the stack (ESP + 8)\n2. Check if reset mode equals 1\n3. If true, clear the main window handle global variable (DAT_6fa91264) to 0\n4. Return 1 to indicate successful handling\n\nParameters:\n  nResetMode - Reset/initialization mode flag. When 1, triggers clearing of main window handle.\n\nReturns:\n  Always returns 1, indicating the initialization step was handled.\n\nSpecial Cases:\n  - The reset mode parameter is validated by checking equality with 1\n  - The global DAT_6fa91264 represents the main application window handle\n  - This function is called from the DLL entry point handler during module initialization",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:9c087099454eeca337d576704d2b3ed9",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "9c087099454eeca337d576704d2b3ed9",
        "CFG": "c28d843778d6313eca5e15ea77ffbb3e",
        "PRO": "bdf22b3e21f6d6db308e72ab161d8d65"
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
    "D2gfx_MNE_40903556bc57": {
      "addresses": {
        "LoD/PD2": "0x6FA8CBA5"
      },
      "rvas": {
        "LoD/PD2": "0xCBA5"
      },
      "sizes": {
        "LoD/PD2": 8
      },
      "name": "CallGraphicsVtable_0x30",
      "signature": "undefined CallGraphicsVtable_0x30(void)",
      "calling_convention": "__stdcall",
      "comment": "Invokes graphics library vtable method at offset 0x30.\n\nAlgorithm:\n1. Load global graphics library pointer from g_pGraphicsLibrary\n2. Calculate graphics vtable entry address by adding offset 0x30\n3. Dereference the vtable entry to retrieve the function pointer\n4. Call the function pointer with no parameters\n5. Return control to caller\n\nParameters:\nNone. This is a parameterless wrapper function.\n\nReturns:\nvoid. This function does not return a value.\n\nSpecial Cases:\nThe graphics library pointer must be initialized before calling this function.\nThe vtable offset 0x30 corresponds to a specific graphics operation.\nIf g_pGraphicsLibrary is NULL or invalid, this function will crash.\nThis function is part of a family of graphics vtable wrapper functions.\nUsed as a callback or dispatch mechanism for graphics subsystem operations.",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:40903556bc57a4df1722c0a365e78b81",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "40903556bc57a4df1722c0a365e78b81",
        "CFG": null,
        "PRO": "58f875d532ca4ce9c43811698c708ebb"
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
    "D2gfx_MNE_305c32d33191": {
      "addresses": {
        "LoD/PD2": "0x6FA8B190"
      },
      "rvas": {
        "LoD/PD2": "0xB190"
      },
      "sizes": {
        "LoD/PD2": 7
      },
      "name": "SetPaletteValue",
      "signature": "void SetPaletteValue(uint dwPaletteValue)",
      "calling_convention": "__fastcall",
      "comment": "Stores the palette configuration value in global memory.\n\nAlgorithm:\n1. Receive palette value parameter via ECX register per __fastcall calling convention\n2. Store 32-bit DWORD value to global palette storage at address 0x6fa91270\n3. Return to caller with control flow restored\n\nParameters:\n  dwPaletteValue: uint (32-bit unsigned integer) - Palette color configuration value passed in ECX register\n\nReturns:\n  void - Function performs global state modification only, returns no value to caller\n\nSpecial Cases:\n  - Uses __fastcall calling convention with first parameter in ECX register\n  - Direct write to global memory with no validation or range checking performed",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:305c32d33191c1b22ce2562362c5fa24",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "305c32d33191c1b22ce2562362c5fa24",
        "CFG": null,
        "PRO": "d32bdb0db8efb79b4f2106ba57d12545"
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
    "D2gfx_MNE_d98637d661e3": {
      "addresses": {
        "LoD/PD2": "0x6FA8B1C0"
      },
      "rvas": {
        "LoD/PD2": "0xB1C0"
      },
      "sizes": {
        "LoD/PD2": 11
      },
      "name": "ResetConfigurationValue",
      "signature": "void ResetConfigurationValue(void)",
      "calling_convention": "__cdecl",
      "comment": "Resets the global configuration value to zero.\n\nAlgorithm:\n1. Write zero (0x0) to global configuration variable at 0x6fa90c14\n2. Return to caller\n\nParameters:\n  None\n\nReturns:\n  void: No return value\n\nSpecial Cases:\n  - This is a simple global variable reset function\n  - Called during graphics subsystem cleanup/reset operations\n  - Does not validate or check current configuration value\n  - Uses __cdecl calling convention (standard for void functions with no parameters)\n  - Single atomic operation - no error conditions possible\n  - Global g_dwConfigurationValue is shared across graphics module\n  - Typically called before reconfiguring graphics settings",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:d98637d661e34ac4188330085482b5ab",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "d98637d661e34ac4188330085482b5ab",
        "CFG": null,
        "PRO": "8c6771bc6ea235192b42b306de63e9c5"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "D2gfx_MNE_a9a3f1cd5746": {
      "addresses": {
        "LoD/PD2": "0x6FA8B1E0"
      },
      "rvas": {
        "LoD/PD2": "0xB1E0"
      },
      "sizes": {
        "LoD/PD2": 30
      },
      "name": "SetGammaAndCallGraphicsMethod",
      "signature": "void SetGammaAndCallGraphicsMethod(int nGammaValue)",
      "calling_convention": "__stdcall",
      "comment": "Sets gamma correction value and invokes graphics library vtable method.\n\nAlgorithm:\n1. Conditionally store gamma value parameter to global storage\n2. If nGammaValue is non-zero, update g_dwGammaResult with the new value\n3. If nGammaValue is zero, skip the storage operation (preserve existing value)\n4. Load the graphics library vtable pointer from g_pGraphicsLibrary\n5. Invoke the graphics method at vtable offset 0x58\n6. The vtable method applies gamma correction to the display\n7. Return to caller with stdcall stack cleanup\n\nParameters:\n- nGammaValue: Gamma correction value to apply (0 = skip update, non-zero = update and apply)\n\nReturns:\n- void (no return value)\n\nSpecial Cases:\n- Zero parameter preserves existing gamma value while still calling the graphics method\n- Graphics library vtable must be initialized before calling this function\n- Vtable offset 0x58 corresponds to the gamma correction handler in the graphics backend",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:a9a3f1cd57460569e4edd4ce1f226a55",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "a9a3f1cd57460569e4edd4ce1f226a55",
        "CFG": "1abbbed88598ab76171d956e8b753f75",
        "PRO": "23de0433edc1539aa807ca3d0b9964d1"
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
    "D2gfx_MNE_0246ba23d2e2": {
      "addresses": {
        "LoD/PD2": "0x6FA8B2B0"
      },
      "rvas": {
        "LoD/PD2": "0xB2B0"
      },
      "sizes": {
        "LoD/PD2": 19
      },
      "name": "ToggleRenderingEnabled",
      "signature": "void ToggleRenderingEnabled(void)",
      "calling_convention": "__cdecl",
      "comment": "Toggles the rendering enabled state between disabled (0) and enabled (1).\n\nAlgorithm:\n1. Load current rendering state from global dwGameState at address 0x6fa90be8\n2. Move the current state value into ECX register\n3. Clear EAX register using XOR to prepare for the toggled result\n4. Test if dwGameState equals 0 using TEST instruction (sets zero flag if true)\n5. Use SETZ instruction to set AL to 1 if zero flag is set, else set AL to 0\n6. Store the toggled boolean result (0 or 1) back to dwGameState global\n7. Return to caller with simple RET instruction (cdecl calling convention)\n\nParameters:\n- None (function takes no parameters and operates only on global state)\n\nReturns:\n- void (no return value; side effect is updating global dwGameState)\n\nSpecial Cases:\n- Converts any non-zero value to 0 (disabled) and converts 0 to 1 (enabled)\n- Result is always exactly 0 or 1 (boolean normalized)\n- Used by ProcessTileRenderingBatch and ProcessTileDataWithValidation to control rendering operations\n- Global dwGameState at 0x6fa90be8 is shared with SetRenderingEnabled and GetRenderingEnabled functions",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:0246ba23d2e2a9bb9388cd8cc7c4cceb",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "0246ba23d2e2a9bb9388cd8cc7c4cceb",
        "CFG": null,
        "PRO": "68619e651a0a72802d99f9a6cbeaa05e"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "D2gfx_MNE_af413c75688c": {
      "addresses": {
        "LoD/PD2": "0x6FA8B290"
      },
      "rvas": {
        "LoD/PD2": "0xB290"
      },
      "sizes": {
        "LoD/PD2": 18
      },
      "name": "GetConditionalCleanupFlag",
      "signature": "uint GetConditionalCleanupFlag(void)",
      "calling_convention": "__stdcall",
      "comment": "Returns cleanup handler flag conditional on display mode adjustment.\n\nAlgorithm:\n1. Load g_dwDisplayModeAdjustment flag into EAX\n2. Load g_dwCleanupHandlerFlag into ECX\n3. Negate EAX using NEG instruction\n4. Propagate sign bit using SBB EAX,EAX (creates 0 or 0xFFFFFFFF mask)\n5. AND ECX with mask and return result\n\nParameters:\nNone - uses global variables g_dwDisplayModeAdjustment and g_dwCleanupHandlerFlag\n\nReturns:\nEAX contains g_dwCleanupHandlerFlag if mode flag is non-zero, otherwise 0\n\nSpecial Cases:\nMode flag = 0: Returns 0 (cleanup handler disabled)\nMode flag != 0: Returns cleanup handler flag value (enabled)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:af413c75688c051388954706b235eefd",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "af413c75688c051388954706b235eefd",
        "CFG": null,
        "PRO": "ddedd71cba749e62957fdce183c7f24d"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "D2gfx_MNE_bde119b92c87": {
      "addresses": {
        "LoD/PD2": "0x6FA8B2E0"
      },
      "rvas": {
        "LoD/PD2": "0xB2E0"
      },
      "sizes": {
        "LoD/PD2": 31
      },
      "name": "SetValueIfCounterReady",
      "signature": "void SetValueIfCounterReady(uint dwNewValue)",
      "calling_convention": "__stdcall",
      "comment": "Conditionally set display mode adjustment value based on error code state.\n\nAlgorithm:\n1. Load error code state from g_dwErrorCodeState global variable\n2. Compare error code state against threshold value 4\n3. If error code state is less than 4: set display mode adjustment to 0 (reset)\n4. If error code state is greater than or equal to 4: set display mode adjustment to the provided new value\n5. Return to caller with standard __stdcall callee cleanup\n\nParameters:\ndwNewValue (uint): The display mode adjustment value to apply if error code state is ready (>= 4)\n\nReturns:\nvoid: No return value. Function modifies global state and returns.\n\nSpecial Cases:\nError Code State Threshold: The function checks if g_dwErrorCodeState >= 4, treating values 0-3 as unready state and >= 4 as ready state. This likely represents initialization or readiness stages (0=uninitialized, 1-3=initializing, 4+=ready).\n\nGlobals Modified:\ng_dwDisplayModeAdjustment: Set to 0 if not ready, or to dwNewValue parameter if ready",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:bde119b92c87788e9010eea26f66d657",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "bde119b92c87788e9010eea26f66d657",
        "CFG": "ebedb8faf55908534e596ba5d47d40c7",
        "PRO": "55609acd183392e8770f9c6848014fec"
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
    "D2gfx_MNE_f5b0d4999cef": {
      "addresses": {
        "LoD/PD2": "0x6FA8B350"
      },
      "rvas": {
        "LoD/PD2": "0xB350"
      },
      "sizes": {
        "LoD/PD2": 5
      },
      "name": "GetZeroValue",
      "signature": "undefined4 GetZeroValue(void)",
      "calling_convention": "__stdcall",
      "comment": "Returns a constant zero value.\n\nAlgorithm:\n1. Clear EAX register using XOR EAX,EAX instruction\n2. Return zero value (0) to caller with __stdcall cleanup protocol\n\nParameters:\n  None - Function accepts no parameters\n\nReturns:\n  undefined4 in EAX: Returns 0 (zero) as a constant stub value\n\nSpecial Cases:\n  - This is a minimal stub function with no parameters\n  - Commonly used as placeholder or default callback in function pointer arrays\n  - __stdcall calling convention with RET 0xc indicates hidden stack parameters\n  - XOR EAX,EAX efficiently clears EAX while setting zero flag\n\nNotes:\n  The RET 0xc instruction pops 12 bytes from the stack, suggesting this function\n  may be part of an interface where callers always push additional stack data.",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:f5b0d4999cef381bea9a054131983f79",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "f5b0d4999cef381bea9a054131983f79",
        "CFG": null,
        "PRO": "d10ed07cc8e38a005814481889c7966d"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "D2gfx_API_3422fd172218": {
      "addresses": {
        "LoD/PD2": "0x6FA8B3A0"
      },
      "rvas": {
        "LoD/PD2": "0xB3A0"
      },
      "sizes": {
        "LoD/PD2": 93
      },
      "name": "FreeGraphicsLibrary",
      "signature": "BOOL FreeGraphicsLibrary(void)",
      "calling_convention": "__stdcall",
      "comment": "Frees the graphics library module and clears associated global state.\n\nAlgorithm:\n1. Load graphics module handle from DAT_6fa9126c\n2. Test if module handle is NULL\n3. If NULL: retrieve error message for code 0x8a, display error with prefix string, exit with code -1\n4. If loaded: push module handle and call FreeLibrary to unload graphics module\n5. Save FreeLibrary return value in ESI\n6. Load graphics vtable pointer index from DAT_6fa91258\n7. Index into graphics vtable array at 0x6fa90c18 to get vtable pointer\n8. Call graphics cleanup function with vtable and EDX=0\n9. Call GetCursorResource to restore cursor graphics resource\n10. Clear graphics module handle (DAT_6fa9126c) to NULL\n11. Clear graphics vtable pointer (g_GraphicsVtablePtr) to NULL\n12. Restore ESI register and return FreeLibrary result code\n\nReturns:\nBOOL - TRUE if FreeLibrary succeeded, FALSE if module unload failed. Function never returns\n       if module handle is NULL (terminates process with exit(-1)).\n\nParameters:\nNone - uses global graphics module handle variable DAT_6fa9126c.\n\nSpecial Cases:\n- Error code 0x8a indicates graphics module missing or not initialized - causes immediate process\n  termination without returning\n- String s_odelete_6fa8e2eb + 8 is used as error message prefix for display\n- Module handle and vtable pointers are always cleared regardless of FreeLibrary result\n- ESI register saved and restored (callee-saved) for function use",
      "name_source": "LoD/PD2",
      "method": "API",
      "index": "API:3422fd17221814fd2a54fd653470b117",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": "3422fd17221814fd2a54fd653470b117",
        "MNE": "ca8476b621b119a9a2d067d303cc151b",
        "CFG": "d69bc82e329d76c21526cdfbd9e8cc3d",
        "PRO": "cd01f1ed4ac3507bc73cdba076f4e794"
      },
      "basic_block_counts": {
        "LoD/PD2": 4
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "api_calls": {
        "LoD/PD2": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "InitializeCleanupForEntryPoint"
        ]
      }
    },
    "D2gfx_STR_f6ed78b03f12": {
      "addresses": {
        "LoD/PD2": "0x6FA8B400"
      },
      "rvas": {
        "LoD/PD2": "0xB400"
      },
      "sizes": {
        "LoD/PD2": 170
      },
      "name": "InitializeGraphicsDLL",
      "signature": "uint InitializeGraphicsDLL(void)",
      "calling_convention": "__stdcall",
      "comment": "Initializes graphics subsystem by dynamically loading graphics DLL and retrieving vtable.\n\nAlgorithm:\n1. Get graphics DLL filename from table at DAT_6fa90c18 indexed by video mode (ESI)\n2. Check if DLL filename pointer is valid; if null, report unsupported mode error\n3. Load graphics DLL into memory using LoadLibraryA() and store handle in DAT_6fa9126c\n4. If LoadLibraryA fails, format error message with DLL name and return 0\n5. Call GetCursorResource() to initialize cursor resources for graphics mode\n6. Call GetProcAddress() with loaded DLL handle and ordinal 0x2710 to find graphics factory\n7. If GetProcAddress fails, retrieve error code with GetLastError() and return 0\n8. Call graphics vtable factory function via returned function pointer\n9. Store returned vtable pointer in global g_GraphicsVtablePtr (DAT_6fa91268)\n10. Return 1 on success, 0 on any failure\n\nParameters:\nESI (implicit) - Video mode index used to select DLL filename from table at DAT_6fa90c18\n  Values: 0+ (typically 0-2 for different video modes like D3D, D3D software, etc.)\n\nReturns:\n1 - Graphics DLL loaded successfully and vtable initialized\n0 - DLL load failed, graphics factory ordinal not found, or unsupported video mode\n\nSpecial Cases:\n- Video mode table (DAT_6fa90c18): Array of LPCSTR pointers, one per supported video mode\n- Ordinal 0x2710 (10000 decimal): Graphics vtable factory function exported by ordinal\n- Stack buffer (64 bytes): Used for error message formatting via wsprintfA()\n- ESI preserved: Function uses ESI as implicit parameter and returns unmodified\n- Globals modified: DAT_6fa9126c (graphics DLL handle), DAT_6fa91268 (graphics vtable)",
      "name_source": "LoD/PD2",
      "method": "STR",
      "index": "STR:f6ed78b03f125024eca606c1c00a0c27",
      "indexes": {
        "EXP": null,
        "STR": "f6ed78b03f125024eca606c1c00a0c27",
        "API": "4ba1e2e8f6b24ece8c603c4786523d32",
        "MNE": "aebe2442c437b7f6c9c8b32d7d362cfb",
        "CFG": "a10651910d68d1e0ee442b13a3fdacab",
        "PRO": "c0ef1477981bacdd4c84bdb0077f78ec"
      },
      "basic_block_counts": {
        "LoD/PD2": 7
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "api_calls": {
        "LoD/PD2": [
          "ValidateAndInitializeParameter",
          "InitializeCleanupForEntryPoint"
        ]
      }
    },
    "D2gfx_STR_91b4514c8a8e": {
      "addresses": {
        "LoD/PD2": "0x6FA8B4B0"
      },
      "rvas": {
        "LoD/PD2": "0xB4B0"
      },
      "sizes": {
        "LoD/PD2": 176
      },
      "name": "CleanupWindowAndDisplayError",
      "signature": "void CleanupWindowAndDisplayError(void)",
      "calling_convention": "__stdcall",
      "comment": "Cleanup window resources and display error message to user via MessageBox.\n\nAlgorithm:\n1. Format error message string using sprintf with format string pointer\n2. Store formatted error message in 256-byte error buffer\n3. Display error message to user via MessageBoxA:\n   - NULL parent window handle\n   - Formatted error message text\n   - NULL title (uses default)\n   - MB_OK button style\n4. Unregister window class via UnregisterClassA to cleanup registered classes\n5. Free graphics library resources via FreeGraphicsLibrary\n6. Return to caller (no return value)\n\nParameters:\n- None (void function)\n\nReturns:\n- void (no return value)\n\nSpecial Cases:\n- Error buffer is stack-allocated (256 bytes) for formatted message\n- Uses MessageBoxA for ANSI string display\n- Window class unregistration may fail silently if class not registered\n- Graphics library cleanup handles NULL/invalid library pointers safely\n\nGlobal Dependencies:\n- MessageBoxA: Win32 API for displaying modal dialog\n- UnregisterClassA: Win32 API for unregistering window class\n- FreeGraphicsLibrary: Custom graphics subsystem cleanup\n\nMagic Numbers:\n- 256: Size of error message buffer in bytes (standard for error strings)",
      "name_source": "LoD/PD2",
      "method": "STR",
      "index": "STR:91b4514c8a8e6156116dea22f727b4da",
      "indexes": {
        "EXP": null,
        "STR": "91b4514c8a8e6156116dea22f727b4da",
        "API": null,
        "MNE": "bfd179fffc3764c8e8b3de8fbe0c1496",
        "CFG": "bb2d29c85306f40b8ffddce47a988e1f",
        "PRO": "9a8388ac0fde0c4bf9f0ecdb935cc31e"
      },
      "basic_block_counts": {
        "LoD/PD2": 12
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "D2gfx_STR_2268699a57d6": {
      "addresses": {
        "LoD/PD2": "0x6FA8B580"
      },
      "rvas": {
        "LoD/PD2": "0xB580"
      },
      "sizes": {
        "LoD/PD2": 352
      },
      "name": "InitializeGraphicsAndWindow",
      "signature": "uint InitializeGraphicsAndWindow(void * pHInstance, void * pWndProc, int nDisplayMode, uint dwUnknown)",
      "calling_convention": "__stdcall",
      "comment": "Initialize graphics subsystem and register window class.\n\nRegisters the main application window class with Windows, loads application\nresources (icon and cursor), initializes the graphics DLL and vtable, and\nsets the display mode configuration.\n\nAlgorithm:\n1. Store pHInstance and pWndProc to global variables\n2. Initialize WNDCLASSA structure with window class properties\n3. Load application icon resource (resource ID 0x66 or 0x67)\n4. Load standard IDC_ARROW cursor\n5. Set background brush to NULL_BRUSH (stock object 5)\n6. Call RegisterClassA to register window class\n7. If RegisterClassA fails, get error code and display dialog\n8. Call InitializeAndValidateDataTable to set up data structures\n9. Register ShowAllWindows function with atexit for cleanup\n10. Store display mode and dwUnknown to globals\n11. Call InitializeGraphicsDLL to load graphics library\n12. Call graphics vtable functions for initialization and validation\n13. Return result or 0 on failure\n\nParameters:\npHInstance - Application instance handle from WinMain\npWndProc - Window procedure callback function pointer\nnDisplayMode - Display mode configuration (0-4 = windowed, 5+ = fullscreen)\ndwUnknown - Unknown parameter stored to global\n\nReturns:\nNon-zero (1) - Success: Window class registered and graphics initialized\n0 - Failure: RegisterClassA failed or graphics DLL initialization failed\n\nSpecial Cases:\n- If nDisplayMode == 5, window style has CS_OWNDC (0x20) masked off\n- If nDisplayMode < 4, DAT_6fa90be4 is cleared to 0",
      "name_source": "LoD/PD2",
      "method": "STR",
      "index": "STR:2268699a57d622c66cb16d1e6317981c",
      "indexes": {
        "EXP": null,
        "STR": "2268699a57d622c66cb16d1e6317981c",
        "API": "211f780722a1f377c6c33dcf487bfe03",
        "MNE": "0c639397cf951f566cdf900cef8d8abf",
        "CFG": "5401cb6de78985c11482bf622199a717",
        "PRO": "e85fd91c24e9a07748c0606eea4b8905"
      },
      "basic_block_counts": {
        "LoD/PD2": 9
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "api_calls": {
        "LoD/PD2": [
          "FindAndValidateD2ExpMpq",
          "LogErrorAndShutdown"
        ]
      },
      "param_counts": {
        "LoD/PD2": 4
      }
    },
    "D2gfx_MNE_d9dcd663dd64": {
      "addresses": {
        "LoD/PD2": "0x6FA8B870"
      },
      "rvas": {
        "LoD/PD2": "0xB870"
      },
      "sizes": {
        "LoD/PD2": 38
      },
      "name": "DecrementWithMinBound",
      "signature": "void DecrementWithMinBound(void)",
      "calling_convention": "__stdcall",
      "comment": "Decrement global counter with minimum boundary enforcement.\n\nAlgorithm:\n1. Load current value from global counter g_dwVirtualStateSource into EAX\n2. Compare EAX against minimum boundary 0x100\n3. If value <= 0x100, skip decrement and return unchanged\n4. If value > 0x100, subtract 0x20 (decrement by 32)\n5. Compare decremented value against minimum boundary 0x100\n6. Store result back to g_dwVirtualStateSource\n7. If decremented value >= 0x100, return with valid decrement\n8. If decremented value < 0x100, reset to minimum boundary 0x100\n9. Return to caller\n\nParameters:\n  None: Function takes no parameters and operates solely on global state\n\nReturns:\n  void: No explicit return value. Modifies global g_dwVirtualStateSource. If original value <= 0x100, unchanged. If original value > 0x100, decreased by 0x20 or clamped to 0x100 if result drops below minimum.\n\nSpecial Cases:\n  - Magic threshold: 0x100 (256 decimal) is the minimum boundary value\n  - Magic decrement: 0x20 (32 decimal) is the decrement amount\n  - Two-stage validation: checks before decrement and after decrement\n  - Boundary clamping: any value below 0x100 gets reset to exactly 0x100",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:d9dcd663dd64b24c75ef6092525c3937",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "d9dcd663dd64b24c75ef6092525c3937",
        "CFG": "76db6c382c26eeeef0f0e1f77aac8844",
        "PRO": "15e0db93f33c29d5096d42d538a46869"
      },
      "basic_block_counts": {
        "LoD/PD2": 6
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "D2gfx_MNE_b1c1c1b51857": {
      "addresses": {
        "LoD/PD2": "0x6FA8B8A0"
      },
      "rvas": {
        "LoD/PD2": "0xB8A0"
      },
      "sizes": {
        "LoD/PD2": 38
      },
      "name": "IncrementWithMaxBound",
      "signature": "void IncrementWithMaxBound(void)",
      "calling_convention": "__stdcall",
      "comment": "Increment value with maximum boundary enforcement\n\nAlgorithm:\n1. Load current value from global g_dwVirtualStateSource\n2. Compare value against maximum boundary 0x200\n3. If value >= 0x200, jump to return (already at or above maximum)\n4. Add 0x20 (32 decimal) to the current value\n5. Store the updated value back to g_dwVirtualStateSource\n6. Compare updated value against maximum boundary 0x200\n7. If updated value <= 0x200, jump to return (within bounds)\n8. If updated value > 0x200, clamp value to maximum 0x200\n9. Return to caller\n\nParameters:\nNone - This function operates on global state (g_dwVirtualStateSource at 0x6FA90BD8)\n\nReturns:\nvoid - No return value. Modifies global g_dwVirtualStateSource in place, ensuring the value never exceeds 0x200\n\nSpecial Cases:\n- Magic values: increment size 0x20 (32), maximum boundary 0x200 (512)\n- Two-stage validation: pre-increment check (if >= max, skip) and post-increment clamping (if > max, reset to max)\n- Complement function: pairs with DecrementWithMinBound which manages the minimum boundary\n- Global state: all operations on g_dwVirtualStateSource at address 0x6FA90BD8",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:b1c1c1b51857eba327201737c699d22f",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "b1c1c1b51857eba327201737c699d22f",
        "CFG": "76db6c382c26eeeef0f0e1f77aac8844",
        "PRO": "470897169debb37d4d3dc45d28cbc1d7"
      },
      "basic_block_counts": {
        "LoD/PD2": 6
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "D2gfx_MNE_6fafd9d61e99": {
      "addresses": {
        "LoD/PD2": "0x6FA8B8D0"
      },
      "rvas": {
        "LoD/PD2": "0xB8D0"
      },
      "sizes": {
        "LoD/PD2": 19
      },
      "name": "SetConstantAndJumpVirtual54",
      "signature": "void SetConstantAndJumpVirtual54(void)",
      "calling_convention": "__stdcall",
      "comment": "Set virtual state constant and dispatch to virtual method handler\n\nAlgorithm:\n1. Load graphics object pointer from global g_pGraphicsVtable into EAX\n2. Load constant value 0x100 (256) into ECX register\n3. Store constant 0x100 to global variable g_dwVirtualStateDestination\n4. Jump indirectly to virtual function at offset +0x54 in the vtable (virtual method dispatch)\n\nParameters:\nNone - This is a wrapper function with no parameters\n\nReturns:\nvoid - Control transferred via indirect jump to virtual method handler, does not return to caller\n\nSpecial Cases:\n- Magic constant: 0x100 (256 decimal) - Virtual state identifier\n- Virtual method offset: 0x54 from vtable base\n- Indirect jump semantics: Transfers control to virtual method without returning to this function\n- Used for virtual method dispatch pattern in graphics subsystem",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:6fafd9d61e995ac46683353d63a5b0e1",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "6fafd9d61e995ac46683353d63a5b0e1",
        "CFG": "82ab21280f7756b94aebf888fcf167cf",
        "PRO": "d17b83d0dbe6cd85ecafc858101ba059"
      },
      "basic_block_counts": {
        "LoD/PD2": 2
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "D2gfx_MNE_3b2b18453ee5": {
      "addresses": {
        "LoD/PD2": "0x6FA8B900"
      },
      "rvas": {
        "LoD/PD2": "0xB900"
      },
      "sizes": {
        "LoD/PD2": 20
      },
      "name": "CopyAndJumpVirtual54",
      "signature": "void CopyAndJumpVirtual54(void)",
      "calling_convention": "__stdcall",
      "comment": "Copy virtual state and transfer control to virtual function at offset +0x54.\\n\\nAlgorithm:\\n1. Load source state value from g_dwVirtualStateSource into ECX\\n2. Load graphics object pointer from g_pGraphicsVtable into EAX\\n3. Copy source state value to g_dwVirtualStateDestination\\n4. Indirect jump to virtual method at offset +0x54 in the object's virtual method table\\n\\nParameters:\\nNone - This is a stateless wrapper function that operates entirely on global state.\\n\\nReturns:\\nvoid - Control never returns; function transfers control via indirect JMP to virtual method.\\n\\nSpecial Cases:\\n- Uses indirect JMP (not CALL), so control is not expected to return to caller\\n- Operates on shared global state (g_dwVirtualStateSource, g_dwVirtualStateDestination)\\n- Virtual method table assumed to be valid pointer in g_pGraphicsVtable\\n- This is one of multiple virtual dispatch wrappers (Virtual0 through Virtual127) that copy state before indirect jumps",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:3b2b18453ee59915d76c8b37fa8cc12b",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "3b2b18453ee59915d76c8b37fa8cc12b",
        "CFG": "cdcb69a505c3a7b19c0b68edd29573c9",
        "PRO": "5c89c78f71cca65720b8841053cd0cee"
      },
      "basic_block_counts": {
        "LoD/PD2": 2
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "D2gfx_MNE_3afa8072d22a": {
      "addresses": {
        "LoD/PD2": "0x6FA8B9A0"
      },
      "rvas": {
        "LoD/PD2": "0xB9A0"
      },
      "sizes": {
        "LoD/PD2": 18
      },
      "name": "CallVirtualMethodC4",
      "signature": "void CallVirtualMethodC4(uint dwMethodParam)",
      "calling_convention": "__stdcall",
      "comment": "Wrapper function that invokes a virtual method at offset +0xc4 from the global graphics object.\n\nAlgorithm:\n1. Load parameter from stack into ECX register\n2. Load global graphics vtable pointer from address 0x6fa91268 into EAX\n3. Call the virtual function at offset +0xc4 from the graphics object base address\n4. Return to caller with stack cleanup\n\nParameters:\ndwMethodParam (uint): Method parameter passed via ECX register to the virtual method\n\nReturns:\nvoid - No return value\n\nSpecial Cases:\n- Virtual method dispatch at offset +0xc4 corresponds to D3D graphics operations\n- Global graphics object pointer (g_pGraphicsVtable) is used as implicit 'this' pointer\n- __stdcall calling convention: callee cleans 0x4 bytes from stack (1 parameter)\n- Extremely lightweight wrapper for performance-critical graphics dispatch",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:3afa8072d22a2bea75c54eb93b71830f",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "3afa8072d22a2bea75c54eb93b71830f",
        "CFG": "3a5fcfe2ddabc615aa9c6675a4c571ba",
        "PRO": "00898a2302ece00ca2067491d07d7afd"
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
    "D2gfx_MNE_5d4d9ee9ea92": {
      "addresses": {
        "LoD/PD2": "0x6FA8B9F0"
      },
      "rvas": {
        "LoD/PD2": "0xB9F0"
      },
      "sizes": {
        "LoD/PD2": 54
      },
      "name": "ValidateAndCallVirtualBc",
      "signature": "void ValidateAndCallVirtualBc(int nMinValue1, int nMinValue2, int nMinValue3, int nMinValue4, uint dwMaxValue1, uint dwMaxValue2)",
      "calling_convention": "__stdcall",
      "comment": "Setting prototype: void ValidateAndCallVirtualBc(int nMinValue1, int nMinValue2, int nMinValue3, int nMinValue4, uint dwMaxValue1, uint dwMaxValue2)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:5d4d9ee9ea92d8a7f3ceaea5fbd777c9",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "5d4d9ee9ea92d8a7f3ceaea5fbd777c9",
        "CFG": "6b8757769b4a8dc1956bb7f6d879d16b",
        "PRO": "e3d1dd1d1eab1f064b5afe2efb2febd6"
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
    "D2gfx_MNE_cafb15237b5e": {
      "addresses": {
        "LoD/PD2": "0x6FA8BA70"
      },
      "rvas": {
        "LoD/PD2": "0xBA70"
      },
      "sizes": {
        "LoD/PD2": 27
      },
      "name": "CallVirtualMethodB4",
      "signature": "void CallVirtualMethodB4(uint param1, uint param2, uint param3)",
      "calling_convention": "__stdcall",
      "comment": "Invokes a virtual method at offset +0xb4 with three parameters.\n\nAlgorithm:\n1. Load third parameter from stack [ESP+0xc] into EAX\n2. Load second parameter from stack [ESP+0x8] into EDL (byte)\n3. Load first parameter from stack [ESP+0x4] into ECX\n4. Push third parameter to stack for passing to virtual method\n5. Load global graphics vtable pointer from 0x6FA91268 into EAX\n6. Call virtual method at offset +0xb4 from vtable base (CALL [EAX+0xb4])\n7. Return to caller with callee cleanup of 0xc bytes (3 parameters)\n\nParameters:\nparam1 (uint): First method parameter, passed in ECX register\nparam2 (uint): Second method parameter, passed in EDL register (byte)\nparam3 (uint): Third method parameter, pushed to stack\n\nReturns:\nvoid - This function does not return a value to the caller. The virtual method\n  is invoked via indirect call through the graphics vtable. Any return value\n  from the virtual method is discarded.\n\nSpecial Cases:\n- This is part of a series of virtual method wrapper functions (B0, B4, B8, etc.)\n- The offset +0xb4 is consistent across multiple wrapper functions\n- __stdcall calling convention: callee cleans 0xc bytes from stack\n- Second parameter loaded as byte suggests it may be a boolean or small value\n- Global vtable at 0x6FA91268 is referenced from 71 locations throughout binary",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:cafb15237b5e84f590251fd658e49815",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "cafb15237b5e84f590251fd658e49815",
        "CFG": "26cdfa4e9a5202faa81756f8775cf88f",
        "PRO": "7584d93c0fadac1abd4b9b5984d7dd83"
      },
      "basic_block_counts": {
        "LoD/PD2": 2
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 3
      }
    },
    "D2gfx_MNE_2cea028ef602": {
      "addresses": {
        "LoD/PD2": "0x6FA8BB80"
      },
      "rvas": {
        "LoD/PD2": "0xBB80"
      },
      "sizes": {
        "LoD/PD2": 32
      },
      "name": "CallGraphicsVtableMethod0xcc",
      "signature": "void CallGraphicsVtableMethod0xcc(uint unused1, uint unused2, uint param1, uint param2)",
      "calling_convention": "__stdcall",
      "comment": "Setting prototype: void CallGraphicsVtableMethod0xcc(uint unused1, uint unused2, uint param1, uint param2)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:2cea028ef602e29fdf72f41ddcb408c0",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "2cea028ef602e29fdf72f41ddcb408c0",
        "CFG": null,
        "PRO": "e6e19a62dc9a1a47ae41060c0193e5be"
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
    "D2gfx_MNE_711b2e0d0d87": {
      "addresses": {
        "LoD/PD2": "0x6FA8BBA0"
      },
      "rvas": {
        "LoD/PD2": "0xBBA0"
      },
      "sizes": {
        "LoD/PD2": 30
      },
      "name": "CallGraphicsVtable_0x64WithParams",
      "signature": "void CallGraphicsVtable_0x64WithParams(void * pArg1, void * pArg2, void * pArg3)",
      "calling_convention": "__cdecl",
      "comment": "Setting prototype: void CallGraphicsVtable_0x64WithParams(void* pArg1, void* pArg2, void* pArg3)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:711b2e0d0d87a17ec2d1d568182c417b",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "711b2e0d0d87a17ec2d1d568182c417b",
        "CFG": null,
        "PRO": "3ea3294c6787ac35af21664d87a2d1d7"
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
    "D2gfx_MNE_489067da1a2c": {
      "addresses": {
        "LoD/PD2": "0x6FA8BBBE"
      },
      "rvas": {
        "LoD/PD2": "0xBBBE"
      },
      "sizes": {
        "LoD/PD2": 43
      },
      "name": "_JumpToContinuation",
      "signature": "void _JumpToContinuation(void * param_1, EHRegistrationNode * param_2)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Single Match\n void __stdcall _JumpToContinuation(void *,struct EHRegistrationNode *)\n\nLibrary: Visual Studio 2003 Release",
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
    "D2gfx_MNE_772d22c2541e": {
      "addresses": {
        "LoD/PD2": "0x6FA8BBEE"
      },
      "rvas": {
        "LoD/PD2": "0xBBEE"
      },
      "sizes": {
        "LoD/PD2": 7
      },
      "name": "CallMemberDestructor",
      "signature": "void CallMemberDestructor(MemberDestructorThunk * pDestructorContext, MemberDestructorThunk * pfnDestructor)",
      "calling_convention": "__stdcall",
      "comment": "Setting prototype: void CallMemberDestructor(MemberDestructorThunk *pDestructorContext, MemberDestructorThunk *pfnDestructor)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:772d22c2541e825eefebea33eefd1baf",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "772d22c2541e825eefebea33eefd1baf",
        "CFG": null,
        "PRO": "bb2d1da90e1266707238b5d8cb61f61d"
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
    "D2gfx_MNE_d9a12ae164ce": {
      "addresses": {
        "LoD/PD2": "0x6FA8BBF5"
      },
      "rvas": {
        "LoD/PD2": "0xBBF5"
      },
      "sizes": {
        "LoD/PD2": 82
      },
      "name": "_UnwindNestedFrames",
      "signature": "void _UnwindNestedFrames(EHRegistrationNode * param_1, EHExceptionRecord * param_2)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Single Match\n void __stdcall _UnwindNestedFrames(struct EHRegistrationNode *,struct EHExceptionRecord *)\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:d9a12ae164ceeb71b3ef1de062e62e18",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "d9a12ae164ceeb71b3ef1de062e62e18",
        "CFG": null,
        "PRO": "8745aed0d079056657ef74ec8cd6995e"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "api_calls": {
        "LoD/PD2": [
          "RtlUnwind"
        ]
      },
      "param_counts": {
        "LoD/PD2": 2
      }
    },
    "D2gfx_MNE_c3e67f0f66e9": {
      "addresses": {
        "LoD/PD2": "0x6FA8BC47"
      },
      "rvas": {
        "LoD/PD2": "0xBC47"
      },
      "sizes": {
        "LoD/PD2": 54
      },
      "name": "___CxxFrameHandler",
      "signature": "undefined4 ___CxxFrameHandler(EHExceptionRecord * param_1, EHRegistrationNode * param_2, _CONTEXT * param_3, void * param_4)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___CxxFrameHandler\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:c3e67f0f66e9fe1748a93603f0dc99e6",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "c3e67f0f66e9fe1748a93603f0dc99e6",
        "CFG": null,
        "PRO": "59081befd9c7c0fdc4e2ca0bf81d2b50"
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
    "D2gfx_MNE_940b36171c84": {
      "addresses": {
        "LoD/PD2": "0x6FA8BCB8"
      },
      "rvas": {
        "LoD/PD2": "0xBCB8"
      },
      "sizes": {
        "LoD/PD2": 199
      },
      "name": "_CallSETranslator",
      "signature": "int _CallSETranslator(EHExceptionRecord * param_1, EHRegistrationNode * param_2, void * param_3, void * param_4, _s_FuncInfo * param_5, int param_6, EHRegistrationNode * param_7)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n int __cdecl _CallSETranslator(struct EHExceptionRecord *,struct EHRegistrationNode *,void *,void *,struct _s_FuncInfo const *,int,struct EHRegistrationNode *)\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:940b36171c849cbdb70fa26527e4a4dd",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "940b36171c849cbdb70fa26527e4a4dd",
        "CFG": "75fe8eb5309a87431907da3c5c2b5f61",
        "PRO": "51538878d2f86b13ad416058676e8b3c"
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
    "D2gfx_MNE_9ed74c09db5e": {
      "addresses": {
        "LoD/PD2": "0x6FA8BD7F"
      },
      "rvas": {
        "LoD/PD2": "0xBD7F"
      },
      "sizes": {
        "LoD/PD2": 175
      },
      "name": "TranslatorGuardHandler",
      "signature": "int TranslatorGuardHandler(EHExceptionRecord * pExceptionRecord, TranslatorGuardRN * pGuardData, CONTEXT * pContext, void * pDispatcherContext)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n enum _EXCEPTION_DISPOSITION __cdecl TranslatorGuardHandler(struct EHExceptionRecord *,struct TranslatorGuardRN *,void *,void *)\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:9ed74c09db5ea664214a06af5e9eacff",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "9ed74c09db5ea664214a06af5e9eacff",
        "CFG": "2c2b41e5f94ce646e02540fd4b0fb252",
        "PRO": "2abd5a9d0c7aa8c75cf0631f0d6b6b2a"
      },
      "basic_block_counts": {
        "LoD/PD2": 9
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 4
      }
    },
    "D2gfx_MNE_c9529d246abf": {
      "addresses": {
        "LoD/PD2": "0x6FA8BE31"
      },
      "rvas": {
        "LoD/PD2": "0xBE31"
      },
      "sizes": {
        "LoD/PD2": 122
      },
      "name": "_GetRangeOfTrysToCheck",
      "signature": "_s_TryBlockMapEntry * _GetRangeOfTrysToCheck(_s_FuncInfo * param_1, int param_2, int param_3, uint * param_4, uint * param_5)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n struct _s_TryBlockMapEntry const * __cdecl _GetRangeOfTrysToCheck(struct _s_FuncInfo const *,int,int,unsigned int *,unsigned int *)\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:c9529d246abf4faab672947c5021a4d5",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "c9529d246abf4faab672947c5021a4d5",
        "CFG": "e07eccead1f73292e394bcf6b04e25be",
        "PRO": "8f133c45fa0a28d00f17557d1230bba1"
      },
      "basic_block_counts": {
        "LoD/PD2": 13
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 5
      }
    },
    "D2gfx_MNE_bd2e318ad253": {
      "addresses": {
        "LoD/PD2": "0x6FA8BEAB"
      },
      "rvas": {
        "LoD/PD2": "0xBEAB"
      },
      "sizes": {
        "LoD/PD2": 40
      },
      "name": "_CreateFrameInfo",
      "signature": "FrameInfo * _CreateFrameInfo(FrameInfo * param_1, void * param_2)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n struct FrameInfo * __cdecl _CreateFrameInfo(struct FrameInfo *,void *)\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:bd2e318ad25348813665cf4effb251a4",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "bd2e318ad25348813665cf4effb251a4",
        "CFG": null,
        "PRO": "1a7b83fd93de604000b09aaee3692d98"
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
    "D2gfx_MNE_6d6cf4ba1895": {
      "addresses": {
        "LoD/PD2": "0x6FA8BED3"
      },
      "rvas": {
        "LoD/PD2": "0xBED3"
      },
      "sizes": {
        "LoD/PD2": 33
      },
      "name": "IsExceptionObjectToBeDestroyed",
      "signature": "int IsExceptionObjectToBeDestroyed(void * pExceptionObject)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n int __cdecl IsExceptionObjectToBeDestroyed(void *)\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:6d6cf4ba189585a4cd2d487202ee7142",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "6d6cf4ba189585a4cd2d487202ee7142",
        "CFG": "80d7cba25940b8a2a85ec71cc60a4ce9",
        "PRO": "2f1e43385ff08c808d019799632e3b67"
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
    "D2gfx_MNE_decef60e401f": {
      "addresses": {
        "LoD/PD2": "0x6FA8BEF4"
      },
      "rvas": {
        "LoD/PD2": "0xBEF4"
      },
      "sizes": {
        "LoD/PD2": 76
      },
      "name": "_FindAndUnlinkFrame",
      "signature": "void _FindAndUnlinkFrame(FrameInfo * param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n void __cdecl _FindAndUnlinkFrame(struct FrameInfo *)\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:decef60e401f8e90b7116a8a0959e784",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "decef60e401f8e90b7116a8a0959e784",
        "CFG": "9507edb72158a2a748bebdf37e4cfd3c",
        "PRO": "b8e36630ac9422663e03a5a87a5df15c"
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
    "D2gfx_MNE_305f98c2994b": {
      "addresses": {
        "LoD/PD2": "0x6FA8BF40"
      },
      "rvas": {
        "LoD/PD2": "0xBF40"
      },
      "sizes": {
        "LoD/PD2": 89
      },
      "name": "_CallCatchBlock2",
      "signature": "void * _CallCatchBlock2(EHRegistrationNode * param_1, _s_FuncInfo * param_2, void * param_3, int param_4, ulong param_5)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n void * __cdecl _CallCatchBlock2(struct EHRegistrationNode *,struct _s_FuncInfo const *,void *,int,unsigned long)\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:305f98c2994b523fe4a005bfb539afe0",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "305f98c2994b523fe4a005bfb539afe0",
        "CFG": null,
        "PRO": "611ba9b1c1370bd1a61e482351b36063"
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
    "D2gfx_MNE_e86a21cb50bb": {
      "addresses": {
        "LoD/PD2": "0x6FA8BF99"
      },
      "rvas": {
        "LoD/PD2": "0xBF99"
      },
      "sizes": {
        "LoD/PD2": 79
      },
      "name": "TypeMatch",
      "signature": "int TypeMatch(_s_HandlerType * pHandler, _s_CatchableType * pCatchable, _s_ThrowInfo * pThrowInfo)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n int __cdecl TypeMatch(struct _s_HandlerType const *,struct _s_CatchableType const *,struct _s_ThrowInfo const *)\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:e86a21cb50bb81e60f0de3031d840cd4",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "e86a21cb50bb81e60f0de3031d840cd4",
        "CFG": "af5701d78567757751d7583904030786",
        "PRO": "a280373490c40bc4a90491d0ec57b305"
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
    "D2gfx_MNE_4adabfa42592": {
      "addresses": {
        "LoD/PD2": "0x6FA8BFE8"
      },
      "rvas": {
        "LoD/PD2": "0xBFE8"
      },
      "sizes": {
        "LoD/PD2": 30
      },
      "name": "FrameUnwindFilter",
      "signature": "int FrameUnwindFilter(void * pExceptionPointers)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n int __cdecl FrameUnwindFilter(struct _EXCEPTION_POINTERS *)\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:4adabfa425928517cf130be62eff166e",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "4adabfa425928517cf130be62eff166e",
        "CFG": "96866a4ce8b4f0299246ba15185965f9",
        "PRO": "26eb74d01ac3fb6153b8698d0186c52a"
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
    "D2gfx_MNE_0e5fe8f035f6": {
      "addresses": {
        "LoD/PD2": "0x6FA8C006"
      },
      "rvas": {
        "LoD/PD2": "0xC006"
      },
      "sizes": {
        "LoD/PD2": 148
      },
      "name": "___FrameUnwindToState",
      "signature": "undefined ___FrameUnwindToState(int param_1, undefined4 param_2, int param_3, int param_4)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___FrameUnwindToState\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:0e5fe8f035f67d55ee839a615aebb8b3",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "0e5fe8f035f67d55ee839a615aebb8b3",
        "CFG": "01d2b40e39bbd1728477b217b34d73b6",
        "PRO": "e1b82019574c21d174f23b4976292499"
      },
      "basic_block_counts": {
        "LoD/PD2": 12
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 4
      }
    },
    "D2gfx_MNE_898894f98c67": {
      "addresses": {
        "LoD/PD2": "0x6FA8C0B9"
      },
      "rvas": {
        "LoD/PD2": "0xC0B9"
      },
      "sizes": {
        "LoD/PD2": 26
      },
      "name": "DecrementPureCallCounter",
      "signature": "void DecrementPureCallCounter(void)",
      "calling_convention": "__stdcall",
      "comment": "Decrements the pure virtual call counter in the current thread's data block.\n\nThis function is part of the C++ exception handling mechanism. It decrements\nthe _purecall field (offset +0x84) in the thread-local data structure when\nunwinding from a pure virtual function call handler.\n\nAlgorithm:\n1. Retrieve current thread data block pointer via __getptd()\n2. Check if _purecall counter is greater than zero\n3. If counter is positive, retrieve thread data again and decrement counter\n4. Return to caller\n\nParameters:\n  None\n\nReturns:\n  void - No return value\n\nSpecial Cases:\n  - If _purecall counter is already zero or negative, no decrement occurs\n  - Double call to __getptd() ensures fresh thread data for modification\n  - Uses offset +0x84 to access _purecall field in _tiddata structure\n\nStructure Layout (_tiddata):\n  Offset | Size | Field Name    | Type      | Description\n  -------|------|---------------|-----------|---------------------------\n  +0x84  | 4    | _purecall     | void*     | Pure virtual call counter",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:898894f98c67bfd44b8002f821424647",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "898894f98c67bfd44b8002f821424647",
        "CFG": "9c4b7358ea8c9341b985f641cf18d2d4",
        "PRO": "b986d8a97b431779e5be36a6baa25ebc"
      },
      "basic_block_counts": {
        "LoD/PD2": 2
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "D2gfx_MNE_efa2f79526cd": {
      "addresses": {
        "LoD/PD2": "0x6FA8C0D4"
      },
      "rvas": {
        "LoD/PD2": "0xC0D4"
      },
      "sizes": {
        "LoD/PD2": 52
      },
      "name": "___DestructExceptionObject",
      "signature": "undefined ___DestructExceptionObject(int param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___DestructExceptionObject\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:efa2f79526cd6c984f92f3e2beec5d87",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "efa2f79526cd6c984f92f3e2beec5d87",
        "CFG": "8bbfe2737ef55f3a9a35ae1b43be54c6",
        "PRO": "6fdbf3a3dafd3e1983a5f299b6c18ece"
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
    "D2gfx_MNE_85190b86d73e": {
      "addresses": {
        "LoD/PD2": "0x6FA8C119"
      },
      "rvas": {
        "LoD/PD2": "0xC119"
      },
      "sizes": {
        "LoD/PD2": 31
      },
      "name": "AdjustPointer",
      "signature": "void * AdjustPointer(void * pObjectPtr, PMD * pPMD)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n void * __cdecl AdjustPointer(void *,struct PMD const &)\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:85190b86d73ebdc8e5739dd02ae41128",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "85190b86d73ebdc8e5739dd02ae41128",
        "CFG": "ebedb8faf55908534e596ba5d47d40c7",
        "PRO": "8e9aad4aec1880b71db46c0be4aeff4c"
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
    "D2gfx_MNE_0cd6dc09c874": {
      "addresses": {
        "LoD/PD2": "0x6FA8C138"
      },
      "rvas": {
        "LoD/PD2": "0xC138"
      },
      "sizes": {
        "LoD/PD2": 157
      },
      "name": "CallCatchBlock",
      "signature": "void * CallCatchBlock(EHExceptionRecord * pExceptionRecord, EHRegistrationNode * pRegistrationNode, _CONTEXT * pContext, _s_FuncInfo * pFuncInfo, void * pCatchHandler, int nCatchIndex, ulong dwThrowFlags)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n void * __cdecl CallCatchBlock(struct EHExceptionRecord *,struct EHRegistrationNode *,struct _CONTEXT *,struct _s_FuncInfo const *,void *,int,unsigned long)\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:0cd6dc09c8745218b08aa07ad6229378",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "0cd6dc09c8745218b08aa07ad6229378",
        "CFG": "b1af6f7b21571bb27a714641cd69b81d",
        "PRO": "4284d497cf1a638b71f8bfe469403b6d"
      },
      "basic_block_counts": {
        "LoD/PD2": 4
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 7
      }
    },
    "D2gfx_MNE_63ed7c9fbe9f": {
      "addresses": {
        "LoD/PD2": "0x6FA8C28D"
      },
      "rvas": {
        "LoD/PD2": "0xC28D"
      },
      "sizes": {
        "LoD/PD2": 111
      },
      "name": "CleanupCppExceptionFrame",
      "signature": "void CleanupCppExceptionFrame(void)",
      "calling_convention": "__stdcall",
      "comment": "Cleanup C++ exception frame and optionally destroy exception object\n\nThis function is called during C++ exception handling cleanup to restore the\nexception frame state and conditionally destroy the exception object. It handles\nMicrosoft Visual C++ exceptions (magic 0xE06D7363) and checks version compatibility.\n\nAlgorithm:\n1. Save return value from stack frame [EBP-0x38] to [EDI-0x4]\n2. Unlink exception frame from thread's exception chain\n3. Restore thread-local unexpected handler from [EBP-0x40] to ptd->_unexpected\n4. Restore thread-local translator from [EBP-0x44] to ptd->_translator\n5. Verify exception signature: check magic 0xE06D7363 at [ESI+0x0]\n6. Verify exception parameter count: check value 3 at [ESI+0x10]\n7. Verify VC++ version: check 0x19930520 or 0x19930521 at [ESI+0x14]\n8. Check destructor flags: verify [EBP-0x48] == 0 and [EBP-0x20] != 0\n9. Query if exception object at [ESI+0x18] should be destroyed\n10. If destruction needed, call abnormal_termination check then destruct object\n\nParameters:\nIMPLICIT EBP = Pointer to exception frame context on stack\nIMPLICIT ESI = Pointer to EXCEPTION_RECORD structure\nIMPLICIT EDI = Pointer to stack frame for return value storage\n\nReturns:\nvoid - No return value\n\nSpecial Cases:\n- Magic number 0xE06D7363 is MS C++ exception code ('msc' | 0xE0000000)\n- Versions 0x19930520 and 0x19930521 are VC++ 4.0+ exception formats\n- Exception object only destroyed if all validation checks pass\n- Frame must be properly unlinked before restoring handlers\n\nStructure Layout (EXCEPTION_RECORD - inferred from ESI accesses):\nOffset | Size | Field Name           | Type  | Description\n-------|------|---------------------|-------|---------------------------\n0x00   | 4    | ExceptionCode       | DWORD | Exception code (0xE06D7363)\n0x10   | 4    | NumberParameters    | DWORD | Parameter count (must be 3)\n0x14   | 4    | MagicNumber         | DWORD | VC++ version identifier\n0x18   | 4    | pExceptionObject    | void* | Pointer to thrown object",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:63ed7c9fbe9fe31a4d4278d4042a2e84",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "63ed7c9fbe9fe31a4d4278d4042a2e84",
        "CFG": "044e95a6511b64bf155bd4de5c12eeac",
        "PRO": "4b128b191ca49f5a0ed748b9b837d678"
      },
      "basic_block_counts": {
        "LoD/PD2": 9
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "D2gfx_MNE_544ea4e68964": {
      "addresses": {
        "LoD/PD2": "0x6FA8C2FC"
      },
      "rvas": {
        "LoD/PD2": "0xC2FC"
      },
      "sizes": {
        "LoD/PD2": 368
      },
      "name": "ConstructCatchObject",
      "signature": "void ConstructCatchObject(EHExceptionRecord * pExceptionRecord, _s_CatchableType * pCatchableInfo, _s_HandlerType * pHandlerInfo, _s_CatchableType * pCatchableType)",
      "calling_convention": "__cdecl",
      "comment": "Setting prototype: void ConstructCatchObject(EHExceptionRecord * pExceptionRecord, _s_CatchableType * pCatchableInfo, _s_HandlerType * pHandlerInfo, _s_CatchableType * pCatchableType)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:544ea4e68964a9fa10177d533eda6601",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "544ea4e68964a9fa10177d533eda6601",
        "CFG": "df167a2acbf0b60dc97c0b03976f4e64",
        "PRO": "8a35263f03694b13e28c69466677a376"
      },
      "basic_block_counts": {
        "LoD/PD2": 46
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 4
      }
    },
    "D2gfx_MNE_a2d392fa0db0": {
      "addresses": {
        "LoD/PD2": "0x6FA8C478"
      },
      "rvas": {
        "LoD/PD2": "0xC478"
      },
      "sizes": {
        "LoD/PD2": 103
      },
      "name": "CatchIt",
      "signature": "void CatchIt(EHExceptionRecord * pExceptionRecord, EHRegistrationNode * pRegistrationNode, _CONTEXT * pThreadContext, void * pThrowInfo, _s_FuncInfo * pFuncInfo, _s_HandlerType * pHandlerType, _s_CatchableType * pCatchableType, _s_TryBlockMapEntry * pTryBlockMap, int nHandlerIndex, EHRegistrationNode * pEstablisherFrame, uchar isConstructed)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n void __cdecl CatchIt(struct EHExceptionRecord *,struct EHRegistrationNode *,struct _CONTEXT *,void *,struct _s_FuncInfo const *,struct _s_HandlerType const *,struct _s_CatchableType const *,struct _s_TryBlockMapEntry const *,int,struct EHRegistrationNode *,unsigned char)\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:a2d392fa0db0696e3e245bca3260930f",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "a2d392fa0db0696e3e245bca3260930f",
        "CFG": "e2a6504b4716007302f5667f41b848a4",
        "PRO": "50267bb0643b89bb3141894233a42199"
      },
      "basic_block_counts": {
        "LoD/PD2": 8
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 11
      }
    },
    "D2gfx_MNE_47bdfc874694": {
      "addresses": {
        "LoD/PD2": "0x6FA8C4DF"
      },
      "rvas": {
        "LoD/PD2": "0xC4DF"
      },
      "sizes": {
        "LoD/PD2": 190
      },
      "name": "FindHandlerForForeignException",
      "signature": "void FindHandlerForForeignException(EHExceptionRecord * pExceptionRecord, EHRegistrationNode * pThisRegistration, _CONTEXT * pContext, void * pDispatcher, _s_FuncInfo * pFuncInfo, int nTryLow, int nTryHigh, EHRegistrationNode * pCatchFrame)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n void __cdecl FindHandlerForForeignException(struct EHExceptionRecord *,struct EHRegistrationNode *,struct _CONTEXT *,void *,struct _s_FuncInfo const *,int,int,struct EHRegistrationNode *)\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:47bdfc874694667f1fbbded06fa6a242",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "47bdfc874694667f1fbbded06fa6a242",
        "CFG": "7c82cf3a78fbc6ff1d3ea126d68e7e52",
        "PRO": "0212b8a5006d8a58c6414754ce666c77"
      },
      "basic_block_counts": {
        "LoD/PD2": 18
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 8
      }
    },
    "D2gfx_MNE_71996afe3d91": {
      "addresses": {
        "LoD/PD2": "0x6FA8C59D"
      },
      "rvas": {
        "LoD/PD2": "0xC59D"
      },
      "sizes": {
        "LoD/PD2": 516
      },
      "name": "FindCatchHandler",
      "signature": "void FindCatchHandler(EHExceptionRecord * pExceptionRecord, EHRegistrationNode * pRegistrationNode, _CONTEXT * pContext, void * pDispatcher, _s_FuncInfo * pFuncInfo, uchar isTranslated, int maxState, EHRegistrationNode * pEstablisherFrame)",
      "calling_convention": "__cdecl",
      "comment": "Searches exception handler table to find a catch block matching the thrown exception.\n\nAlgorithm:\n1. Validate exception state against function info maxState bounds\n2. Check if exception has C++ exception signature (0xe06d7363 magic)\n3. If translated exception exists, retrieve it from thread-local data\n4. Validate translated exception before processing\n5. Call _GetRangeOfTrysToCheck to get applicable try blocks for current state\n6. For each try block in valid range:\n   a. Check if exception state falls within try block bounds\n   b. Iterate through catch clauses in the try block\n   c. For each catchable type, check type compatibility via TypeMatch\n   d. Call CatchIt to execute matching handler and return\n7. If no matching handler found and not translated exception:\n   - Call FindHandlerForForeignException for non-C++ exceptions\n8. If translated exception and no match found, call ___DestructExceptionObject\n9. If no handler and isTranslated=true, call terminate()\n\nParameters:\n  pExceptionRecord: Thrown exception object with type info and payload\n  pRegistrationNode: Current exception registration/frame node\n  pContext: Machine context snapshot (registers/stack at exception point)\n  pDispatcher: Dispatcher callback context\n  pFuncInfo: Function metadata including try/catch block map\n  isTranslated: Flag indicating exception was translated/wrapped by translator\n  maxState: Current execution state (EH scope level within function)\n  pEstablisherFrame: Frame node for handler establishment\n\nReturns:\n  void (does not return normally - jumps to catch handler or terminates)\n\nSpecial Cases:\n  - Magic value 0xe06d7363 indicates native C++ exception format\n  - Magic values 0x19930520, 0x19930521 indicate Visual C++ EH version\n  - State value -1 is valid minimum state\n  - Handles translated exceptions wrapped by unexpected() handler\n  - Calls terminate() if no handler found for translated exception",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:71996afe3d91ebc0635560132615f7bc",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "71996afe3d91ebc0635560132615f7bc",
        "CFG": "e052d9f60eb1b13aa12de09005b4982f",
        "PRO": "1bc5fbf1e24040c82bc0ba9f799a94e4"
      },
      "basic_block_counts": {
        "LoD/PD2": 43
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 8
      }
    },
    "D2gfx_MNE_e75ee0306c31": {
      "addresses": {
        "LoD/PD2": "0x6FA8C7A1"
      },
      "rvas": {
        "LoD/PD2": "0xC7A1"
      },
      "sizes": {
        "LoD/PD2": 162
      },
      "name": "___InternalCxxFrameHandler",
      "signature": "undefined4 ___InternalCxxFrameHandler(EHExceptionRecord * param_1, EHRegistrationNode * param_2, _CONTEXT * param_3, void * param_4, _s_FuncInfo * param_5, int param_6, EHRegistrationNode * param_7, uchar param_8)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___InternalCxxFrameHandler\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:e75ee0306c31bdd597d86ebd787537ac",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "e75ee0306c31bdd597d86ebd787537ac",
        "CFG": "e69b5b2d2ce6c635a72554fac4fc9756",
        "PRO": "b510fadaa4446af75d5b053a40be4222"
      },
      "basic_block_counts": {
        "LoD/PD2": 14
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 8
      }
    },
    "D2gfx_MNE_048fa86b16ba": {
      "addresses": {
        "LoD/PD2": "0x6FA8C843"
      },
      "rvas": {
        "LoD/PD2": "0xC843"
      },
      "sizes": {
        "LoD/PD2": 46
      },
      "name": "terminate",
      "signature": "void terminate(void)",
      "calling_convention": "__cdecl",
      "comment": "Terminates the thread by invoking the registered terminate handler and aborting.\n\nAlgorithm:\n1. Call __getptd() to retrieve the thread-local data structure\n2. Check if terminate handler is installed (ptlocinfo != NULL at offset 0x6c)\n3. If handler exists, clear the exception state in local variable at [EBP-0x4]\n4. Call __getptd() again to get fresh thread-local data reference\n5. Invoke the terminate handler function pointer stored at [ptlocinfo + 0x6c]\n6. Jump to _abort() function to terminate the entire process\n7. _abort() never returns, ensuring process termination\n\nParameters:\n  (none): Function takes no parameters\n\nReturns:\n  Never returns: Execution always terminates via _abort() call to end process\n\nSpecial Cases:\n  - Handler function pointer is registered by std::set_terminate()\n  - If handler itself throws exception, recursive terminate is triggered\n  - Process termination is guaranteed regardless of handler outcome",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:048fa86b16ba3f4924242f25b953c745",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "048fa86b16ba3f4924242f25b953c745",
        "CFG": "6c3f0566df164baf42f457563e0b9bcf",
        "PRO": "8b59fe2265e3ebb286c66a6a0ca4b438"
      },
      "basic_block_counts": {
        "LoD/PD2": 4
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "D2gfx_MNE_abf83bbd7e60": {
      "addresses": {
        "LoD/PD2": "0x6FA8C878"
      },
      "rvas": {
        "LoD/PD2": "0xC878"
      },
      "sizes": {
        "LoD/PD2": 32
      },
      "name": "_inconsistency",
      "signature": "void _inconsistency(void)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n void __cdecl _inconsistency(void)\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:abf83bbd7e609b1bb0ad650aa99da4ac",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "abf83bbd7e609b1bb0ad650aa99da4ac",
        "CFG": "c0911ab13e8db6d703c6ff224f1b4a1f",
        "PRO": "bcc41a71659498cb2c46829019968bee"
      },
      "basic_block_counts": {
        "LoD/PD2": 3
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "D2gfx_MNE_54a4c3410932": {
      "addresses": {
        "LoD/PD2": "0x6FA8C8B0"
      },
      "rvas": {
        "LoD/PD2": "0xC8B0"
      },
      "sizes": {
        "LoD/PD2": 76
      },
      "name": "__CallSettingFrame@12",
      "signature": "undefined __CallSettingFrame@12(undefined4 param_1, undefined4 param_2, int param_3)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Single Match\n __CallSettingFrame@12\n\nLibrary: Visual Studio 2003 Release",
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
    "D2gfx_MNE_d3fefb7c954c": {
      "addresses": {
        "LoD/PD2": "0x6FA8C8FC"
      },
      "rvas": {
        "LoD/PD2": "0xC8FC"
      },
      "sizes": {
        "LoD/PD2": 78
      },
      "name": "__CxxUnhandledExceptionFilter",
      "signature": "int __CxxUnhandledExceptionFilter(int * param_1)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Single Match\n long __stdcall __CxxUnhandledExceptionFilter(struct _EXCEPTION_POINTERS *)\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:d3fefb7c954cbb3bdf620b064e1026c9",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "d3fefb7c954cbb3bdf620b064e1026c9",
        "CFG": "ac168114f9af0e2a47558c34c91a6f7b",
        "PRO": "587728b545a741f4ea6183f0a7cafa66"
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
    "D2gfx_MNE_48b089e35ec3": {
      "addresses": {
        "LoD/PD2": "0x6FA8C986"
      },
      "rvas": {
        "LoD/PD2": "0xC986"
      },
      "sizes": {
        "LoD/PD2": 28
      },
      "name": "_ValidateRead",
      "signature": "int _ValidateRead(void * param_1, uint param_2)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n int __cdecl _ValidateRead(void const *,unsigned int)\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:48b089e35ec33e654b6d909f9cdbb713",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "48b089e35ec33e654b6d909f9cdbb713",
        "CFG": "e67ee52de705150869e2ef2baa9939af",
        "PRO": "f7a895c6b36ed86cdff413f81de6f388"
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
    "D2gfx_MNE_226bd7b7660f": {
      "addresses": {
        "LoD/PD2": "0x6FA8C9A2"
      },
      "rvas": {
        "LoD/PD2": "0xC9A2"
      },
      "sizes": {
        "LoD/PD2": 24
      },
      "name": "_ValidateExecute",
      "signature": "int _ValidateExecute(_func_int * param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n int __cdecl _ValidateExecute(int (__stdcall*)(void))\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:226bd7b7660f7c129864f3453c504df2",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "226bd7b7660f7c129864f3453c504df2",
        "CFG": "35cb04bc19b2020a12670858f7d7ed27",
        "PRO": "ef1c6642ae13c92cce4949ae9292be06"
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
    "D2gfx_MNE_e65987029a33": {
      "addresses": {
        "LoD/PD2": "0x6FA8C9BA"
      },
      "rvas": {
        "LoD/PD2": "0xC9BA"
      },
      "sizes": {
        "LoD/PD2": 23
      },
      "name": "_abort",
      "signature": "void _abort(void)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n _abort\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:e65987029a330b525d706048fc12bba9",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "e65987029a330b525d706048fc12bba9",
        "CFG": null,
        "PRO": "3c75987e39b97bc2b3024d4209985471"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "D2gfx_MNE_2af2421e9adb": {
      "addresses": {
        "LoD/PD2": "0x6FA8C9D2"
      },
      "rvas": {
        "LoD/PD2": "0xC9D2"
      },
      "sizes": {
        "LoD/PD2": 46
      },
      "name": "siglookup",
      "signature": "undefined siglookup(void)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n _siglookup\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:2af2421e9adbd50e4220f87768729b8e",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "2af2421e9adbd50e4220f87768729b8e",
        "CFG": "7982cea02743e8ef27b2e318b1301c25",
        "PRO": "83e4b58e057f0a0002b98fe134d5c4c8"
      },
      "basic_block_counts": {
        "LoD/PD2": 7
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "D2gfx_MNE_9ca8b994d17a": {
      "addresses": {
        "LoD/PD2": "0x6FA8CA00"
      },
      "rvas": {
        "LoD/PD2": "0xCA00"
      },
      "sizes": {
        "LoD/PD2": 356
      },
      "name": "_raise",
      "signature": "int _raise(int _SigNum)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n _raise\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:9ca8b994d17aa0674346136517490025",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "9ca8b994d17aa0674346136517490025",
        "CFG": "e50b9784be465f73c57aef46a0af86d7",
        "PRO": "ce7f20cc8a910507d74f4a5b95a894d8"
      },
      "basic_block_counts": {
        "LoD/PD2": 39
      },
      "loop_counts": {
        "LoD/PD2": 0
      },
      "param_counts": {
        "LoD/PD2": 1
      }
    },
    "D2gfx_MNE_ced68f090488": {
      "addresses": {
        "LoD/PD2": "0x6FA8CB3B"
      },
      "rvas": {
        "LoD/PD2": "0xCB3B"
      },
      "sizes": {
        "LoD/PD2": 13
      },
      "name": "ConditionalUnlockCriticalSection",
      "signature": "void ConditionalUnlockCriticalSection(int nLockIndex)",
      "calling_convention": "__fastcall",
      "comment": "Setting prototype: void ConditionalUnlockCriticalSection(int nLockIndex)",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:ced68f09048890319abe4e844972fc66",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "ced68f09048890319abe4e844972fc66",
        "CFG": "7750d3e200f3a3c6416ddf41088bb841",
        "PRO": "3b3b4940fd9dcada562948a9b0a975b0"
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
    "D2gfx_MNE_ac5f29842510": {
      "addresses": {
        "LoD/PD2": "0x6FA8CBE0"
      },
      "rvas": {
        "LoD/PD2": "0xCBE0"
      },
      "sizes": {
        "LoD/PD2": 11
      },
      "name": "Unwind@6fa8cbc0",
      "signature": "undefined Unwind@6fa8cbc0(FrameNode * param_1)",
      "calling_convention": "__cdecl",
      "comment": "C++ exception unwinding helper that extracts the return address from the current stack frame and passes control to UnlinkFrameNode for stack frame cleanup during exception propagation.\n\nAlgorithm:\n1. Load the return address from the stack frame at [EBP + 0x4]\n2. Add 0x4 to the return address to skip the 4-byte frame node pointer\n3. Transfer control to UnlinkFrameNode for frame node unlinking and stack cleanup\n\nParameters:\n(implicit) Frame pointer in EBP pointing to the current stack frame containing return address at offset 0x4\n\nReturns:\nDoes not return; transfers control to UnlinkFrameNode which handles stack unwinding\n\nSpecial Cases:\nThis function is part of the C++ exception handling mechanism and is called when exceptions propagate through the call stack. The return address adjustment (+0x4) accounts for the frame node pointer that precedes the actual return address in the exception handling context.",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:ac5f298425102bd1e7190496a742e83e",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "ac5f298425102bd1e7190496a742e83e",
        "CFG": null,
        "PRO": "4a3fff72420ecf28e59e96413916df1d"
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
    "D2gfx_MNE_e83bd76a96c5": {
      "addresses": {
        "LoD/PD2": "0x6FA8CC00"
      },
      "rvas": {
        "LoD/PD2": "0xCC00"
      },
      "sizes": {
        "LoD/PD2": 10
      },
      "name": "Unwind@6fa8cbeb",
      "signature": "undefined Unwind@6fa8cbeb(void)",
      "calling_convention": "__stdcall",
      "comment": "Wrapper function to remove a list entry from a doubly-linked list.\n\nAlgorithm:\n1. Load list entry pointer from parameter (EBP+4)\n2. Call RemoveListEntry to unlink the entry from the list\n3. Return to caller\n\nParameters:\n[EBP+4] - Pointer to LIST_ENTRY structure to be removed from the list\n\nReturns:\nvoid - No return value\n\nSpecial Cases:\nThis function acts as a simple forwarding wrapper, commonly used in function pointer tables or callbacks where list manipulation is needed. The implicit EBP parameter pattern suggests this may be used as a callback or indirect function reference.",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:e83bd76a96c575481d28f5927cfaf30f",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "e83bd76a96c575481d28f5927cfaf30f",
        "CFG": null,
        "PRO": "a2494c1dcd34b084a48ac917bbd658c0"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "D2gfx_MNE_ed28c98bc7b7": {
      "addresses": {
        "LoD/PD2": "0x6FA8CC20"
      },
      "rvas": {
        "LoD/PD2": "0xCC20"
      },
      "sizes": {
        "LoD/PD2": 22
      },
      "name": "RegisterStaticListInitialization",
      "signature": "void RegisterStaticListInitialization(void)",
      "calling_convention": "__stdcall",
      "comment": "Register static list initialization and cleanup handler.\n\nAlgorithm:\n1. Call initialization function FUN_6fa81070 with static data structure address 0x6fa9d678\n2. Register InitializeStaticDataStructure as exit handler via _atexit for cleanup\n3. Return to caller\n\nParameters:\n  None - function takes no parameters\n\nReturns:\n  void - no return value\n\nSpecial Cases:\n  - Static data structure at 0x6fa9d678 is a linked list or similar structure\n  - The structure is initialized once during program startup\n  - Exit handler ensures proper cleanup when program terminates\n  - Uses __stdcall calling convention",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:ed28c98bc7b79f45de01cb2d7f8acda6",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "ed28c98bc7b79f45de01cb2d7f8acda6",
        "CFG": null,
        "PRO": "358408013ddfb4e5b383ffb6e4656fec"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    },
    "D2gfx_MNE_a0296f3d619f": {
      "addresses": {
        "LoD/PD2": "0x6FA8CC40"
      },
      "rvas": {
        "LoD/PD2": "0xCC40"
      },
      "sizes": {
        "LoD/PD2": 11
      },
      "name": "InitializeStaticDataStructure",
      "signature": "void InitializeStaticDataStructure(void)",
      "calling_convention": "__stdcall",
      "comment": "Initialize static data structure at 0x6fa9d678.\n\nAlgorithm:\n1. Push address of static data structure (0x6fa9d678) onto stack\n2. Call initialization function FUN_6fa81030 to set up the structure\n3. Return to caller\n\nParameters:\n  None - function takes no parameters\n\nReturns:\n  void - no return value\n\nSpecial Cases:\n  - Uses __stdcall calling convention\n  - Static data structure at 0x6fa9d678 is shared by multiple functions\n  - Referenced by functions at 0x6fa879fa, 0x6fa87c5c, 0x6fa8cc20",
      "name_source": "LoD/PD2",
      "method": "MNE",
      "index": "MNE:a0296f3d619ffd4307ef69ba5693f78e",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "a0296f3d619ffd4307ef69ba5693f78e",
        "CFG": null,
        "PRO": "b650814bda968cd043d06ee526f36455"
      },
      "basic_block_counts": {
        "LoD/PD2": 1
      },
      "loop_counts": {
        "LoD/PD2": 0
      }
    }
  }
};

if (typeof FUNCTION_DATA === 'undefined') FUNCTION_DATA = {};
FUNCTION_DATA['D2gfx.dll'] = FUNCTIONS_D2gfx_dll;
