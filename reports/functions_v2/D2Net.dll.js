// Auto-generated from function_registry_v2.json
// Generated: 2025-12-13T00:30:31.404426
// Functions for D2Net.dll
// Versions: LoD/1.07, LoD/1.08, LoD/1.09, LoD/1.09b, LoD/1.09d, LoD/1.10, LoD/1.11, LoD/1.11b, LoD/1.12a, LoD/1.13c, LoD/1.13d

var FUNCTIONS_D2Net_dll = {
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
    "d2net.dll_NET_GetLastNetworkResult": {
      "addresses": {
        "LoD/1.07": "0x6FC31000",
        "LoD/1.08": "0x6FC31000",
        "LoD/1.09": "0x6FC01000",
        "LoD/1.09b": "0x6FC01000",
        "LoD/1.09d": "0x6FC01000",
        "LoD/1.10": "0x6FC01000"
      },
      "rvas": {
        "LoD/1.07": "0x1000",
        "LoD/1.08": "0x1000",
        "LoD/1.09": "0x1000",
        "LoD/1.09b": "0x1000",
        "LoD/1.09d": "0x1000",
        "LoD/1.10": "0x1000"
      },
      "sizes": {
        "LoD/1.07": 64,
        "LoD/1.08": 64,
        "LoD/1.09": 64,
        "LoD/1.09b": 64,
        "LoD/1.09d": 64,
        "LoD/1.10": 64
      },
      "name": "NET_GetLastNetworkResult",
      "signature": "uint NET_GetLastNetworkResult(void)",
      "calling_convention": "__stdcall",
      "comment": "Retrieves the last network operation result from the D2Net module.\n\nAlgorithm:\n1. Check if network state is active (state 1 or 2) via NET_IsNetworkStateActive\n2. If active, return 1 immediately (network busy/in progress)\n3. If not active, check if network pool is allocated (g_pNetworkPool != NULL)\n4. If pool not allocated, return 0 (network not initialized)\n5. If pool allocated, enter critical section with timeout 0x51\n6. Read cached result from g_dwLastNetworkResult\n7. Leave critical section via LeaveCriticalSection\n8. Return the cached result value\n\nParameters:\n  None\n\nReturns:\n  uint - Network result status:\n    0 = Network not initialized (pool not allocated)\n    1 = Network active (state 1 or 2)\n    Other = Cached result from last network operation\n\nSpecial Cases:\n  - Early return with 1 if network state active (avoids lock acquisition)\n  - Early return with 0 if network pool not allocated\n  - Thread-safe access to g_dwLastNetworkResult via critical section\n\nGlobals Accessed:\n  g_dwNetworkState (0x6fc3b22c) - Network state flag (1=active, 2=active)\n  g_pNetworkPool (0x6fc3b07c) - Pointer to network memory pool\n  g_NetCriticalSection (0x6fc3b048) - Critical section for thread safety\n  g_dwLastNetworkResult (0x6fc3b228) - Cached last network result",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:7b9b5e23e922978d27005b0c9d147eb0",
      "callees": {
        "LoD/1.07": [
          "EnterCriticalSectionWrapper"
        ],
        "LoD/1.08": [
          "LeaveCriticalSectionValidated"
        ],
        "LoD/1.09": [
          "LeaveCriticalSectionValidated"
        ],
        "LoD/1.09b": [
          "LeaveCriticalSectionValidated"
        ],
        "LoD/1.09d": [
          "LeaveCriticalSectionValidated"
        ],
        "LoD/1.10": [
          "LeaveCriticalSectionValidated"
        ]
      },
      "basic_block_counts": {
        "LoD/1.07": 5,
        "LoD/1.08": 5,
        "LoD/1.09": 5,
        "LoD/1.09b": 5,
        "LoD/1.09d": 5,
        "LoD/1.10": 5
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "7b9b5e23e922978d27005b0c9d147eb0",
        "LoD/1.08": "7b9b5e23e922978d27005b0c9d147eb0",
        "LoD/1.09": "7b9b5e23e922978d27005b0c9d147eb0",
        "LoD/1.09b": "7b9b5e23e922978d27005b0c9d147eb0",
        "LoD/1.09d": "7b9b5e23e922978d27005b0c9d147eb0",
        "LoD/1.10": "7b9b5e23e922978d27005b0c9d147eb0"
      }
    },
    "d2net.dll_STR_cce16f5f5018": {
      "addresses": {
        "LoD/1.07": "0x6FC31040",
        "LoD/1.08": "0x6FC31040",
        "LoD/1.09": "0x6FC01040",
        "LoD/1.09b": "0x6FC01040",
        "LoD/1.09d": "0x6FC01040",
        "LoD/1.10": "0x6FC01040"
      },
      "rvas": {
        "LoD/1.07": "0x1040",
        "LoD/1.08": "0x1040",
        "LoD/1.09": "0x1040",
        "LoD/1.09b": "0x1040",
        "LoD/1.09d": "0x1040",
        "LoD/1.10": "0x1040"
      },
      "sizes": {
        "LoD/1.07": 224,
        "LoD/1.08": 224,
        "LoD/1.09": 224,
        "LoD/1.09b": 224,
        "LoD/1.09d": 224,
        "LoD/1.10": 224
      },
      "name_source": "LoD/1.07",
      "method": "STR",
      "index": "STR:cce16f5f50185d176952abf0b35dda0b",
      "callees": {
        "LoD/1.07": [
          "FogFatalError",
          "FogFatalError",
          "ResolveHostnameToIP"
        ],
        "LoD/1.08": [
          "FogFatalError",
          "FogFatalError",
          "ResolveHostnameToIP"
        ],
        "LoD/1.09": [
          "FogFatalError",
          "FogFatalError",
          "ResolveHostnameToIP"
        ],
        "LoD/1.09b": [
          "FogFatalError",
          "FogFatalError",
          "ResolveHostnameToIP"
        ],
        "LoD/1.09d": [
          "FogFatalError",
          "FogFatalError",
          "ResolveHostnameToIP"
        ],
        "LoD/1.10": [
          "FogFatalError",
          "FogFatalError",
          "Ordinal_10015"
        ]
      },
      "strings": {
        "LoD/1.07": [
          "\"WSAStartup\"",
          "\"Socket\"",
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2Net\\\\SRC\\\\Client..."
        ],
        "LoD/1.08": [
          "\"WSAStartup\"",
          "\"Socket\"",
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2Net\\\\SRC\\\\Client..."
        ],
        "LoD/1.09": [
          "\"WSAStartup\"",
          "\"Socket\"",
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2Net\\\\SRC\\\\Client..."
        ],
        "LoD/1.09b": [
          "\"WSAStartup\"",
          "\"Socket\"",
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2Net\\\\SRC\\\\Client..."
        ],
        "LoD/1.09d": [
          "\"WSAStartup\"",
          "\"Socket\"",
          "\"C:\\\\Src\\\\Diablo2\\\\Source\\\\D2Net\\\\SRC\\\\Client.cpp\""
        ],
        "LoD/1.10": [
          "\"WSAStartup\"",
          "\"Socket\"",
          "\"C:\\\\projects\\\\D2\\\\head\\\\Diablo2\\\\Source\\\\D2Net\\\\S..."
        ]
      },
      "basic_block_counts": {
        "LoD/1.07": 7,
        "LoD/1.08": 7,
        "LoD/1.09": 7,
        "LoD/1.09b": 7,
        "LoD/1.09d": 7,
        "LoD/1.10": 7
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "a0f58da4648d145161afbc4048f0da64",
        "LoD/1.08": "a0f58da4648d145161afbc4048f0da64",
        "LoD/1.09": "a0f58da4648d145161afbc4048f0da64",
        "LoD/1.09b": "a0f58da4648d145161afbc4048f0da64",
        "LoD/1.09d": "a0f58da4648d145161afbc4048f0da64",
        "LoD/1.10": "55f20ca374a986e5a5a3490b4839eb2d"
      }
    },
    "d2net.dll_NET_StartClientReceiveThread": {
      "addresses": {
        "LoD/1.07": "0x6FC31120",
        "LoD/1.08": "0x6FC31120",
        "LoD/1.09": "0x6FC01120",
        "LoD/1.09b": "0x6FC01120",
        "LoD/1.09d": "0x6FC01120",
        "LoD/1.10": "0x6FC01120"
      },
      "rvas": {
        "LoD/1.07": "0x1120",
        "LoD/1.08": "0x1120",
        "LoD/1.09": "0x1120",
        "LoD/1.09b": "0x1120",
        "LoD/1.09d": "0x1120",
        "LoD/1.10": "0x1120"
      },
      "sizes": {
        "LoD/1.07": 140,
        "LoD/1.08": 140,
        "LoD/1.09": 140,
        "LoD/1.09b": 140,
        "LoD/1.09d": 140,
        "LoD/1.10": 140
      },
      "name": "NET_StartClientReceiveThread",
      "signature": "int NET_StartClientReceiveThread(void)",
      "calling_convention": "__stdcall",
      "comment": "Starts the client network receive thread for processing incoming data.\n\nClassification: Initialization/Public API (Ordinal Export 10025)\n\nAlgorithm:\n1. Check if network subsystem is shutting down via NET_IsShuttingDown()\n2. If shutting down, return 2 (already active/shutting down)\n3. Wait on g_hClientSyncEvent with 100ms timeout\n4. If wait times out (result != 0), return 1 (timeout)\n5. If g_hClientSocket is NULL, return 0 (no connection)\n6. Check shutdown state again\n7. If not shutting down, enter critical section and set g_dwClientConnectionState = 1\n8. Leave critical section\n9. Create client receive thread (NET_ClientReceiveThreadProc) with above-normal priority\n10. Store thread handle in g_hClientReceiveThread, thread ID in g_dwClientReceiveThreadId\n11. Return 2 (thread started successfully)\n\nParameters:\n  None (void)\n\nReturns:\n  0 - No client socket connection exists\n  1 - Wait timed out (sync event not signaled within 100ms)\n  2 - Thread started successfully OR already shutting down\n\nGlobals Accessed:\n  g_hClientSyncEvent (0x6fc3b088) - Event handle for client synchronization\n  g_hClientSocket (0x6fc3b084) - Client socket handle (SOCKET)\n  g_ClientCriticalSection (0x6fc3b048) - Critical section protecting connection state\n  g_dwClientConnectionState (0x6fc3b228) - Connection state flag (1=active)\n  g_hClientReceiveThread (0x6fc3b080) - Handle to receive thread\n  g_dwClientReceiveThreadId (0x6fc3b220) - Thread ID of receive thread\n\nThread Safety:\n  Uses critical section to protect state changes. Thread created with THREAD_PRIORITY_ABOVE_NORMAL.\n\nDecompiler Note:\n  extraout_var/extraout_var_00 are artifacts from decompiler handling of bool return in EAX.\n  CONCAT31 tests full EAX register but only low byte (AL) contains actual bool value.",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:542ebb86c3312e77268ab0aa00198146",
      "callees": {
        "LoD/1.07": [
          "EnterCriticalSectionWrapper"
        ],
        "LoD/1.08": [
          "LeaveCriticalSectionValidated"
        ],
        "LoD/1.09": [
          "LeaveCriticalSectionValidated"
        ],
        "LoD/1.09b": [
          "LeaveCriticalSectionValidated"
        ],
        "LoD/1.09d": [
          "LeaveCriticalSectionValidated"
        ],
        "LoD/1.10": [
          "LeaveCriticalSectionValidated"
        ]
      },
      "basic_block_counts": {
        "LoD/1.07": 9,
        "LoD/1.08": 9,
        "LoD/1.09": 9,
        "LoD/1.09b": 9,
        "LoD/1.09d": 9,
        "LoD/1.10": 9
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "542ebb86c3312e77268ab0aa00198146",
        "LoD/1.08": "542ebb86c3312e77268ab0aa00198146",
        "LoD/1.09": "542ebb86c3312e77268ab0aa00198146",
        "LoD/1.09b": "542ebb86c3312e77268ab0aa00198146",
        "LoD/1.09d": "542ebb86c3312e77268ab0aa00198146",
        "LoD/1.10": "542ebb86c3312e77268ab0aa00198146"
      }
    },
    "d2net.dll_D2Net_InitializeClient": {
      "addresses": {
        "LoD/1.07": "0x6FC311B0",
        "LoD/1.08": "0x6FC311B0",
        "LoD/1.09": "0x6FC011B0",
        "LoD/1.09b": "0x6FC011B0",
        "LoD/1.09d": "0x6FC011B0",
        "LoD/1.10": "0x6FC011B0"
      },
      "rvas": {
        "LoD/1.07": "0x11B0",
        "LoD/1.08": "0x11B0",
        "LoD/1.09": "0x11B0",
        "LoD/1.09b": "0x11B0",
        "LoD/1.09d": "0x11B0",
        "LoD/1.10": "0x11B0"
      },
      "sizes": {
        "LoD/1.07": 138,
        "LoD/1.08": 138,
        "LoD/1.09": 138,
        "LoD/1.09b": 138,
        "LoD/1.09d": 138,
        "LoD/1.10": 138
      },
      "name": "D2Net_InitializeClient",
      "signature": "HANDLE D2Net_InitializeClient(dword dwNetworkType, void * pThreadParam)",
      "calling_convention": "__stdcall",
      "comment": "D2Net Client Initialization (Ordinal 10000)\n\nInitializes the D2Net client subsystem by allocating the client buffer,\ninitializing synchronization primitives, and creating the client thread.\nThis is the primary entry point for client-side network initialization.\n\nClassification: Public API / Initialization\n\nAlgorithm:\n1. Reset packet counters (sent/received) to zero\n2. Initialize critical section for client synchronization (g_csClientLock)\n3. Allocate client buffer (0x7BC = 1980 bytes) via FogMemAlloc\n4. Zero-initialize the buffer (495 DWORDs = 1980 bytes) using REP STOSD\n5. Store network type parameter in global (g_dwNetworkType)\n6. Check if running in server mode (types 1 or 2)\n7. If server mode: call D2Net_NotifyServerMode and return success (0x1)\n8. If client mode: create client thread at LAB_6fc31040 with pThreadParam\n\nParameters:\n  dwNetworkType (dword) - Network operation type:\n    0 = Client mode (creates thread)\n    1 = Server mode type 1 (skip thread creation)\n    2 = Server mode type 2 (skip thread creation)\n  pThreadParam (void *) - Opaque parameter passed to client thread function.\n    Note: void* is intentional as this is a LPVOID passed to CreateThread.\n    The thread function interprets this context-specifically.\n\nReturns:\n  HANDLE - Thread handle on success (client mode), stored in g_hClientThread\n  0x1 - Success indicator (server mode)\n\nDecompiler Temporaries (SSA artifacts):\n  fIsServerMode - Boolean return from D2Net_IsServerMode()\n  nLoopCounter - Loop counter (0x1EF iterations) for buffer zeroing\n  pdwBufferPtr - Buffer pointer incremented during REP STOSD\n  wExtraOutCX, bExtraOutVar - Register extraout artifacts from calling convention\n\nGlobals Modified:\n  g_dwClientPacketsSent (0x6fc3b078) - Reset to 0\n  g_dwClientPacketsRecv (0x6fc3b060) - Reset to 0\n  g_csClientLock (0x6fc3b048) - Initialized critical section\n  g_pClientBuffer (0x6fc3b07c) - Allocated buffer pointer (1980 bytes)\n  g_dwNetworkType (0x6fc3b22c) - Stored network type\n  g_hClientThread (0x6fc3b088) - Created thread handle (client mode only)\n  g_dwClientThreadId (0x6fc3b220) - Thread ID from CreateThread\n\nCallees:\n  InitializeCriticalSection - Win32 API to init g_csClientLock\n  FogMemAlloc - Fog memory allocation with source tracking\n  D2Net_SetNetworkType - Store network type in global\n  D2Net_IsServerMode - Check if type is 1 or 2 (server mode)\n  D2Net_NotifyServerMode - Send server mode notification (Ordinal_10006)\n  CreateThread - Create client thread at LAB_6fc31040\n\nMemory:\n  Allocates 1980 bytes (0x7BC) for client buffer via FogMemAlloc\n  Caller responsible for cleanup via D2Net shutdown functions\n\nMagic Numbers:\n  0x7BC (1980) - Client buffer size in bytes\n  0x1EF (495) - Number of DWORDs to zero (495 x 4 = 1980)\n  0xC2 (194) - Source file line number for FogMemAlloc tracking\n  0x6fc38044 - String ptr: \"C:\\Projects\\Diablo2\\Source\\D2Net\\SRC\\Client.cpp\"",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:68e6a6a5446061e2535587f74735b3d1",
      "callees": {
        "LoD/1.07": [
          "FogMemAlloc"
        ],
        "LoD/1.08": [
          "FogMemAlloc"
        ],
        "LoD/1.09": [
          "FogMemAlloc"
        ],
        "LoD/1.09b": [
          "FogMemAlloc"
        ],
        "LoD/1.09d": [
          "FogMemAlloc"
        ],
        "LoD/1.10": [
          "FogMemAlloc"
        ]
      },
      "strings": {
        "LoD/1.07": [
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2Net\\\\SRC\\\\Client..."
        ],
        "LoD/1.08": [
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2Net\\\\SRC\\\\Client..."
        ],
        "LoD/1.09": [
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2Net\\\\SRC\\\\Client..."
        ],
        "LoD/1.09b": [
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2Net\\\\SRC\\\\Client..."
        ],
        "LoD/1.09d": [
          "\"C:\\\\Src\\\\Diablo2\\\\Source\\\\D2Net\\\\SRC\\\\Client.cpp\""
        ],
        "LoD/1.10": [
          "\"C:\\\\projects\\\\D2\\\\head\\\\Diablo2\\\\Source\\\\D2Net\\\\S..."
        ]
      },
      "basic_block_counts": {
        "LoD/1.07": 3,
        "LoD/1.08": 3,
        "LoD/1.09": 3,
        "LoD/1.09b": 3,
        "LoD/1.09d": 3,
        "LoD/1.10": 3
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "68e6a6a5446061e2535587f74735b3d1",
        "LoD/1.08": "68e6a6a5446061e2535587f74735b3d1",
        "LoD/1.09": "68e6a6a5446061e2535587f74735b3d1",
        "LoD/1.09b": "68e6a6a5446061e2535587f74735b3d1",
        "LoD/1.09d": "68e6a6a5446061e2535587f74735b3d1",
        "LoD/1.10": "68e6a6a5446061e2535587f74735b3d1"
      }
    },
    "d2net.dll_NET_Shutdown": {
      "addresses": {
        "LoD/1.07": "0x6FC31240",
        "LoD/1.08": "0x6FC31240",
        "LoD/1.09": "0x6FC01240",
        "LoD/1.09b": "0x6FC01240",
        "LoD/1.09d": "0x6FC01240",
        "LoD/1.10": "0x6FC01240"
      },
      "rvas": {
        "LoD/1.07": "0x1240",
        "LoD/1.08": "0x1240",
        "LoD/1.09": "0x1240",
        "LoD/1.09b": "0x1240",
        "LoD/1.09d": "0x1240",
        "LoD/1.10": "0x1240"
      },
      "sizes": {
        "LoD/1.07": 188,
        "LoD/1.08": 188,
        "LoD/1.09": 188,
        "LoD/1.09b": 188,
        "LoD/1.09d": 188,
        "LoD/1.10": 188
      },
      "name": "NET_Shutdown",
      "signature": "void NET_Shutdown(void)",
      "calling_convention": "__stdcall",
      "comment": "Shuts down the network subsystem and releases all network resources.\n\nAlgorithm:\n1. Enter critical section g_NetCriticalSection\n2. If g_pNetPoolAllocation is non-null, release the pool allocation\n3. Set g_pNetPoolAllocation to 0 (cleared)\n4. Set g_dwNetShutdownFlag to 1 (signal shutdown in progress)\n5. Leave critical section\n6. Wait on g_hNetShutdownEvent with 6000ms (6 second) timeout\n7. Drain send queue by calling FUN_6fc31b00 with g_pNetSendQueue\n8. Drain receive queue by calling FUN_6fc31b00 with g_pNetRecvQueue\n9. Re-enter critical section and delete it\n10. Check shutdown state via FUN_6fc31a20\n11. If not in final shutdown state:\n    a. Close g_NetSocket\n    b. Set g_NetSocket to 0\n    c. If closesocket returns -1 (SOCKET_ERROR), call WSAGetLastError\n\nParameters: None (void function)\n\nReturns: void\n\nSpecial Cases:\n- Waits up to 6 seconds for pending network operations to complete\n- Socket only closed if FUN_6fc31a20 returns false (not in shutdown state 1 or 2)\n- WSAGetLastError called only on socket close failure\n\nSSA Temporaries (decompiler-generated, not renameable):\n- bVar1: Return value from FUN_6fc31a20 (bool - shutdown state check)\n- extraout_var: Upper bytes of EAX from closesocket return value\n- extraout_EAX: Full EAX register after closesocket call\n\nGlobal State Modified:\n- g_pNetPoolAllocation: Set to 0\n- g_dwNetShutdownFlag: Set to 1\n- g_NetSocket: Set to 0 (if closed)\n- g_NetCriticalSection: Deleted\n- g_pNetSendQueue: Drained via FUN_6fc31b00\n- g_pNetRecvQueue: Drained via FUN_6fc31b00",
      "name_source": "LoD/1.07",
      "method": "API",
      "index": "API:d086a0f05a96ad379907ba95d1da93a1",
      "callees": {
        "LoD/1.07": [
          "EnterCriticalSectionWrapper",
          "ReleasePoolAllocation",
          "EnterCriticalSectionWrapper",
          "closesocket"
        ],
        "LoD/1.08": [
          "LeaveCriticalSectionValidated",
          "ReleasePoolAllocation",
          "LeaveCriticalSectionValidated",
          "DeleteFile"
        ],
        "LoD/1.09": [
          "LeaveCriticalSectionValidated",
          "ReleasePoolAllocation",
          "LeaveCriticalSectionValidated",
          "DeleteFile"
        ],
        "LoD/1.09b": [
          "LeaveCriticalSectionValidated",
          "ReleasePoolAllocation",
          "LeaveCriticalSectionValidated",
          "DeleteFile"
        ],
        "LoD/1.09d": [
          "LeaveCriticalSectionValidated",
          "ReleasePoolAllocation",
          "LeaveCriticalSectionValidated",
          "DeleteFile"
        ],
        "LoD/1.10": [
          "LeaveCriticalSectionValidated",
          "ReleasePoolAllocation",
          "LeaveCriticalSectionValidated",
          "DeleteFile"
        ]
      },
      "strings": {
        "LoD/1.07": [
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2Net\\\\SRC\\\\Client..."
        ],
        "LoD/1.08": [
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2Net\\\\SRC\\\\Client..."
        ],
        "LoD/1.09": [
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2Net\\\\SRC\\\\Client..."
        ],
        "LoD/1.09b": [
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2Net\\\\SRC\\\\Client..."
        ],
        "LoD/1.09d": [
          "\"C:\\\\Src\\\\Diablo2\\\\Source\\\\D2Net\\\\SRC\\\\Client.cpp\""
        ],
        "LoD/1.10": [
          "\"C:\\\\projects\\\\D2\\\\head\\\\Diablo2\\\\Source\\\\D2Net\\\\S..."
        ]
      },
      "basic_block_counts": {
        "LoD/1.07": 6,
        "LoD/1.08": 6,
        "LoD/1.09": 6,
        "LoD/1.09b": 6,
        "LoD/1.09d": 6,
        "LoD/1.10": 6
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "e730831e281586459f8f0b106ab6b013",
        "LoD/1.08": "e730831e281586459f8f0b106ab6b013",
        "LoD/1.09": "e730831e281586459f8f0b106ab6b013",
        "LoD/1.09b": "e730831e281586459f8f0b106ab6b013",
        "LoD/1.09d": "e730831e281586459f8f0b106ab6b013",
        "LoD/1.10": "e730831e281586459f8f0b106ab6b013"
      }
    },
    "d2net.dll_NET_ReceivePacket": {
      "addresses": {
        "LoD/1.07": "0x6FC31300",
        "LoD/1.08": "0x6FC31300",
        "LoD/1.09": "0x6FC01300",
        "LoD/1.09b": "0x6FC01300",
        "LoD/1.09d": "0x6FC01300"
      },
      "rvas": {
        "LoD/1.07": "0x1300",
        "LoD/1.08": "0x1300",
        "LoD/1.09": "0x1300",
        "LoD/1.09b": "0x1300",
        "LoD/1.09d": "0x1300"
      },
      "sizes": {
        "LoD/1.07": 28,
        "LoD/1.08": 28,
        "LoD/1.09": 28,
        "LoD/1.09b": 28,
        "LoD/1.09d": 28
      },
      "name": "NET_ReceivePacket",
      "signature": "uint NET_ReceivePacket(void * pBuffer, uint dwBufferSize)",
      "calling_convention": "__stdcall",
      "comment": "Receives a packet from the network receive queue.\n\nExported as D2Net Ordinal 10007. Thread-safe wrapper that dequeues the next\navailable packet from g_pNetRecvQueue into the caller's buffer.\n\nAlgorithm:\n1. Load pBuffer and dwBufferSize from stack parameters\n2. Load g_pNetRecvQueue pointer into EDX (queue head pointer)\n3. Load g_NetCriticalSection address into ECX (synchronization object)\n4. Call internal queue dequeue function to copy packet data\n5. Return packet type identifier or 0xFFFFFFFF on failure/empty\n\nParameters:\n  pBuffer      - void* - Output buffer to receive packet data (max 0x204 bytes copied)\n  dwBufferSize - uint  - Size of output buffer in bytes\n\nReturns:\n  uint - Packet type identifier from queue entry on success\n         0xFFFFFFFF (-1) if queue is empty or throttled (network type 2, <500ms since last)\n\nSpecial Cases:\n  - If dwBufferSize > 0x203, only 0x204 bytes are copied (internal limit)\n  - Network type 2: 500ms throttle between receives from same queue entry\n  - Critical section protects queue access for thread safety\n\nCalled By:\n  - Entry Point (exported ordinal)\n  - Function table at 0x6fc37d94",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:a99b640f62a9c3b9185735dd35c2b2f9",
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "a99b640f62a9c3b9185735dd35c2b2f9",
        "LoD/1.08": "a99b640f62a9c3b9185735dd35c2b2f9",
        "LoD/1.09": "a99b640f62a9c3b9185735dd35c2b2f9",
        "LoD/1.09b": "a99b640f62a9c3b9185735dd35c2b2f9",
        "LoD/1.09d": "a99b640f62a9c3b9185735dd35c2b2f9"
      }
    },
    "d2net.dll_NET_ReceiveClientPacket": {
      "addresses": {
        "LoD/1.07": "0x6FC31320",
        "LoD/1.08": "0x6FC31320",
        "LoD/1.09": "0x6FC01320",
        "LoD/1.09b": "0x6FC01320",
        "LoD/1.09d": "0x6FC01320"
      },
      "rvas": {
        "LoD/1.07": "0x1320",
        "LoD/1.08": "0x1320",
        "LoD/1.09": "0x1320",
        "LoD/1.09b": "0x1320",
        "LoD/1.09d": "0x1320"
      },
      "sizes": {
        "LoD/1.07": 28,
        "LoD/1.08": 28,
        "LoD/1.09": 28,
        "LoD/1.09b": 28,
        "LoD/1.09d": 28
      },
      "name": "NET_ReceiveClientPacket",
      "signature": "dword NET_ReceiveClientPacket(dword * pOutputBuffer, dword dwBufferSize)",
      "calling_convention": "__stdcall",
      "comment": "Dequeues a network packet from the client receive queue.\n\nClassification: Thunk/Wrapper - passes fixed globals to internal queue dequeue function\n\nAlgorithm:\n1. Load buffer pointer and size from stack parameters\n2. Set EDX = g_pNetSendQueue (packet queue head pointer)\n3. Set ECX = g_pCritSecClient (critical section for thread safety)\n4. Call FUN_6fc31a50 to dequeue packet with critical section protection\n5. Return packet type/size or 0xFFFFFFFF on failure\n\nParameters:\n  pOutputBuffer - Output buffer to receive dequeued packet data (max 0x204 bytes)\n  dwBufferSize  - Size of output buffer in bytes\n\nReturns:\n  On success: Packet type identifier from queue entry offset 0x204\n  On failure: 0xFFFFFFFF if queue empty or timing constraint not met\n\nSpecial Cases:\n- If g_dwNetworkType == 2, packet must be at least 500ms old (GetTickCount check)\n- Buffer size clamped to 0x204 (516) bytes maximum\n- Uses critical section g_pCritSecClient for thread-safe queue access\n\nRelated Functions:\n- Ordinal_10005: Send packet to server (NET_SendClientPacket)\n- FUN_6fc31a50: Internal queue dequeue with copy and critical section\n- D2Net_InitializeClient: Initializes queue and critical section",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:a99b640f62a9c3b9185735dd35c2b2f9",
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "a99b640f62a9c3b9185735dd35c2b2f9",
        "LoD/1.08": "a99b640f62a9c3b9185735dd35c2b2f9",
        "LoD/1.09": "a99b640f62a9c3b9185735dd35c2b2f9",
        "LoD/1.09b": "a99b640f62a9c3b9185735dd35c2b2f9",
        "LoD/1.09d": "a99b640f62a9c3b9185735dd35c2b2f9"
      }
    },
    "d2net.dll_NET_ClientReceiveThreadProc": {
      "addresses": {
        "LoD/1.07": "0x6FC31340",
        "LoD/1.08": "0x6FC31340",
        "LoD/1.09": "0x6FC01340",
        "LoD/1.09b": "0x6FC01340",
        "LoD/1.09d": "0x6FC01340",
        "LoD/1.10": "0x6FC01320",
        "LoD/1.11": "0x6FBF7220",
        "LoD/1.11b": "0x6FBF6C80",
        "LoD/1.12a": "0x6FBF6BD0",
        "LoD/1.13c": "0x6FBF7290",
        "LoD/1.13d": "0x6FBF6B60"
      },
      "rvas": {
        "LoD/1.07": "0x1340",
        "LoD/1.08": "0x1340",
        "LoD/1.09": "0x1340",
        "LoD/1.09b": "0x1340",
        "LoD/1.09d": "0x1340",
        "LoD/1.10": "0x1320",
        "LoD/1.11": "0x7220",
        "LoD/1.11b": "0x6C80",
        "LoD/1.12a": "0x6BD0",
        "LoD/1.13c": "0x7290",
        "LoD/1.13d": "0x6B60"
      },
      "sizes": {
        "LoD/1.07": 672,
        "LoD/1.08": 672,
        "LoD/1.09": 672,
        "LoD/1.09b": 672,
        "LoD/1.09d": 672,
        "LoD/1.10": 672,
        "LoD/1.11": 682,
        "LoD/1.11b": 682,
        "LoD/1.12a": 682,
        "LoD/1.13c": 682,
        "LoD/1.13d": 682
      },
      "name": "NET_ClientReceiveThreadProc",
      "signature": "void NET_ClientReceiveThreadProc(void)",
      "calling_convention": "__stdcall",
      "comment": "Client network receive thread procedure - handles incoming data from server.\n\nClassification: Callback/Handler - Thread procedure spawned by NET_StartClientReceiveThread\n\nAlgorithm:\n1. Initialize buffer position (uVar5=0) and processing state (uStack_ad0=0)\n2. Check g_dwNetShutdownFlag; if set, exit thread with debug message\n3. Main loop: Poll g_hClientSocket using select() with 100ms timeout\n4. If select() returns 0 (timeout), continue polling loop\n5. If select() returns -1 (error), call WSAGetLastError() and check shutdown state\n6. If not shutting down on error, set g_dwClientConnectionState=0 (disconnected)\n7. If select() returns positive, call func_0x6fc365e4 to verify socket in fd_set\n8. If socket not ready or shutdown flag set, output debug and ExitThread(0)\n9. Enter critical section for thread-safe buffer access\n10. If uStack_ad0==0 (normal mode): recv() into g_pNetPoolAllocation at offset 0x7b8\n11. On successful recv, increment pool write offset and call NET_ProcessReceivedPackets\n12. If uStack_ad0!=0 (overflow mode): recv() into local abStack_9c0 buffer\n13. Parse variable-length packets: first byte < 0xF0 = 1-byte length, >= 0xF0 = 2-byte length\n14. For 2-byte length: length = (byte[0] & 0x0F) * 256 + byte[1]\n15. Process each complete packet via func_0x6fc325d4, update pool offset\n16. If partial packet remains, memmove to buffer start via NET_MemmoveBuffer\n17. Leave critical section after processing\n18. If recv() returns -1 (error) or 0 (disconnect), set connection state and ExitThread\n\nParameters: None (thread procedure)\n\nReturns: void (exits via ExitThread, never returns normally)\n\nPacket Length Encoding:\n- Byte 0 < 0xF0 (240): Single-byte length, packet size = byte[0]\n- Byte 0 >= 0xF0: Two-byte length, packet size = (byte[0] & 0x0F) * 256 + byte[1]\n- Header size: 1 byte for short packets, 2 bytes for long packets\n- Max recv size: 0x5B4 (1460 bytes - standard MTU minus headers)\n\nGlobals Accessed:\n- g_dwNetShutdownFlag: Shutdown signal flag\n- g_hClientSocket: Client socket handle (SOCKET)\n- g_dwClientConnectionState: Connection state (0=disconnected)\n- g_NetCriticalSection: Thread synchronization object\n- g_pNetPoolAllocation: Network buffer pool pointer\n- g_pNetPoolAllocation+0x7b8: Current write offset in buffer pool\n\nDebug Strings:\n- szClientClose2: Normal shutdown exit\n- szClientClose3: Shutdown during socket ready check\n- szClientClose5: Socket error exit\n- szClientClose6: Graceful disconnect exit\n\nError Handling:\n- Socket errors: Log via WSAGetLastError, set disconnected state, exit thread\n- Graceful disconnect (recv=0): Set disconnected state, exit thread\n- Shutdown flag: Immediate thread exit with debug output",
      "name_source": "LoD/1.07",
      "method": "STR",
      "index": "STR:a94b3e62ae5ce13d808c0cf5fa32d36c",
      "callees": {
        "LoD/1.07": [
          "EnterCriticalSectionWrapper",
          "__WSAFDIsSet",
          "EnterCriticalSectionWrapper",
          "DecodeHuffmanStream",
          "EnterCriticalSectionWrapper",
          "EnterCriticalSectionWrapper"
        ],
        "LoD/1.08": [
          "LeaveCriticalSectionValidated",
          "__WSAFDIsSet",
          "LeaveCriticalSectionValidated",
          "DecodeHuffmanStream",
          "LeaveCriticalSectionValidated",
          "LeaveCriticalSectionValidated"
        ],
        "LoD/1.09": [
          "LeaveCriticalSectionValidated",
          "__WSAFDIsSet",
          "LeaveCriticalSectionValidated",
          "DecodeHuffmanStream",
          "LeaveCriticalSectionValidated",
          "LeaveCriticalSectionValidated"
        ],
        "LoD/1.09b": [
          "LeaveCriticalSectionValidated",
          "__WSAFDIsSet",
          "LeaveCriticalSectionValidated",
          "DecodeHuffmanStream",
          "LeaveCriticalSectionValidated",
          "LeaveCriticalSectionValidated"
        ],
        "LoD/1.09d": [
          "LeaveCriticalSectionValidated",
          "__WSAFDIsSet",
          "LeaveCriticalSectionValidated",
          "DecodeHuffmanStream",
          "LeaveCriticalSectionValidated",
          "LeaveCriticalSectionValidated"
        ],
        "LoD/1.10": [
          "LeaveCriticalSectionValidated",
          "__WSAFDIsSet",
          "LeaveCriticalSectionValidated",
          "Ordinal_10224",
          "LeaveCriticalSectionValidated",
          "LeaveCriticalSectionValidated"
        ],
        "LoD/1.11": [
          "select",
          "WSAGetLastError",
          "LeaveCriticalSectionValidated",
          "__WSAFDIsSet",
          "LeaveCriticalSectionValidated",
          "recv",
          "DecodeHuffmanBitStream",
          "recv",
          "WSAGetLastError",
          "LeaveCriticalSectionValidated",
          "...+1 more"
        ],
        "LoD/1.11b": [
          "select",
          "WSAGetLastError",
          "LeaveCriticalSectionValidated",
          "__WSAFDIsSet",
          "LeaveCriticalSectionValidated",
          "recv",
          "DecodeHuffmanBitStream",
          "recv",
          "WSAGetLastError",
          "LeaveCriticalSectionValidated",
          "...+1 more"
        ],
        "LoD/1.12a": [
          "select",
          "WSAGetLastError",
          "LeaveCriticalSectionValidated",
          "__WSAFDIsSet",
          "LeaveCriticalSectionValidated",
          "recv",
          "DecodeHuffmanBitStream",
          "recv",
          "WSAGetLastError",
          "LeaveCriticalSectionValidated",
          "...+1 more"
        ],
        "LoD/1.13c": [
          "select",
          "WSAGetLastError",
          "LeaveCriticalSectionValidated",
          "__WSAFDIsSet",
          "LeaveCriticalSectionValidated",
          "recv",
          "DecodeHuffmanBitStream",
          "recv",
          "WSAGetLastError",
          "LeaveCriticalSectionValidated",
          "...+1 more"
        ],
        "LoD/1.13d": [
          "select",
          "WSAGetLastError",
          "LeaveCriticalSectionValidated",
          "__WSAFDIsSet",
          "LeaveCriticalSectionValidated",
          "recv",
          "DecodeHuffmanBitStream",
          "recv",
          "WSAGetLastError",
          "LeaveCriticalSectionValidated",
          "...+1 more"
        ]
      },
      "strings": {
        "LoD/1.07": [
          "\"Client thread close #3\\n\"",
          "\"Client thread close #2\\n\"",
          "\"Client thread close #5\\n\"",
          "\"Client thread close #6\\n\""
        ],
        "LoD/1.08": [
          "\"Client thread close #3\\n\"",
          "\"Client thread close #2\\n\"",
          "\"Client thread close #5\\n\"",
          "\"Client thread close #6\\n\""
        ],
        "LoD/1.09": [
          "\"Client thread close #3\\n\"",
          "\"Client thread close #2\\n\"",
          "\"Client thread close #5\\n\"",
          "\"Client thread close #6\\n\""
        ],
        "LoD/1.09b": [
          "\"Client thread close #3\\n\"",
          "\"Client thread close #2\\n\"",
          "\"Client thread close #5\\n\"",
          "\"Client thread close #6\\n\""
        ],
        "LoD/1.09d": [
          "\"Client thread close #3\\n\"",
          "\"Client thread close #2\\n\"",
          "\"Client thread close #5\\n\"",
          "\"Client thread close #6\\n\""
        ],
        "LoD/1.10": [
          "\"Client thread close #3\\n\"",
          "\"Client thread close #2\\n\"",
          "\"Client thread close #5\\n\"",
          "\"Client thread close #6\\n\""
        ],
        "LoD/1.11": [
          "\"Client thread close #3\\n\"",
          "\"Client thread close #2\\n\"",
          "\"Client thread close #5\\n\"",
          "\"Client thread close #6\\n\""
        ],
        "LoD/1.11b": [
          "\"Client thread close #3\\n\"",
          "\"Client thread close #2\\n\"",
          "\"Client thread close #5\\n\"",
          "\"Client thread close #6\\n\""
        ],
        "LoD/1.12a": [
          "\"Client thread close #3\\n\"",
          "\"Client thread close #2\\n\"",
          "\"Client thread close #5\\n\"",
          "\"Client thread close #6\\n\""
        ],
        "LoD/1.13c": [
          "\"Client thread close #3\\n\"",
          "\"Client thread close #2\\n\"",
          "\"Client thread close #5\\n\"",
          "\"Client thread close #6\\n\""
        ],
        "LoD/1.13d": [
          "\"Client thread close #3\\n\"",
          "\"Client thread close #2\\n\"",
          "\"Client thread close #5\\n\"",
          "\"Client thread close #6\\n\""
        ]
      },
      "basic_block_counts": {
        "LoD/1.07": 34,
        "LoD/1.08": 34,
        "LoD/1.09": 34,
        "LoD/1.09b": 34,
        "LoD/1.09d": 34,
        "LoD/1.10": 34,
        "LoD/1.11": 39,
        "LoD/1.11b": 39,
        "LoD/1.12a": 39,
        "LoD/1.13c": 39,
        "LoD/1.13d": 39
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "81dacc3d24b9c3f186ef7b226a055935",
        "LoD/1.08": "81dacc3d24b9c3f186ef7b226a055935",
        "LoD/1.09": "81dacc3d24b9c3f186ef7b226a055935",
        "LoD/1.09b": "81dacc3d24b9c3f186ef7b226a055935",
        "LoD/1.09d": "81dacc3d24b9c3f186ef7b226a055935",
        "LoD/1.10": "81dacc3d24b9c3f186ef7b226a055935",
        "LoD/1.11": "e89b45b99751be448f78e8a476cdac28",
        "LoD/1.11b": "e89b45b99751be448f78e8a476cdac28",
        "LoD/1.12a": "e89b45b99751be448f78e8a476cdac28",
        "LoD/1.13c": "e89b45b99751be448f78e8a476cdac28",
        "LoD/1.13d": "e89b45b99751be448f78e8a476cdac28"
      }
    },
    "d2net.dll_NET_ParseAndQueuePackets": {
      "addresses": {
        "LoD/1.07": "0x6FC315E0",
        "LoD/1.08": "0x6FC315E0",
        "LoD/1.09": "0x6FC015E0",
        "LoD/1.09b": "0x6FC015E0",
        "LoD/1.09d": "0x6FC015E0",
        "LoD/1.10": "0x6FC015C0"
      },
      "rvas": {
        "LoD/1.07": "0x15E0",
        "LoD/1.08": "0x15E0",
        "LoD/1.09": "0x15E0",
        "LoD/1.09b": "0x15E0",
        "LoD/1.09d": "0x15E0",
        "LoD/1.10": "0x15C0"
      },
      "sizes": {
        "LoD/1.07": 416,
        "LoD/1.08": 416,
        "LoD/1.09": 416,
        "LoD/1.09b": 416,
        "LoD/1.09d": 416,
        "LoD/1.10": 416
      },
      "name": "NET_ParseAndQueuePackets",
      "signature": "dword NET_ParseAndQueuePackets(void)",
      "calling_convention": "__stdcall",
      "comment": "Parses network packets from the receive pool buffer and queues them for processing.\n\nClassification: Worker function - core network packet parsing and queue management\n\nAlgorithm:\n1. Load remaining byte count from pool buffer offset 0x7B8\n2. Loop while bytes remain in pool buffer:\n   a. Call Ordinal_10030 to determine packet size based on packet type byte\n   b. Validate packet size <= 0x204 (516 bytes max), assert on failure\n   c. Validate remaining bytes >= packet size, break if insufficient\n   d. Allocate 0x210 (528) byte packet structure via FogMemAlloc\n   e. Store packet size at structure offset 0x204\n   f. Zero structure bytes at offsets 0x208-0x20F (next pointer and flags)\n   g. Copy packet data from pool to structure using DWORD then byte copies\n   h. Handle special packet types:\n      - 0xA7: Compression packet - if subtype 0x81, decode Huffman table\n      - 0x8F: Timestamp packet - store GetTickCount() at structure offset 0x0D\n   i. Select queue: g_pNetRecvQueue if type <= 0xA6, g_pNetSendQueue if > 0xA6\n   j. Walk queue to find tail (linked via offset 0x20C)\n   k. Append packet structure to queue tail\n   l. Advance pool cursor by packet size, decrement remaining bytes\n3. Update remaining byte count at pool buffer offset 0x7B8\n4. If bytes remain and cursor moved, memmove remaining data to pool start\n5. Return compression flag (1 if 0xA7 packet processed, 0 otherwise)\n\nParameters:\n  None (uses global pool buffer g_pNetPoolAlloc)\n\nReturns:\n  0 - No compression packets processed or error\n  1 - Compression packet (0xA7) was processed\n\nSpecial Cases:\n- Packet size > 0x204 triggers FogAssert and fatal error exit\n- Remaining bytes < packet size causes early loop exit\n- Packet type 0xA7 with subtype 0x00 skips compression processing\n- Packet type 0xA7 with subtype 0x81 triggers Huffman table decode loop\n\nPacket Structure Layout (0x210 bytes):\n  Offset  Size  Field           Description\n  0x000   0x204 abData          Raw packet data\n  0x204   0x4   dwPacketSize    Size of packet data in bytes\n  0x208   0x4   dwFlags         Reserved flags (initialized to 0)\n  0x20C   0x4   pNextPacket     Linked list next pointer\n\nMagic Numbers:\n  0x204 - Maximum packet data size (516 bytes)\n  0x210 - Total packet structure size (528 bytes)\n  0xA7  - Compression packet type\n  0x8F  - Timestamp packet type\n  0xA6  - Queue selection threshold (<=0xA6 recv, >0xA6 send)\n  0x81  - Huffman table subtype for 0xA7 packets\n  0x80  - Huffman decode loop iteration limit (128 entries)\n  0x7B8 - Pool buffer remaining bytes count offset\n\nRelated Globals:\n  g_pNetPoolAlloc  - Network receive pool buffer base\n  g_pNetRecvQueue  - Queue head for received packets (type <= 0xA6)\n  g_pNetSendQueue  - Queue head for send-related packets (type > 0xA6)",
      "name_source": "LoD/1.07",
      "method": "STR",
      "index": "STR:8ddebd8361e26863204c1a73b891cc64",
      "callees": {
        "LoD/1.07": [
          "NET_GetPacketSize",
          "FogMemAlloc",
          "BuildHuffmanDecodeTables",
          "FogAssert"
        ],
        "LoD/1.08": [
          "NET_GetPacketSize",
          "FogMemAlloc",
          "BuildHuffmanDecodeTables",
          "FogAssert"
        ],
        "LoD/1.09": [
          "NET_GetPacketSize",
          "FogMemAlloc",
          "BuildHuffmanDecodeTables",
          "FogAssert"
        ],
        "LoD/1.09b": [
          "NET_GetPacketSize",
          "FogMemAlloc",
          "BuildHuffmanDecodeTables",
          "FogAssert"
        ],
        "LoD/1.09d": [
          "NET_GetPacketSize",
          "FogMemAlloc",
          "BuildHuffmanDecodeTables",
          "FogAssert"
        ],
        "LoD/1.10": [
          "Ordinal_10030",
          "FogMemAlloc",
          "Ordinal_10219",
          "FogAssert"
        ]
      },
      "strings": {
        "LoD/1.07": [
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2Net\\\\SRC\\\\Client...",
          "\"msgSize <= MAX_MSG_SIZE\""
        ],
        "LoD/1.08": [
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2Net\\\\SRC\\\\Client...",
          "\"msgSize <= MAX_MSG_SIZE\""
        ],
        "LoD/1.09": [
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2Net\\\\SRC\\\\Client...",
          "\"msgSize <= MAX_MSG_SIZE\""
        ],
        "LoD/1.09b": [
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2Net\\\\SRC\\\\Client...",
          "\"msgSize <= MAX_MSG_SIZE\""
        ],
        "LoD/1.09d": [
          "\"C:\\\\Src\\\\Diablo2\\\\Source\\\\D2Net\\\\SRC\\\\Client.cpp\"",
          "\"msgSize <= MAX_MSG_SIZE\""
        ],
        "LoD/1.10": [
          "\"C:\\\\projects\\\\D2\\\\head\\\\Diablo2\\\\Source\\\\D2Net\\\\S...",
          "\"msgSize <= MAX_MSG_SIZE\""
        ]
      },
      "basic_block_counts": {
        "LoD/1.07": 25,
        "LoD/1.08": 25,
        "LoD/1.09": 25,
        "LoD/1.09b": 25,
        "LoD/1.09d": 25,
        "LoD/1.10": 22
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "c246fd0702e3fa5ddb134a31f38c8140",
        "LoD/1.08": "c246fd0702e3fa5ddb134a31f38c8140",
        "LoD/1.09": "c246fd0702e3fa5ddb134a31f38c8140",
        "LoD/1.09b": "c246fd0702e3fa5ddb134a31f38c8140",
        "LoD/1.09d": "c246fd0702e3fa5ddb134a31f38c8140",
        "LoD/1.10": "89b2286a6a6c5b6b9722cca7ad83c544"
      }
    },
    "d2net.dll_NET_SendClientData": {
      "addresses": {
        "LoD/1.07": "0x6FC31780",
        "LoD/1.08": "0x6FC31780",
        "LoD/1.09": "0x6FC01780",
        "LoD/1.09b": "0x6FC01780",
        "LoD/1.09d": "0x6FC01780",
        "LoD/1.10": "0x6FC01760"
      },
      "rvas": {
        "LoD/1.07": "0x1780",
        "LoD/1.08": "0x1780",
        "LoD/1.09": "0x1780",
        "LoD/1.09b": "0x1780",
        "LoD/1.09d": "0x1780",
        "LoD/1.10": "0x1760"
      },
      "sizes": {
        "LoD/1.07": 161,
        "LoD/1.08": 161,
        "LoD/1.09": 161,
        "LoD/1.09b": 161,
        "LoD/1.09d": 161,
        "LoD/1.10": 161
      },
      "name": "NET_SendClientData",
      "signature": "uint NET_SendClientData(uint dwSocketHandle, byte * pbData, uint dwDataSize)",
      "calling_convention": "__stdcall",
      "comment": "Sends data to the game server over the network client socket.\n\nThis is a public API function (Ordinal 10005) that sends data to the connected\nserver. It validates the network state and message size, then either queues\nthe message for batch processing or sends directly via Winsock depending on\nthe shutdown state.\n\nAlgorithm:\n1. Check if network is initialized (g_fNetworkInitialized); return 0 if not\n2. Call NET_IsShuttingDown to check if network is being shut down\n3. If NOT shutting down (normal operation):\n   a. Load socket handle from g_hClientSocket\n   b. Call send(socket, pbData, dwDataSize, 0) via IAT\n   c. If send returns -1 (SOCKET_ERROR):\n      - Call WSAGetLastError to get error code\n      - Call NET_IsShuttingDown again to recheck shutdown state\n      - If now shutting down, return 0 (graceful exit)\n      - Otherwise assert failure, clear g_dwLastNetworkError, and call LeaveCriticalSection\n   d. Return bytes sent (EAX from send)\n4. If shutting down:\n   a. Validate dwDataSize <= MAX_MSG_SIZE (0x204 = 516 bytes)\n   b. If size exceeds limit, assert and call FUN_6fc326bb(-1) to signal error\n   c. Call FUN_6fc32510(dwSocketHandle, dwDataSize) to queue message\n   d. Return result (success/failure)\n\nParameters:\n  dwSocketHandle - Socket identifier (param_1, stack+4)\n  pbData - Pointer to data buffer to send (param_2, stack+8)\n  dwDataSize - Size of data in bytes (param_3, stack+C)\n\nReturns:\n  uint - Bytes sent on success, 0 on failure or if network not initialized\n\nSpecial Cases:\n  - Returns 0 immediately if g_fNetworkInitialized is false\n  - MAX_MSG_SIZE is 0x204 (516 bytes) - triggers assert if exceeded during shutdown\n  - Socket errors during normal operation trigger WSAGetLastError and shutdown check\n\nError Handling:\n  - SOCKET_ERROR (-1) from send() triggers error recovery path\n  - Clears g_dwLastNetworkError on socket error during active connection\n  - FogAssert called on message size violation with szAssertWsizeValid\n\nMagic Numbers:\n  0x204 - MAX_MSG_SIZE (516 bytes maximum message size)\n  0x1C5 - Assert line number in Client.cpp (453)\n  -1 (0xFFFFFFFF) - SOCKET_ERROR return value / error signal to FUN_6fc326bb\n  0x41 - Error code passed to EnterCriticalSectionWrapper on fatal error",
      "name_source": "LoD/1.07",
      "method": "API",
      "index": "API:cda67140fce8dc1f214ef718dfff0b09",
      "callees": {
        "LoD/1.07": [
          "FogAssert",
          "EnterCriticalSectionWrapper"
        ],
        "LoD/1.08": [
          "FogAssert",
          "LeaveCriticalSectionValidated"
        ],
        "LoD/1.09": [
          "FogAssert",
          "LeaveCriticalSectionValidated"
        ],
        "LoD/1.09b": [
          "FogAssert",
          "LeaveCriticalSectionValidated"
        ],
        "LoD/1.09d": [
          "FogAssert",
          "LeaveCriticalSectionValidated"
        ],
        "LoD/1.10": [
          "FogAssert",
          "LeaveCriticalSectionValidated"
        ]
      },
      "strings": {
        "LoD/1.07": [
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2Net\\\\SRC\\\\Client...",
          "\"wSize <= MAX_MSG_SIZE\""
        ],
        "LoD/1.08": [
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2Net\\\\SRC\\\\Client...",
          "\"wSize <= MAX_MSG_SIZE\""
        ],
        "LoD/1.09": [
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2Net\\\\SRC\\\\Client...",
          "\"wSize <= MAX_MSG_SIZE\""
        ],
        "LoD/1.09b": [
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2Net\\\\SRC\\\\Client...",
          "\"wSize <= MAX_MSG_SIZE\""
        ],
        "LoD/1.09d": [
          "\"C:\\\\Src\\\\Diablo2\\\\Source\\\\D2Net\\\\SRC\\\\Client.cpp\"",
          "\"wSize <= MAX_MSG_SIZE\""
        ],
        "LoD/1.10": [
          "\"wSize <= MAX_MSG_SIZE\"",
          "\"C:\\\\projects\\\\D2\\\\head\\\\Diablo2\\\\Source\\\\D2Net\\\\S..."
        ]
      },
      "basic_block_counts": {
        "LoD/1.07": 10,
        "LoD/1.08": 10,
        "LoD/1.09": 10,
        "LoD/1.09b": 10,
        "LoD/1.09d": 10,
        "LoD/1.10": 10
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "84a0810b5e44f42c369c63fad891b12d",
        "LoD/1.08": "84a0810b5e44f42c369c63fad891b12d",
        "LoD/1.09": "84a0810b5e44f42c369c63fad891b12d",
        "LoD/1.09b": "84a0810b5e44f42c369c63fad891b12d",
        "LoD/1.09d": "84a0810b5e44f42c369c63fad891b12d",
        "LoD/1.10": "84a0810b5e44f42c369c63fad891b12d"
      }
    },
    "d2net.dll_NET_QueuePacketForShutdown": {
      "addresses": {
        "LoD/1.07": "0x6FC31830",
        "LoD/1.08": "0x6FC31830",
        "LoD/1.09": "0x6FC01830",
        "LoD/1.09b": "0x6FC01830",
        "LoD/1.09d": "0x6FC01830",
        "LoD/1.10": "0x6FC01810"
      },
      "rvas": {
        "LoD/1.07": "0x1830",
        "LoD/1.08": "0x1830",
        "LoD/1.09": "0x1830",
        "LoD/1.09b": "0x1830",
        "LoD/1.09d": "0x1830",
        "LoD/1.10": "0x1810"
      },
      "sizes": {
        "LoD/1.07": 400,
        "LoD/1.08": 400,
        "LoD/1.09": 400,
        "LoD/1.09b": 400,
        "LoD/1.09d": 400,
        "LoD/1.10": 400
      },
      "name": "NET_QueuePacketForShutdown",
      "signature": "void NET_QueuePacketForShutdown(byte * pbPacketData, dword dwDataSize)",
      "calling_convention": "__fastcall",
      "comment": "Queues network packets for deferred processing during shutdown.\n\nCalled when NET_IsShuttingDown() returns true to store incoming packets in the\nappropriate queue for later processing after shutdown completes.\n\nAlgorithm:\n1. Loop while dwRemainingSize > 0\n2. Allocate NetQueueEntry (0x210 bytes) via FogMemAlloc\n3. Call Ordinal_10030 (NET_GetMessageSize) to parse packet type and get size\n4. If size is 0, exit (invalid packet)\n5. Validate size: assert nSize <= MAX_MSG_SIZE (0x204) and nSize > 0\n6. Copy packet data to allocated entry using DWORD then BYTE copy loops\n7. Set entry->dwPacketSize = dwPacketSize at offset 0x204\n8. Set entry->dwTimestamp = GetTickCount() at offset 0x208\n9. Clear entry->pNext (4 bytes at offset 0x20c)\n10. Select queue based on message type:\n    - Type < 0xA7: use g_pNetRecvQueue (client-to-server messages)\n    - Type 0xA7-0xAC: use g_pNetSendQueue (server-to-client messages)\n    - Type > 0xAC: fatal error (bad message type)\n11. If queue empty, set as head; else traverse to tail and append\n12. Update dwRemainingSize and advance pbPacketData pointer\n13. Repeat until all data processed\n\nParameters:\n  pbPacketData - byte* - ECX - Input buffer containing one or more packets\n  dwDataSize   - dword - EDX - Total size of input data in bytes\n\nReturns:\n  void\n\nStructure Layout (NetQueueEntry - 0x210 bytes):\n  Offset  Size  Field           Type     Description\n  0x000   516   abPacketData    byte[]   Raw packet data (max 0x204 bytes)\n  0x204   4     dwPacketSize    dword    Actual packet size\n  0x208   4     dwTimestamp     dword    GetTickCount() when queued\n  0x20C   4     pNext           void*    Next entry in linked list\n\nMessage Type Ranges:\n  0x00-0xA6: Client messages -> g_pNetRecvQueue\n  0xA7-0xAC: Server messages -> g_pNetSendQueue\n  0xAD+:     Invalid (triggers FogFatalError)\n\nSpecial Cases:\n  - Multiple packets in single buffer processed sequentially\n  - Packet size > 0x204 triggers FogAssert then FUN_6fc326bb(-1)\n  - Packet size <= 0 triggers FogAssert then FUN_6fc326bb(-1)\n  - Invalid message type triggers FogFatalError\n\nCalled By:\n  Ordinal_10006 (when NET_IsShuttingDown() is true)",
      "name_source": "LoD/1.07",
      "method": "STR",
      "index": "STR:a2736ab402304fa5f41d71a5d13290b2",
      "callees": {
        "LoD/1.07": [
          "FogMemAlloc",
          "NET_GetPacketSize",
          "FogAssert",
          "FogAssert",
          "FogFatalError",
          "FogFatalError"
        ],
        "LoD/1.08": [
          "FogMemAlloc",
          "NET_GetPacketSize",
          "FogAssert",
          "FogAssert",
          "FogFatalError",
          "FogFatalError"
        ],
        "LoD/1.09": [
          "FogMemAlloc",
          "NET_GetPacketSize",
          "FogAssert",
          "FogAssert",
          "FogFatalError",
          "FogFatalError"
        ],
        "LoD/1.09b": [
          "FogMemAlloc",
          "NET_GetPacketSize",
          "FogAssert",
          "FogAssert",
          "FogFatalError",
          "FogFatalError"
        ],
        "LoD/1.09d": [
          "FogMemAlloc",
          "NET_GetPacketSize",
          "FogAssert",
          "FogAssert",
          "FogFatalError",
          "FogFatalError"
        ],
        "LoD/1.10": [
          "FogMemAlloc",
          "Ordinal_10030",
          "FogAssert",
          "FogAssert",
          "FogFatalError",
          "FogFatalError"
        ]
      },
      "strings": {
        "LoD/1.07": [
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2Net\\\\SRC\\\\Client...",
          "\"nSize <= MAX_MSG_SIZE\"",
          "\"nSize > 0\"",
          "\"Bad message type\""
        ],
        "LoD/1.08": [
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2Net\\\\SRC\\\\Client...",
          "\"nSize <= MAX_MSG_SIZE\"",
          "\"nSize > 0\"",
          "\"Bad message type\""
        ],
        "LoD/1.09": [
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2Net\\\\SRC\\\\Client...",
          "\"nSize <= MAX_MSG_SIZE\"",
          "\"nSize > 0\"",
          "\"Bad message type\""
        ],
        "LoD/1.09b": [
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2Net\\\\SRC\\\\Client...",
          "\"nSize <= MAX_MSG_SIZE\"",
          "\"nSize > 0\"",
          "\"Bad message type\""
        ],
        "LoD/1.09d": [
          "\"C:\\\\Src\\\\Diablo2\\\\Source\\\\D2Net\\\\SRC\\\\Client.cpp\"",
          "\"nSize <= MAX_MSG_SIZE\"",
          "\"nSize > 0\"",
          "\"Bad message type\""
        ],
        "LoD/1.10": [
          "\"C:\\\\projects\\\\D2\\\\head\\\\Diablo2\\\\Source\\\\D2Net\\\\S...",
          "\"nSize <= MAX_MSG_SIZE\"",
          "\"nSize > 0\"",
          "\"Bad message type\""
        ]
      },
      "basic_block_counts": {
        "LoD/1.07": 24,
        "LoD/1.08": 24,
        "LoD/1.09": 24,
        "LoD/1.09b": 24,
        "LoD/1.09d": 24,
        "LoD/1.10": 24
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "3bbadb83fab156e2323576c85ed2fd78",
        "LoD/1.08": "3bbadb83fab156e2323576c85ed2fd78",
        "LoD/1.09": "3bbadb83fab156e2323576c85ed2fd78",
        "LoD/1.09b": "3bbadb83fab156e2323576c85ed2fd78",
        "LoD/1.09d": "3bbadb83fab156e2323576c85ed2fd78",
        "LoD/1.10": "01d89fa33861f6c0ff4b960f1ae9d811"
      }
    },
    "d2net.dll_GetLocalSocketAddressString": {
      "addresses": {
        "LoD/1.07": "0x6FC319C0",
        "LoD/1.08": "0x6FC319C0",
        "LoD/1.09": "0x6FC019C0",
        "LoD/1.09b": "0x6FC019C0",
        "LoD/1.09d": "0x6FC019C0",
        "LoD/1.10": "0x6FC019A0"
      },
      "rvas": {
        "LoD/1.07": "0x19C0",
        "LoD/1.08": "0x19C0",
        "LoD/1.09": "0x19C0",
        "LoD/1.09b": "0x19C0",
        "LoD/1.09d": "0x19C0",
        "LoD/1.10": "0x19A0"
      },
      "sizes": {
        "LoD/1.07": 84,
        "LoD/1.08": 84,
        "LoD/1.09": 84,
        "LoD/1.09b": 84,
        "LoD/1.09d": 84,
        "LoD/1.10": 84
      },
      "name": "GetLocalSocketAddressString",
      "signature": "void GetLocalSocketAddressString(int nDestBuffer)",
      "calling_convention": "__stdcall",
      "comment": "Retrieves the local IP address of the client socket as a dotted-decimal string.\n\nClassification: Public API (Ordinal 10013) - exported utility function for callers to obtain local network address.\n\nAlgorithm:\n1. Initialize sockaddr structure (16 bytes) and address length to 0x10\n2. Call getsockname() on g_hClientSocket to retrieve local endpoint info\n3. Extract in_addr from sockaddr at offset +4 (sin_addr field)\n4. Call inet_ntoa() to convert binary IP to dotted-decimal string\n5. Copy result string to caller's buffer using SStrCopy\n\nParameters:\n  lpszDestBuffer (int) - Destination buffer for IP string (e.g., \"192.168.1.1\")\n                         Must be at least 16 bytes for max IPv4 string\n\nReturns: void\n\nSpecial Cases:\n  - If g_hClientSocket is invalid, getsockname fails and buffer receives \"0.0.0.0\"\n  - inet_ntoa returns pointer to static buffer, hence immediate copy to lpszDestBuffer\n\nGlobals Referenced:\n  g_hClientSocket (0x6fc3b084) - Client socket handle obtained during connection\n\nStructure Layout (sockaddr_in at Stack[-0x10]):\n  Offset  Size  Field         Type      Description\n  0x00    2     sin_family    ushort    Address family (AF_INET)\n  0x02    2     sin_port      ushort    Port number (network byte order)\n  0x04    4     sin_addr      in_addr   IPv4 address\n  0x08    8     sin_zero      char[8]   Padding to match sockaddr size",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:5ac3a75aff7cc1836aa147dfbcca7fd9",
      "callees": {
        "LoD/1.07": [
          "SStrCopy"
        ],
        "LoD/1.08": [
          "Ordinal_501"
        ],
        "LoD/1.09": [
          "Ordinal_501"
        ],
        "LoD/1.09b": [
          "Ordinal_501"
        ],
        "LoD/1.09d": [
          "Ordinal_501"
        ],
        "LoD/1.10": [
          "Ordinal_501"
        ]
      },
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "5ac3a75aff7cc1836aa147dfbcca7fd9",
        "LoD/1.08": "5ac3a75aff7cc1836aa147dfbcca7fd9",
        "LoD/1.09": "5ac3a75aff7cc1836aa147dfbcca7fd9",
        "LoD/1.09b": "5ac3a75aff7cc1836aa147dfbcca7fd9",
        "LoD/1.09d": "5ac3a75aff7cc1836aa147dfbcca7fd9",
        "LoD/1.10": "5ac3a75aff7cc1836aa147dfbcca7fd9"
      }
    },
    "d2net.dll_NET_IsShuttingDown": {
      "addresses": {
        "LoD/1.07": "0x6FC31A20",
        "LoD/1.08": "0x6FC31A20",
        "LoD/1.09": "0x6FC01A20",
        "LoD/1.09b": "0x6FC01A20",
        "LoD/1.09d": "0x6FC01A20",
        "LoD/1.10": "0x6FC01A00"
      },
      "rvas": {
        "LoD/1.07": "0x1A20",
        "LoD/1.08": "0x1A20",
        "LoD/1.09": "0x1A20",
        "LoD/1.09b": "0x1A20",
        "LoD/1.09d": "0x1A20",
        "LoD/1.10": "0x1A00"
      },
      "sizes": {
        "LoD/1.07": 22,
        "LoD/1.08": 22,
        "LoD/1.09": 22,
        "LoD/1.09b": 22,
        "LoD/1.09d": 22,
        "LoD/1.10": 22
      },
      "name": "NET_IsShuttingDown",
      "signature": "bool NET_IsShuttingDown(void)",
      "calling_convention": "__stdcall",
      "comment": "Checks if the network subsystem is in server/shutdown mode.\n\nAlgorithm:\n1. Load g_dwNetworkType global into EAX\n2. Compare with 1 (server mode type 1) - if equal, return true immediately\n3. Compare with 2 (server mode type 2) - return (type == 2)\n4. Returns false for type 0 (client mode)\n\nParameters: None\n\nReturns:\n  bool - true if g_dwNetworkType is 1 or 2 (server modes)\n       - false if g_dwNetworkType is 0 (client mode)\n\nGlobal State Read:\n  g_dwNetworkType (0x6fc3b22c) - Network operation type:\n    0 = Client mode (normal operation)\n    1 = Server mode type 1 (shutting down / server)\n    2 = Server mode type 2 (shutting down / server)\n\nCallers:\n  D2Net_InitializeClient - Skips thread creation if server mode\n  NET_Shutdown - Skips socket close if server mode\n  NET_GetLastNetworkResult - State validation\n  NET_SendClientData - State validation before send\n  NET_StartClientReceiveThread - State validation\n  Ordinal_10006 - D2Net_NotifyServerMode uses for state check\n\nNote: Despite the name, this function checks for \"server mode\" state,\nwhich is set during shutdown or when running as server rather than client.",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:af155f231b34e3cf344491a75e13c99d",
      "basic_block_counts": {
        "LoD/1.07": 3,
        "LoD/1.08": 3,
        "LoD/1.09": 3,
        "LoD/1.09b": 3,
        "LoD/1.09d": 3,
        "LoD/1.10": 3
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "af155f231b34e3cf344491a75e13c99d",
        "LoD/1.08": "af155f231b34e3cf344491a75e13c99d",
        "LoD/1.09": "af155f231b34e3cf344491a75e13c99d",
        "LoD/1.09b": "af155f231b34e3cf344491a75e13c99d",
        "LoD/1.09d": "af155f231b34e3cf344491a75e13c99d",
        "LoD/1.10": "af155f231b34e3cf344491a75e13c99d"
      }
    },
    "d2net.dll_D2Net_SetNetworkType": {
      "addresses": {
        "LoD/1.07": "0x6FC31A40",
        "LoD/1.08": "0x6FC31A40",
        "LoD/1.09": "0x6FC01A40",
        "LoD/1.09b": "0x6FC01A40",
        "LoD/1.09d": "0x6FC01A40",
        "LoD/1.10": "0x6FC01A20"
      },
      "rvas": {
        "LoD/1.07": "0x1A40",
        "LoD/1.08": "0x1A40",
        "LoD/1.09": "0x1A40",
        "LoD/1.09b": "0x1A40",
        "LoD/1.09d": "0x1A40",
        "LoD/1.10": "0x1A20"
      },
      "sizes": {
        "LoD/1.07": 7,
        "LoD/1.08": 7,
        "LoD/1.09": 7,
        "LoD/1.09b": 7,
        "LoD/1.09d": 7,
        "LoD/1.10": 7
      },
      "name": "D2Net_SetNetworkType",
      "signature": "void D2Net_SetNetworkType(dword dwNetworkType)",
      "calling_convention": "__fastcall",
      "comment": "Sets the network type global variable for D2Net subsystem.\n\nClassification: Leaf function / Internal utility setter\n\nAlgorithm:\n1. Store dwNetworkType parameter (ECX) directly to global g_dwNetworkType\n2. Return\n\nParameters:\n  dwNetworkType (dword, ECX) - Network operation type:\n    0 = Client mode (normal multiplayer client)\n    1 = Server mode type 1\n    2 = Server mode type 2\n\nReturns:\n  void - No return value\n\nCallers:\n  D2Net_InitializeClient - Sets network type during client initialization\n\nGlobal Modified:\n  g_dwNetworkType (0x6fc3b22c) - Stores the active network type\n\nCross-References to g_dwNetworkType:\n  NET_IsShuttingDown (READ) - Checks network type for server mode detection\n  FUN_6fc31a50 (READ) - Reads network type for mode checks\n  FUN_6fc31b60 (WRITE) - Also writes network type",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:305c32d33191c1b22ce2562362c5fa24",
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "305c32d33191c1b22ce2562362c5fa24",
        "LoD/1.08": "305c32d33191c1b22ce2562362c5fa24",
        "LoD/1.09": "305c32d33191c1b22ce2562362c5fa24",
        "LoD/1.09b": "305c32d33191c1b22ce2562362c5fa24",
        "LoD/1.09d": "305c32d33191c1b22ce2562362c5fa24",
        "LoD/1.10": "305c32d33191c1b22ce2562362c5fa24"
      }
    },
    "d2net.dll_DequeueNetworkPacket": {
      "addresses": {
        "LoD/1.07": "0x6FC31A50",
        "LoD/1.08": "0x6FC31A50",
        "LoD/1.09": "0x6FC01A50",
        "LoD/1.09b": "0x6FC01A50",
        "LoD/1.09d": "0x6FC01A50",
        "LoD/1.10": "0x6FC01A30",
        "LoD/1.11": "0x6FBF6A50",
        "LoD/1.11b": "0x6FBF75B0",
        "LoD/1.12a": "0x6FBF6400",
        "LoD/1.13c": "0x6FBF6AC0",
        "LoD/1.13d": "0x6FBF6390"
      },
      "rvas": {
        "LoD/1.07": "0x1A50",
        "LoD/1.08": "0x1A50",
        "LoD/1.09": "0x1A50",
        "LoD/1.09b": "0x1A50",
        "LoD/1.09d": "0x1A50",
        "LoD/1.10": "0x1A30",
        "LoD/1.11": "0x6A50",
        "LoD/1.11b": "0x75B0",
        "LoD/1.12a": "0x6400",
        "LoD/1.13c": "0x6AC0",
        "LoD/1.13d": "0x6390"
      },
      "sizes": {
        "LoD/1.07": 167,
        "LoD/1.08": 167,
        "LoD/1.09": 167,
        "LoD/1.09b": 167,
        "LoD/1.09d": 167,
        "LoD/1.10": 167,
        "LoD/1.11": 167,
        "LoD/1.11b": 167,
        "LoD/1.12a": 167,
        "LoD/1.13c": 167,
        "LoD/1.13d": 167
      },
      "name": "DequeueNetworkPacket",
      "signature": "void DequeueNetworkPacket(LPCRITICAL_SECTION pCritSec, void * * ppQueueHead, void * pOutputBuffer, uint dwBufferSize)",
      "calling_convention": "__fastcall",
      "comment": "Dequeues and copies a network packet from a thread-safe linked list queue.\n\nClassification: Worker function - Internal packet queue dequeue helper\n\nAlgorithm:\n1. Enter critical section for thread-safe queue access\n2. Load queue head pointer from ppQueueHead\n3. If queue empty (NULL), exit with error -1\n4. If g_dwNetworkType == 2, check timestamp throttle:\n   - Get current tick count\n   - If less than 500ms since packet timestamp (offset 0x208), exit with -1\n5. Clamp dwBufferSize to max 0x204 (516) bytes if larger than 0x203\n6. Copy packet data using DWORD-aligned memcpy:\n   - First loop copies dwBufferSize >> 2 DWORDs (REP MOVSD)\n   - Second loop copies dwBufferSize & 3 remaining bytes (REP MOVSB)\n7. Extract packet type from queue entry offset 0x204\n8. Update queue head to next entry (offset 0x20C)\n9. Release queue entry allocation via ReleasePoolAllocation\n10. Leave critical section\n11. Return packet type identifier\n\nParameters:\n  pCritSec      - LPCRITICAL_SECTION - Critical section for queue synchronization (ECX)\n  ppQueueHead   - void**             - Pointer to queue head pointer (EDX)\n  pOutputBuffer - void*              - Destination buffer for packet data\n  dwBufferSize  - uint               - Maximum bytes to copy (clamped to 0x204)\n\nReturns:\n  On success: Packet type identifier from queue entry offset 0x204\n  On failure: 0xFFFFFFFF (-1) if queue empty or throttled\n\nQueue Entry Layout (0x210 bytes):\n  Offset  Size  Field           Description\n  0x000   0x204 abPacketData    Raw packet data (max 516 bytes)\n  0x204   0x4   dwPacketType    Packet type identifier (returned)\n  0x208   0x4   dwTimestamp     GetTickCount when packet was queued\n  0x20C   0x4   pNextEntry      Pointer to next queue entry\n\nSpecial Cases:\n  - Network type 2: 500ms throttle between dequeues (rate limiting)\n  - Buffer size > 0x203 clamped to 0x204 (internal limit)\n  - Empty queue (NULL head) returns -1 immediately\n\nCalled By:\n  - NET_ReceivePacket (Ordinal 10007) with g_pNetRecvQueue\n  - NET_ReceiveClientPacket (Ordinal 10008) with g_pNetSendQueue",
      "name_source": "LoD/1.07",
      "method": "API",
      "index": "API:c49e429976faabc43d86aeeceef72c20",
      "callees": {
        "LoD/1.07": [
          "EnterCriticalSectionWrapper",
          "ReleasePoolAllocation"
        ],
        "LoD/1.08": [
          "LeaveCriticalSectionValidated",
          "ReleasePoolAllocation"
        ],
        "LoD/1.09": [
          "LeaveCriticalSectionValidated",
          "ReleasePoolAllocation"
        ],
        "LoD/1.09b": [
          "LeaveCriticalSectionValidated",
          "ReleasePoolAllocation"
        ],
        "LoD/1.09d": [
          "LeaveCriticalSectionValidated",
          "ReleasePoolAllocation"
        ],
        "LoD/1.10": [
          "LeaveCriticalSectionValidated",
          "ReleasePoolAllocation"
        ],
        "LoD/1.11": [
          "LeaveCriticalSectionValidated",
          "InitializeModule"
        ],
        "LoD/1.11b": [
          "LeaveCriticalSectionValidated",
          "InitializeModule"
        ],
        "LoD/1.12a": [
          "LeaveCriticalSectionValidated",
          "InitializeModule"
        ],
        "LoD/1.13c": [
          "LeaveCriticalSectionValidated",
          "InitializeModule"
        ],
        "LoD/1.13d": [
          "LeaveCriticalSectionValidated",
          "InitializeModule"
        ]
      },
      "strings": {
        "LoD/1.07": [
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2Net\\\\SRC\\\\D2Net...."
        ],
        "LoD/1.08": [
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2Net\\\\SRC\\\\D2Net...."
        ],
        "LoD/1.09": [
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2Net\\\\SRC\\\\D2Net...."
        ],
        "LoD/1.09b": [
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2Net\\\\SRC\\\\D2Net...."
        ],
        "LoD/1.09d": [
          "\"C:\\\\Src\\\\Diablo2\\\\Source\\\\D2Net\\\\SRC\\\\D2Net.cpp\""
        ],
        "LoD/1.10": [
          "\"C:\\\\projects\\\\D2\\\\head\\\\Diablo2\\\\Source\\\\D2Net\\\\S..."
        ],
        "LoD/1.11": [
          "\"..\\\\Source\\\\D2Net\\\\SRC\\\\D2Net.cpp\""
        ],
        "LoD/1.11b": [
          "\"..\\\\Source\\\\D2Net\\\\SRC\\\\D2Net.cpp\""
        ],
        "LoD/1.12a": [
          "\"..\\\\Source\\\\D2Net\\\\SRC\\\\D2Net.cpp\""
        ],
        "LoD/1.13c": [
          "\"..\\\\Source\\\\D2Net\\\\SRC\\\\D2Net.cpp\""
        ],
        "LoD/1.13d": [
          "\"..\\\\Source\\\\D2Net\\\\SRC\\\\D2Net.cpp\""
        ]
      },
      "basic_block_counts": {
        "LoD/1.07": 7,
        "LoD/1.08": 7,
        "LoD/1.09": 7,
        "LoD/1.09b": 7,
        "LoD/1.09d": 7,
        "LoD/1.10": 7,
        "LoD/1.11": 7,
        "LoD/1.11b": 7,
        "LoD/1.12a": 7,
        "LoD/1.13c": 7,
        "LoD/1.13d": 7
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "d529120be15a5a70833f5984962faa6f",
        "LoD/1.08": "d529120be15a5a70833f5984962faa6f",
        "LoD/1.09": "d529120be15a5a70833f5984962faa6f",
        "LoD/1.09b": "d529120be15a5a70833f5984962faa6f",
        "LoD/1.09d": "d529120be15a5a70833f5984962faa6f",
        "LoD/1.10": "d529120be15a5a70833f5984962faa6f",
        "LoD/1.11": "3d25b65ec162c3f1449545782a704df9",
        "LoD/1.11b": "3d25b65ec162c3f1449545782a704df9",
        "LoD/1.12a": "3d25b65ec162c3f1449545782a704df9",
        "LoD/1.13c": "3d25b65ec162c3f1449545782a704df9",
        "LoD/1.13d": "3d25b65ec162c3f1449545782a704df9"
      }
    },
    "d2net.dll_DrainPacketQueue": {
      "addresses": {
        "LoD/1.07": "0x6FC31B00",
        "LoD/1.08": "0x6FC31B00",
        "LoD/1.09": "0x6FC01B00",
        "LoD/1.09b": "0x6FC01B00",
        "LoD/1.09d": "0x6FC01B00",
        "LoD/1.10": "0x6FC01AE0"
      },
      "rvas": {
        "LoD/1.07": "0x1B00",
        "LoD/1.08": "0x1B00",
        "LoD/1.09": "0x1B00",
        "LoD/1.09b": "0x1B00",
        "LoD/1.09d": "0x1B00",
        "LoD/1.10": "0x1AE0"
      },
      "sizes": {
        "LoD/1.07": 65,
        "LoD/1.08": 65,
        "LoD/1.09": 65,
        "LoD/1.09b": 65,
        "LoD/1.09d": 65,
        "LoD/1.10": 65
      },
      "name": "DrainPacketQueue",
      "signature": "int DrainPacketQueue(LPCRITICAL_SECTION pCriticalSection, int * ppQueueHead)",
      "calling_convention": "__fastcall",
      "comment": "Drains a network packet queue by releasing all queued packet allocations.\n\nAlgorithm:\n1. Enter critical section to protect queue access\n2. Load queue head pointer from ppQueueHead\n3. If queue head is NULL, skip to step 7 (queue empty)\n4. Save next pointer from current node at offset 0x20c\n5. Call ReleasePoolAllocation to free current packet\n6. Update queue head to next pointer, repeat from step 3\n7. Leave critical section\n8. Return 1 (success)\n\nParameters:\n  pCriticalSection (ECX): Pointer to critical section protecting the queue\n  ppQueueHead (EDX): Pointer to queue head pointer (modified to NULL when drained)\n\nReturns:\n  int: Always returns 1 (success)\n\nLinked List Node Layout:\n  Offset 0x20c: Next pointer in queue chain\n\nCallers:\n  NET_Shutdown - Drains both send and receive queues during network shutdown\n\nSpecial Cases:\n  - Handles empty queue (NULL head) gracefully\n  - Completely drains queue, setting head to NULL\n  - Thread-safe via critical section\n\nSource File Reference:\n  Line 0x57 (87): EnterCriticalSectionWrapper call\n  Line 0x5d (93): ReleasePoolAllocation call in loop",
      "name_source": "LoD/1.07",
      "method": "API",
      "index": "API:c49e429976faabc43d86aeeceef72c20",
      "callees": {
        "LoD/1.07": [
          "EnterCriticalSectionWrapper",
          "ReleasePoolAllocation"
        ],
        "LoD/1.08": [
          "LeaveCriticalSectionValidated",
          "ReleasePoolAllocation"
        ],
        "LoD/1.09": [
          "LeaveCriticalSectionValidated",
          "ReleasePoolAllocation"
        ],
        "LoD/1.09b": [
          "LeaveCriticalSectionValidated",
          "ReleasePoolAllocation"
        ],
        "LoD/1.09d": [
          "LeaveCriticalSectionValidated",
          "ReleasePoolAllocation"
        ],
        "LoD/1.10": [
          "LeaveCriticalSectionValidated",
          "ReleasePoolAllocation"
        ]
      },
      "strings": {
        "LoD/1.07": [
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2Net\\\\SRC\\\\D2Net...."
        ],
        "LoD/1.08": [
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2Net\\\\SRC\\\\D2Net...."
        ],
        "LoD/1.09": [
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2Net\\\\SRC\\\\D2Net...."
        ],
        "LoD/1.09b": [
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2Net\\\\SRC\\\\D2Net...."
        ],
        "LoD/1.09d": [
          "\"C:\\\\Src\\\\Diablo2\\\\Source\\\\D2Net\\\\SRC\\\\D2Net.cpp\""
        ],
        "LoD/1.10": [
          "\"C:\\\\projects\\\\D2\\\\head\\\\Diablo2\\\\Source\\\\D2Net\\\\S..."
        ]
      },
      "basic_block_counts": {
        "LoD/1.07": 4,
        "LoD/1.08": 3,
        "LoD/1.09": 3,
        "LoD/1.09b": 3,
        "LoD/1.09d": 3,
        "LoD/1.10": 3
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "d1fb8387713d3ee912abe14d30fe83eb",
        "LoD/1.08": "d1fb8387713d3ee912abe14d30fe83eb",
        "LoD/1.09": "d1fb8387713d3ee912abe14d30fe83eb",
        "LoD/1.09b": "d1fb8387713d3ee912abe14d30fe83eb",
        "LoD/1.09d": "d1fb8387713d3ee912abe14d30fe83eb",
        "LoD/1.10": "d1fb8387713d3ee912abe14d30fe83eb"
      }
    },
    "d2net.dll_WSAGetLastError": {
      "addresses": {
        "LoD/1.07": "0x6FC31B50",
        "LoD/1.08": "0x6FC31B50",
        "LoD/1.09": "0x6FC01B50",
        "LoD/1.09b": "0x6FC01B50",
        "LoD/1.09d": "0x6FC01B50",
        "LoD/1.10": "0x6FC01B30",
        "LoD/1.11": "0x6FBF5D88",
        "LoD/1.11b": "0x6FBF5D64",
        "LoD/1.12a": "0x6FBF5DF8",
        "LoD/1.13c": "0x6FBF5DF8",
        "LoD/1.13d": "0x6FBF5D88"
      },
      "rvas": {
        "LoD/1.07": "0x1B50",
        "LoD/1.08": "0x1B50",
        "LoD/1.09": "0x1B50",
        "LoD/1.09b": "0x1B50",
        "LoD/1.09d": "0x1B50",
        "LoD/1.10": "0x1B30",
        "LoD/1.11": "0x5D88",
        "LoD/1.11b": "0x5D64",
        "LoD/1.12a": "0x5DF8",
        "LoD/1.13c": "0x5DF8",
        "LoD/1.13d": "0x5D88"
      },
      "sizes": {
        "LoD/1.07": 6,
        "LoD/1.08": 6,
        "LoD/1.09": 6,
        "LoD/1.09b": 6,
        "LoD/1.09d": 6,
        "LoD/1.10": 6,
        "LoD/1.11": 6,
        "LoD/1.11b": 6,
        "LoD/1.12a": 6,
        "LoD/1.13c": 6,
        "LoD/1.13d": 6
      },
      "name": "WSAGetLastError",
      "signature": "int WSAGetLastError(void)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:e3e7225badfcf3c2e051c42d71d7237a",
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1,
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.08": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09d": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.10": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.12a": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13c": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13d": "e3e7225badfcf3c2e051c42d71d7237a"
      }
    },
    "d2net.dll_DllNotificationHandler": {
      "addresses": {
        "LoD/1.07": "0x6FC31B60",
        "LoD/1.08": "0x6FC31B60",
        "LoD/1.09": "0x6FC01B60",
        "LoD/1.09b": "0x6FC01B60",
        "LoD/1.09d": "0x6FC01B60",
        "LoD/1.10": "0x6FC01B40",
        "LoD/1.11": "0x6FBF6A30",
        "LoD/1.11b": "0x6FBF7590",
        "LoD/1.12a": "0x6FBF63E0",
        "LoD/1.13c": "0x6FBF6AA0",
        "LoD/1.13d": "0x6FBF6370"
      },
      "rvas": {
        "LoD/1.07": "0x1B60",
        "LoD/1.08": "0x1B60",
        "LoD/1.09": "0x1B60",
        "LoD/1.09b": "0x1B60",
        "LoD/1.09d": "0x1B60",
        "LoD/1.10": "0x1B40",
        "LoD/1.11": "0x6A30",
        "LoD/1.11b": "0x7590",
        "LoD/1.12a": "0x63E0",
        "LoD/1.13c": "0x6AA0",
        "LoD/1.13d": "0x6370"
      },
      "sizes": {
        "LoD/1.07": 25,
        "LoD/1.08": 25,
        "LoD/1.09": 25,
        "LoD/1.09b": 25,
        "LoD/1.09d": 25,
        "LoD/1.10": 25,
        "LoD/1.11": 25,
        "LoD/1.11b": 25,
        "LoD/1.12a": 25,
        "LoD/1.13c": 25,
        "LoD/1.13d": 25
      },
      "name": "DllNotificationHandler",
      "signature": "int DllNotificationHandler(void * pInstance, dword dwReason, void * pReserved)",
      "calling_convention": "__stdcall",
      "comment": "DLL notification handler called by DllMain entry point.\nResets g_dwNetworkType to 0 when the DLL is being attached to a process.\nThis ensures clean network state initialization when D2Net.dll is loaded.\n\nAlgorithm:\n1. Check if dwReason equals 1 (DLL_PROCESS_ATTACH)\n2. If attaching, clear g_dwNetworkType to 0\n3. Return TRUE (1) to indicate successful handling\n\nParameters:\n  pInstance   - Handle to the DLL module (unused)\n  dwReason    - DLL notification reason code:\n                0 = DLL_PROCESS_DETACH\n                1 = DLL_PROCESS_ATTACH\n                2 = DLL_THREAD_ATTACH\n                3 = DLL_THREAD_DETACH\n  pReserved   - Reserved parameter (unused)\n\nReturns:\n  TRUE (1) - Always returns success regardless of reason code\n\nGlobal State Modified:\n  g_dwNetworkType - Set to 0 on DLL_PROCESS_ATTACH only",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:a0c0d6b1c3282eea25abd0f1350f43b4",
      "basic_block_counts": {
        "LoD/1.07": 3,
        "LoD/1.08": 3,
        "LoD/1.09": 3,
        "LoD/1.09b": 3,
        "LoD/1.09d": 3,
        "LoD/1.10": 3,
        "LoD/1.11": 3,
        "LoD/1.11b": 3,
        "LoD/1.12a": 3,
        "LoD/1.13c": 3,
        "LoD/1.13d": 3
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "a0c0d6b1c3282eea25abd0f1350f43b4",
        "LoD/1.08": "a0c0d6b1c3282eea25abd0f1350f43b4",
        "LoD/1.09": "a0c0d6b1c3282eea25abd0f1350f43b4",
        "LoD/1.09b": "a0c0d6b1c3282eea25abd0f1350f43b4",
        "LoD/1.09d": "a0c0d6b1c3282eea25abd0f1350f43b4",
        "LoD/1.10": "9c087099454eeca337d576704d2b3ed9",
        "LoD/1.11": "9c087099454eeca337d576704d2b3ed9",
        "LoD/1.11b": "9c087099454eeca337d576704d2b3ed9",
        "LoD/1.12a": "9c087099454eeca337d576704d2b3ed9",
        "LoD/1.13c": "9c087099454eeca337d576704d2b3ed9",
        "LoD/1.13d": "9c087099454eeca337d576704d2b3ed9"
      }
    },
    "d2net.dll_NET_GetPacketSize": {
      "addresses": {
        "LoD/1.07": "0x6FC31E40",
        "LoD/1.08": "0x6FC31E40",
        "LoD/1.09": "0x6FC01E40",
        "LoD/1.09b": "0x6FC01E40",
        "LoD/1.09d": "0x6FC01E40",
        "LoD/1.10": "0x6FC01B60"
      },
      "rvas": {
        "LoD/1.07": "0x1E40",
        "LoD/1.08": "0x1E40",
        "LoD/1.09": "0x1E40",
        "LoD/1.09b": "0x1E40",
        "LoD/1.09d": "0x1E40",
        "LoD/1.10": "0x1B60"
      },
      "sizes": {
        "LoD/1.07": 308,
        "LoD/1.08": 308,
        "LoD/1.09": 308,
        "LoD/1.09b": 308,
        "LoD/1.09d": 308,
        "LoD/1.10": 549
      },
      "name": "NET_GetPacketSize",
      "signature": "int NET_GetPacketSize(byte * pbPacketData, uint dwBufferSize, int * pnOutPacketSize)",
      "calling_convention": "__fastcall",
      "comment": "Calculates the size of a network packet based on its opcode byte.\n\nClassification: Worker function - core packet parsing utility\n\nAlgorithm:\n1. Return 0 if buffer is empty (dwBufferSize == 0)\n2. Read first byte as packet opcode\n3. If opcode == 0xFF, return 1 with size 16 (special keepalive/ping packet)\n4. If opcode > 0x6D, return 0 (invalid opcode range)\n5. Lookup fixed packet size from g_adPacketSizeTable[opcode]\n6. If table value is 0, packet type has no data - return 0\n7. If table value is negative (variable-length indicator):\n   a. For opcodes 0x14-0x15: Parse multiple null-terminated strings\n      - String 1 starts at offset +3\n      - String 2 follows String 1\n      - String 3 follows String 2  \n      - Extra byte after String 3 adds to total\n   b. For opcode 0x69: Size = byte[1] + 7\n   c. Other negative entries: Set size to 0\n8. Return computed packet size\n\nParameters:\n  pbPacketData (ECX) - Pointer to packet data buffer\n  dwBufferSize (EDX) - Size of available buffer in bytes\n  pnOutPacketSize (Stack+4) - Output pointer for calculated packet size\n\nReturns:\n  Non-zero: Packet size successfully calculated (value also stored in *pnOutPacketSize)\n  0: Error - buffer too small, invalid opcode, or unknown variable packet\n\nSpecial Cases:\n  - Opcode 0xFF: Fixed 16-byte packet (keepalive)\n  - Opcodes 0x14-0x15: Variable-length with 3 strings + extra byte\n  - Opcode 0x69: Variable-length using byte[1] as length field\n  - Table value -1: Variable-length packet marker\n\nMagic Numbers:\n  0xFF - Keepalive/ping packet opcode\n  0x6D (109) - Maximum valid opcode\n  0x10 (16) - Size of keepalive packet\n  0x14-0x15 (20-21) - Chat message packet opcodes\n  0x69 (105) - Variable data packet opcode\n\nPacket Size Table Layout (g_adPacketSizeTable):\n  Index 0x00-0x6D: Packet sizes by opcode\n  Positive value: Fixed packet size\n  Zero: Unknown/no-data packet\n  Negative (-1): Variable-length, requires parsing",
      "name_source": "LoD/1.07",
      "method": "API",
      "index": "API:3cde23138545941857f1e2b28777d19d",
      "callees": {
        "LoD/1.07": [
          "SStrLen",
          "SStrLen",
          "SStrLen",
          "SStrLen"
        ],
        "LoD/1.08": [
          "SStrLen",
          "SStrLen",
          "SStrLen",
          "SStrLen"
        ],
        "LoD/1.09": [
          "SStrLen",
          "SStrLen",
          "SStrLen",
          "SStrLen"
        ],
        "LoD/1.09b": [
          "SStrLen",
          "SStrLen",
          "SStrLen",
          "SStrLen"
        ],
        "LoD/1.09d": [
          "SStrLen",
          "SStrLen",
          "SStrLen",
          "SStrLen"
        ],
        "LoD/1.10": [
          "SStrLen",
          "SStrLen",
          "SStrLen"
        ]
      },
      "basic_block_counts": {
        "LoD/1.07": 26,
        "LoD/1.08": 26,
        "LoD/1.09": 26,
        "LoD/1.09b": 26,
        "LoD/1.09d": 26,
        "LoD/1.10": 49
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "71f863412da4e205fc141b877611c0e6",
        "LoD/1.08": "71f863412da4e205fc141b877611c0e6",
        "LoD/1.09": "71f863412da4e205fc141b877611c0e6",
        "LoD/1.09b": "71f863412da4e205fc141b877611c0e6",
        "LoD/1.09d": "71f863412da4e205fc141b877611c0e6",
        "LoD/1.10": "9594cf8b7b238fb449a268d88d20b75b"
      }
    },
    "d2net.dll_NET_QueueShutdownCallback": {
      "addresses": {
        "LoD/1.07": "0x6FC31F80",
        "LoD/1.08": "0x6FC31F80",
        "LoD/1.09": "0x6FC01F80",
        "LoD/1.09b": "0x6FC01F80",
        "LoD/1.09d": "0x6FC01F80",
        "LoD/1.10": "0x6FC01FC0"
      },
      "rvas": {
        "LoD/1.07": "0x1F80",
        "LoD/1.08": "0x1F80",
        "LoD/1.09": "0x1F80",
        "LoD/1.09b": "0x1F80",
        "LoD/1.09d": "0x1F80",
        "LoD/1.10": "0x1FC0"
      },
      "sizes": {
        "LoD/1.07": 19,
        "LoD/1.08": 19,
        "LoD/1.09": 19,
        "LoD/1.09b": 19,
        "LoD/1.09d": 19,
        "LoD/1.10": 19
      },
      "name": "NET_QueueShutdownCallback",
      "signature": "int NET_QueueShutdownCallback(byte * pbPacketData, dword dwDataSize)",
      "calling_convention": "__stdcall",
      "comment": "NET_QueueShutdownCallback - Network shutdown packet queue callback\n\nClassification: Callback - invoked by network subsystem during shutdown\n\nAlgorithm:\n1. Receive packet data pointer and size from network layer\n2. Adapt calling convention: move EDX (size) to ECX, load pbPacketData from stack\n3. Call NET_QueuePacketForShutdown to queue packet data\n4. Return 1 (TRUE) to indicate success\n\nParameters:\n  pbPacketData (byte *) - Pointer to packet data buffer to queue\n  dwDataSize (dword) - Size of packet data in bytes\n\nReturns:\n  int - Always returns 1 (TRUE) indicating successful queueing\n\nNote: This function has incomplete disassembly in Ghidra - only first instruction visible.\nFull bytes at 0x6fc31f80: 8B CA 8B 54 24 04 E8 A5 F8 FF FF B8 01 00 00 00 C2 04 00\n  MOV ECX, EDX       - Move size to ECX for fastcall\n  MOV EDX, [ESP+4]   - Load packet pointer to EDX  \n  CALL 0x6fc31830    - Call NET_QueuePacketForShutdown\n  MOV EAX, 1         - Set return value to TRUE\n  RET 4              - Return, cleanup 1 dword param (stdcall)\n\nCalled by: Ordinal_10003 via InitializeNetworkContext callback registration",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:d12dadc1ab311ba2f88d2c389f3cb83c",
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "d12dadc1ab311ba2f88d2c389f3cb83c",
        "LoD/1.08": "d12dadc1ab311ba2f88d2c389f3cb83c",
        "LoD/1.09": "d12dadc1ab311ba2f88d2c389f3cb83c",
        "LoD/1.09b": "d12dadc1ab311ba2f88d2c389f3cb83c",
        "LoD/1.09d": "d12dadc1ab311ba2f88d2c389f3cb83c",
        "LoD/1.10": "d12dadc1ab311ba2f88d2c389f3cb83c"
      }
    },
    "d2net.dll_NET_ValidateClientPacket": {
      "addresses": {
        "LoD/1.07": "0x6FC31FA0",
        "LoD/1.08": "0x6FC31FA0",
        "LoD/1.09": "0x6FC01FA0",
        "LoD/1.09b": "0x6FC01FA0",
        "LoD/1.09d": "0x6FC01FA0"
      },
      "rvas": {
        "LoD/1.07": "0x1FA0",
        "LoD/1.08": "0x1FA0",
        "LoD/1.09": "0x1FA0",
        "LoD/1.09b": "0x1FA0",
        "LoD/1.09d": "0x1FA0"
      },
      "sizes": {
        "LoD/1.07": 201,
        "LoD/1.08": 201,
        "LoD/1.09": 201,
        "LoD/1.09b": 201,
        "LoD/1.09d": 201
      },
      "name": "NET_ValidateClientPacket",
      "signature": "int NET_ValidateClientPacket(byte * pbPacketData, uint dwPacketLength, uint * pdwParsedSize, uint * pdwStatus, int * pnPacketClass, uint * pdwMaxSize)",
      "calling_convention": "__fastcall",
      "comment": "Validates an incoming client network packet for protocol compliance.\n\nAlgorithm:\n1. Return 3 (incomplete) if dwPacketLength is 0\n2. Read first byte of packet as opcode (byOpcode = *pbPacketData)\n3. Call NET_GetPacketSize to parse packet header and get actual packet size\n4. Return 3 if NET_GetPacketSize fails (returns 0)\n5. Return 4 (invalid) if opcode > 0x6d AND opcode != 0xff (reserved range)\n6. Return 4 (invalid) if parsed size > 0x204 (516 bytes max)\n7. Return 3 (incomplete) if parsed size exceeds available buffer\n8. Set output parameters:\n   - *pdwStatus = 0 (success)\n   - *pdwParsedSize = actual packet size from header\n   - *pnPacketClass = 1 if opcode < 100, else 0 or 2 based on range\n   - *pdwMaxSize = 100 (constant)\n9. Return based on packet class: 1 for class 1, 2 for class 0, 1-2 for class 2\n\nParameters:\n  pbPacketData (ECX): Pointer to raw packet buffer\n  dwPacketLength (EDX): Length of available data in buffer\n  pdwParsedSize (Stack+0x04): OUTPUT - Receives actual packet size\n  pdwStatus (Stack+0x08): OUTPUT - Receives 0 on success\n  pnPacketClass (Stack+0x0C): OUTPUT - Receives packet class (0, 1, or 2)\n  pdwMaxSize (Stack+0x10): OUTPUT - Receives max packet size (100)\n\nReturns:\n  1 - Valid packet, class 1 (normal game packet, opcode < 100)\n  2 - Valid packet, class 0 (control packet)\n  3 - Incomplete data (need more bytes or invalid parse)\n  4 - Invalid packet (bad opcode range or oversized)\n\nPacket Classification:\n  Class 1: Opcode 0x00-0x63 (0-99) - Standard game packets\n  Class 2: Opcode 0x64-0x6D (100-109) - Extended game packets\n  Class 0: Opcode 0x6E+ or 0xFF - Control/system packets\n\nMagic Numbers:\n  0x6D (109): Maximum valid game packet opcode\n  0xFF (255): Special control packet marker\n  0x204 (516): Maximum allowed packet size\n  100 (0x64): Threshold for packet class determination",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:f91f85c4e85ea139100de7fa684c6668",
      "callees": {
        "LoD/1.07": [
          "NET_GetPacketSize"
        ],
        "LoD/1.08": [
          "NET_GetPacketSize"
        ],
        "LoD/1.09": [
          "NET_GetPacketSize"
        ],
        "LoD/1.09b": [
          "NET_GetPacketSize"
        ],
        "LoD/1.09d": [
          "NET_GetPacketSize"
        ]
      },
      "basic_block_counts": {
        "LoD/1.07": 17,
        "LoD/1.08": 17,
        "LoD/1.09": 17,
        "LoD/1.09b": 17,
        "LoD/1.09d": 17
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "f91f85c4e85ea139100de7fa684c6668",
        "LoD/1.08": "f91f85c4e85ea139100de7fa684c6668",
        "LoD/1.09": "f91f85c4e85ea139100de7fa684c6668",
        "LoD/1.09b": "f91f85c4e85ea139100de7fa684c6668",
        "LoD/1.09d": "f91f85c4e85ea139100de7fa684c6668"
      }
    },
    "d2net.dll_NET_SendAcknowledgeCallback": {
      "addresses": {
        "LoD/1.07": "0x6FC32070",
        "LoD/1.08": "0x6FC32070",
        "LoD/1.09": "0x6FC02070",
        "LoD/1.09b": "0x6FC02070",
        "LoD/1.09d": "0x6FC02070",
        "LoD/1.10": "0x6FC020B0"
      },
      "rvas": {
        "LoD/1.07": "0x2070",
        "LoD/1.08": "0x2070",
        "LoD/1.09": "0x2070",
        "LoD/1.09b": "0x2070",
        "LoD/1.09d": "0x2070",
        "LoD/1.10": "0x20B0"
      },
      "sizes": {
        "LoD/1.07": 35,
        "LoD/1.08": 35,
        "LoD/1.09": 35,
        "LoD/1.09b": 35,
        "LoD/1.09d": 35,
        "LoD/1.10": 35
      },
      "name": "NET_SendAcknowledgeCallback",
      "signature": "int NET_SendAcknowledgeCallback(dword dwUnused, byte * pbData)",
      "calling_convention": "__fastcall",
      "comment": "NET_SendAcknowledgeCallback - Network acknowledgment packet callback\n\nClassification: Callback - invoked by network subsystem\n\nAlgorithm:\n1. Allocate 2-byte buffer on stack\n2. Initialize buffer with packet type 0xA7 and value 0x01\n3. Call Ordinal_10006 (send packet function) with:\n   - param_1 = 0 (unused/broadcast)\n   - param_2 = pbData (ignored, we send our own packet)\n   - param_3 = stack buffer pointer\n   - param_4 = 2 (packet size)\n4. Return 1 (TRUE) indicating success\n\nParameters:\n  dwUnused (dword, ECX) - Unused parameter, passed as 0 to Ordinal_10006\n  pbData (byte *, EDX) - Pointer to incoming data (ignored in this callback)\n\nReturns:\n  int - Always returns 1 (TRUE) indicating successful acknowledgment sent\n\nSpecial Cases:\n  - Packet bytes [0xA7, 0x01] are a special packet type\n  - 0xA7 prefix bypasses Huffman encoding in Ordinal_10006\n\nNote: Function body is truncated in Ghidra disassembly (shows only PUSH ECX).\nFull assembly from memory inspection:\n  PUSH ECX               ; Save ECX, create stack space\n  LEA EAX, [ESP+0x2]     ; Get address of 2-byte stack buffer\n  PUSH 2                 ; Push packet size (2 bytes)\n  PUSH EAX               ; Push buffer pointer\n  PUSH EDX               ; Push pbData (becomes param_2)\n  PUSH 0                 ; Push 0 (becomes param_1)\n  MOV BYTE [ESP+0x12], 0xA7  ; Initialize buffer[0] = 0xA7\n  MOV BYTE [ESP+0x13], 0x01  ; Initialize buffer[1] = 0x01\n  CALL Ordinal_10006     ; Send the packet\n  MOV EAX, 1             ; Return TRUE\n  POP ECX                ; Restore ECX\n  RET 8                  ; Return, cleanup 8 bytes (stdcall-like)\n\nCalled by: Ordinal_10003 via InitializeNetworkContext callback registration",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:3b92469cae2e70bdd4896d5fd74d16ee",
      "callees": {
        "LoD/1.07": [
          "NET_SendDataPacket"
        ],
        "LoD/1.08": [
          "NET_SendDataPacket"
        ],
        "LoD/1.09": [
          "NET_SendDataPacket"
        ],
        "LoD/1.09b": [
          "NET_SendDataPacket"
        ],
        "LoD/1.09d": [
          "NET_SendDataPacket"
        ],
        "LoD/1.10": [
          "Ordinal_10006"
        ]
      },
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "3b92469cae2e70bdd4896d5fd74d16ee",
        "LoD/1.08": "3b92469cae2e70bdd4896d5fd74d16ee",
        "LoD/1.09": "3b92469cae2e70bdd4896d5fd74d16ee",
        "LoD/1.09b": "3b92469cae2e70bdd4896d5fd74d16ee",
        "LoD/1.09d": "3b92469cae2e70bdd4896d5fd74d16ee",
        "LoD/1.10": "3b92469cae2e70bdd4896d5fd74d16ee"
      }
    },
    "d2net.dll_NET_QueueReceivedMessageCallba": {
      "addresses": {
        "LoD/1.07": "0x6FC320A0",
        "LoD/1.08": "0x6FC320A0",
        "LoD/1.09": "0x6FC020A0",
        "LoD/1.09b": "0x6FC020A0",
        "LoD/1.09d": "0x6FC020A0",
        "LoD/1.10": "0x6FC020E0"
      },
      "rvas": {
        "LoD/1.07": "0x20A0",
        "LoD/1.08": "0x20A0",
        "LoD/1.09": "0x20A0",
        "LoD/1.09b": "0x20A0",
        "LoD/1.09d": "0x20A0",
        "LoD/1.10": "0x20E0"
      },
      "sizes": {
        "LoD/1.07": 35,
        "LoD/1.08": 35,
        "LoD/1.09": 35,
        "LoD/1.09b": 35,
        "LoD/1.09d": 35,
        "LoD/1.10": 35
      },
      "name": "NET_QueueReceivedMessageCallback",
      "signature": "int NET_QueueReceivedMessageCallback(byte * pbPacketData, dword dwDataSize)",
      "calling_convention": "__stdcall",
      "comment": "NET_QueueReceivedMessageCallback - Network message queue callback\n\nClassification: Callback - invoked by network subsystem when data is received\n\nAlgorithm:\n1. Load network context handle from g_dwNetSendCount global\n2. Build parameter block on stack with packet marker 0x6D\n3. Call QueueReceivedMessage to queue the received packet data\n4. Return 1 (TRUE) indicating successful queueing\n\nParameters:\n  pbPacketData (byte *, Stack+0x04): Pointer to received packet data buffer\n  dwDataSize (dword, Stack+0x08): Size of received data in bytes\n\nReturns:\n  int - Always returns 1 (TRUE) indicating successful message queueing\n\nNote: Function body is truncated in Ghidra disassembly (shows only PUSH ECX).\nFull assembly from memory inspection at 0x6fc320a0:\n  51              PUSH ECX            ; Save ECX, create stack space\n  8B 0D 30B2C36F  MOV ECX,[g_dwNetSendCount] ; Load network context\n  52              PUSH EDX            ; Save EDX\n  8D 44 24 07     LEA EAX,[ESP+0x7]   ; Calculate buffer address\n  6A 01           PUSH 1              ; Push flag parameter\n  50              PUSH EAX            ; Push buffer pointer\n  51              PUSH ECX            ; Push context handle\n  C6 44 24 13 6D  MOV [ESP+0x13],0x6D ; Set packet marker byte\n  E8 2C050000     CALL QueueReceivedMessage\n  B8 01000000     MOV EAX,1           ; Set return value TRUE\n  59              POP ECX             ; Restore ECX\n  C2 08 00        RET 8               ; Return, cleanup 8 bytes (stdcall)\n\nMagic Numbers:\n  0x6D (109): Packet type marker byte for received message queueing\n  1: Success return value\n\nCalled by: Ordinal_10003 via InitializeNetworkContext callback registration\n  - Registered as 7th parameter to InitializeNetworkContext\n  - Called when network layer has received data to process",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:57348ed67585737a7cbf807de1511fa6",
      "callees": {
        "LoD/1.07": [
          "QueueReceivedMessage"
        ],
        "LoD/1.08": [
          "QueueReceivedMessage"
        ],
        "LoD/1.09": [
          "QueueReceivedMessage"
        ],
        "LoD/1.09b": [
          "QueueReceivedMessage"
        ],
        "LoD/1.09d": [
          "Ordinal_10175"
        ],
        "LoD/1.10": [
          "Ordinal_10175"
        ]
      },
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "57348ed67585737a7cbf807de1511fa6",
        "LoD/1.08": "57348ed67585737a7cbf807de1511fa6",
        "LoD/1.09": "57348ed67585737a7cbf807de1511fa6",
        "LoD/1.09b": "57348ed67585737a7cbf807de1511fa6",
        "LoD/1.09d": "57348ed67585737a7cbf807de1511fa6",
        "LoD/1.10": "57348ed67585737a7cbf807de1511fa6"
      }
    },
    "d2net.dll_D2Net_NotifyServerMode": {
      "addresses": {
        "LoD/1.07": "0x6FC320D0",
        "LoD/1.08": "0x6FC320D0",
        "LoD/1.09": "0x6FC020D0",
        "LoD/1.09b": "0x6FC020D0",
        "LoD/1.09d": "0x6FC020D0",
        "LoD/1.10": "0x6FC02110"
      },
      "rvas": {
        "LoD/1.07": "0x20D0",
        "LoD/1.08": "0x20D0",
        "LoD/1.09": "0x20D0",
        "LoD/1.09b": "0x20D0",
        "LoD/1.09d": "0x20D0",
        "LoD/1.10": "0x2110"
      },
      "sizes": {
        "LoD/1.07": 29,
        "LoD/1.08": 29,
        "LoD/1.09": 29,
        "LoD/1.09b": 29,
        "LoD/1.09d": 29,
        "LoD/1.10": 29
      },
      "name": "D2Net_NotifyServerMode",
      "signature": "void D2Net_NotifyServerMode(USHORT wServerMode)",
      "calling_convention": "__fastcall",
      "comment": "D2Net Server Mode Notification (Ordinal 10001)\n\nSends a 2-byte server mode notification packet to the network layer.\nCalled by D2Net_InitializeClient when running in server mode (types 1 or 2).\n\nClassification: Wrapper / Notification\n\nAlgorithm:\n1. Build 4-byte packet on stack with format: [wServerMode:2][0xA7][0x00]\n2. Call Ordinal_10006 to send raw packet (bypasses Huffman encoding due to 0xA7 marker)\n3. Return immediately (fire-and-forget notification)\n\nParameters:\n  wServerMode (USHORT, CX) - Server mode value passed from caller's network type.\n    Typically the low 16 bits of dwNetworkType from D2Net_InitializeClient.\n\nReturns:\n  void - No return value; notification is fire-and-forget.\n\nPacket Format:\n  Offset  Size  Field         Value\n  0x00    2     wServerMode   Parameter value (server mode identifier)\n  0x02    1     bPacketType   0xA7 (raw packet marker, skips Huffman encoding)\n  0x03    1     bPadding      0x00 (null terminator/padding)\n\nCallees:\n  Ordinal_10006 @ 0x6fc32270 - D2Net packet send function\n    When first byte is 0xA7, packet is sent raw without Huffman encoding.\n    Args: (0, NULL, &packet[2], 2) - sends 2 bytes starting at offset +2\n\nMagic Numbers:\n  0xA7 - Raw packet marker; tells Ordinal_10006 to skip Huffman encoding\n  2    - Packet size sent to Ordinal_10006\n\nCallers:\n  D2Net_InitializeClient @ 0x6fc311b0 - Called when network type indicates server mode\n\nStack Frame:\n  ESP-4: 4-byte packet buffer (uStack_4)\n    [ESP+0]: wServerMode (2 bytes)\n    [ESP+2]: 0xA7 (1 byte) - packet type marker\n    [ESP+3]: 0x00 (1 byte) - padding",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:3b6b6cb5c08de46e31bd42782faffbb3",
      "callees": {
        "LoD/1.07": [
          "NET_SendDataPacket"
        ],
        "LoD/1.08": [
          "NET_SendDataPacket"
        ],
        "LoD/1.09": [
          "NET_SendDataPacket"
        ],
        "LoD/1.09b": [
          "NET_SendDataPacket"
        ],
        "LoD/1.09d": [
          "NET_SendDataPacket"
        ],
        "LoD/1.10": [
          "Ordinal_10006"
        ]
      },
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "3b6b6cb5c08de46e31bd42782faffbb3",
        "LoD/1.08": "3b6b6cb5c08de46e31bd42782faffbb3",
        "LoD/1.09": "3b6b6cb5c08de46e31bd42782faffbb3",
        "LoD/1.09b": "3b6b6cb5c08de46e31bd42782faffbb3",
        "LoD/1.09d": "3b6b6cb5c08de46e31bd42782faffbb3",
        "LoD/1.10": "3b6b6cb5c08de46e31bd42782faffbb3"
      }
    },
    "d2net.dll_NET_WaitForSendEvent": {
      "addresses": {
        "LoD/1.07": "0x6FC320F0",
        "LoD/1.08": "0x6FC320F0",
        "LoD/1.09": "0x6FC02190",
        "LoD/1.09b": "0x6FC02190",
        "LoD/1.09d": "0x6FC024A0",
        "LoD/1.10": "0x6FC02200",
        "LoD/1.11": "0x6FBF6240",
        "LoD/1.11b": "0x6FBF61B0",
        "LoD/1.12a": "0x6FBF73B0",
        "LoD/1.13c": "0x6FBF6250",
        "LoD/1.13d": "0x6FBF71E0"
      },
      "rvas": {
        "LoD/1.07": "0x20F0",
        "LoD/1.08": "0x20F0",
        "LoD/1.09": "0x2190",
        "LoD/1.09b": "0x2190",
        "LoD/1.09d": "0x24A0",
        "LoD/1.10": "0x2200",
        "LoD/1.11": "0x6240",
        "LoD/1.11b": "0x61B0",
        "LoD/1.12a": "0x73B0",
        "LoD/1.13c": "0x6250",
        "LoD/1.13d": "0x71E0"
      },
      "sizes": {
        "LoD/1.07": 20,
        "LoD/1.08": 20,
        "LoD/1.09": 20,
        "LoD/1.09b": 20,
        "LoD/1.09d": 20,
        "LoD/1.10": 20,
        "LoD/1.11": 20,
        "LoD/1.11b": 20,
        "LoD/1.12a": 20,
        "LoD/1.13c": 20,
        "LoD/1.13d": 20
      },
      "name": "NET_WaitForSendEvent",
      "signature": "DWORD NET_WaitForSendEvent(DWORD dwTimeoutMs)",
      "calling_convention": "__stdcall",
      "comment": "Waits for network send operation to complete or timeout.\n\nPublic API wrapper (Ordinal 10002) that blocks the calling thread until\na network send event is signaled or the specified timeout elapses.\n\nAlgorithm:\n1. Load global network send event handle from g_dwNetSendCount\n2. Forward call to WaitForArchiveEvent with handle and timeout\n3. Return wait result to caller\n\nParameters:\n  dwTimeoutMs [in] - Wait timeout in milliseconds. Use INFINITE (0xFFFFFFFF)\n                     for indefinite wait.\n\nReturns:\n  DWORD - Wait result from WaitForArchiveEvent:\n    WAIT_OBJECT_0 (0) - Send event was signaled\n    WAIT_TIMEOUT (258) - Timeout elapsed before event signaled\n    WAIT_FAILED (0xFFFFFFFF) - Error occurred\n\nSpecial Cases:\n  - If g_dwNetSendCount is not initialized, behavior is undefined\n  - Timeout of 0 performs a non-blocking check\n\nRelated:\n  - Ordinal_10003: Initializes g_dwNetSendCount\n  - Ordinal_10004: Gets/sets send count state",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:0c7249cc723d27c36926c4cb05e7aa15",
      "callees": {
        "LoD/1.07": [
          "WaitForArchiveEvent"
        ],
        "LoD/1.08": [
          "WaitForArchiveEvent"
        ],
        "LoD/1.09": [
          "SetArchivePriority"
        ],
        "LoD/1.09b": [
          "SetArchivePriority"
        ],
        "LoD/1.09d": [
          "Ordinal_10171"
        ],
        "LoD/1.10": [
          "SetFieldBD0"
        ],
        "LoD/1.11": [
          "WaitOnObjectHandle"
        ],
        "LoD/1.11b": [
          "WriteValueToOffset0xBD0"
        ],
        "LoD/1.12a": [
          "WaitOnObjectHandle"
        ],
        "LoD/1.13c": [
          "SetGameObjectProperty"
        ],
        "LoD/1.13d": [
          "SearchHashTableEntry"
        ]
      },
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1,
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "0c7249cc723d27c36926c4cb05e7aa15",
        "LoD/1.08": "0c7249cc723d27c36926c4cb05e7aa15",
        "LoD/1.09": "0c7249cc723d27c36926c4cb05e7aa15",
        "LoD/1.09b": "0c7249cc723d27c36926c4cb05e7aa15",
        "LoD/1.09d": "0c7249cc723d27c36926c4cb05e7aa15",
        "LoD/1.10": "0c7249cc723d27c36926c4cb05e7aa15",
        "LoD/1.11": "0c7249cc723d27c36926c4cb05e7aa15",
        "LoD/1.11b": "0c7249cc723d27c36926c4cb05e7aa15",
        "LoD/1.12a": "0c7249cc723d27c36926c4cb05e7aa15",
        "LoD/1.13c": "0c7249cc723d27c36926c4cb05e7aa15",
        "LoD/1.13d": "0c7249cc723d27c36926c4cb05e7aa15"
      }
    },
    "d2net.dll_NET_InitializeClientContext": {
      "addresses": {
        "LoD/1.07": "0x6FC32110",
        "LoD/1.08": "0x6FC32110",
        "LoD/1.09": "0x6FC02110",
        "LoD/1.09b": "0x6FC02110",
        "LoD/1.09d": "0x6FC02110",
        "LoD/1.10": "0x6FC02150",
        "LoD/1.11": "0x6FBF6520",
        "LoD/1.11b": "0x6FBF6520",
        "LoD/1.12a": "0x6FBF7690",
        "LoD/1.13c": "0x6FBF6590",
        "LoD/1.13d": "0x6FBF7620"
      },
      "rvas": {
        "LoD/1.07": "0x2110",
        "LoD/1.08": "0x2110",
        "LoD/1.09": "0x2110",
        "LoD/1.09b": "0x2110",
        "LoD/1.09d": "0x2110",
        "LoD/1.10": "0x2150",
        "LoD/1.11": "0x6520",
        "LoD/1.11b": "0x6520",
        "LoD/1.12a": "0x7690",
        "LoD/1.13c": "0x6590",
        "LoD/1.13d": "0x7620"
      },
      "sizes": {
        "LoD/1.07": 50,
        "LoD/1.08": 50,
        "LoD/1.09": 50,
        "LoD/1.09b": 50,
        "LoD/1.09d": 50,
        "LoD/1.10": 50,
        "LoD/1.11": 50,
        "LoD/1.11b": 50,
        "LoD/1.12a": 50,
        "LoD/1.13c": 50,
        "LoD/1.13d": 50
      },
      "name": "NET_InitializeClientContext",
      "signature": "void NET_InitializeClientContext(int nNetworkMode, int nUseWinNT)",
      "calling_convention": "__stdcall",
      "comment": "Initializes the network client context with predefined callbacks.\n\nClassification: Initialization / Public API (Ordinal 10003)\n\nAlgorithm:\n1. Load nUseWinNT parameter from stack [ESP+0x8] into EAX\n2. Load nNetworkMode parameter from stack [ESP+0x4] into ECX\n3. Push callback function pointers in reverse order:\n   - NET_QueueShutdownCallback (0x6fc31f80) - handles send queue shutdown\n   - NET_QueueReceivedMessageCallback (0x6fc320a0) - handles incoming messages\n   - NET_SendAcknowledgeCallback (0x6fc32070) - handles send acknowledgements\n   - NET_ValidateClientPacket (0x6fc31fa0) - validates incoming packets\n4. Push nUseWinNT (EAX) - Windows NT network API flag\n5. Push port number 0xfa0 (4000) - hardcoded network port\n6. Push max connections value 3 - hardcoded connection limit\n7. Push nNetworkMode (ECX) - network mode selector\n8. Call InitializeNetworkContext with 8 parameters\n9. Store returned context handle in g_dwNetSendCount global\n10. Return (cleanup 8 bytes via RET 0x8)\n\nParameters:\n  nNetworkMode (int) - Network mode selector passed to InitializeNetworkContext\n  nUseWinNT (int) - Flag indicating whether to use Windows NT network APIs\n\nReturns:\n  void - Result stored in g_dwNetSendCount global\n\nCallbacks Registered:\n  NET_ValidateClientPacket - Validates and parses incoming packet data\n  NET_SendAcknowledgeCallback - Handles send acknowledgement processing\n  NET_QueueReceivedMessageCallback - Queues received messages for processing\n  NET_QueueShutdownCallback - Handles network shutdown/cleanup\n\nMagic Numbers:\n  0xfa0 (4000) - Default network port number\n  3 - Maximum concurrent connections\n\nGlobal State Modified:\n  g_dwNetSendCount (0x6fc3b230) - Stores network context handle/counter",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:6e27217d4e1042877a85c7ff189e2274",
      "callees": {
        "LoD/1.07": [
          "InitializeNetworkContext"
        ],
        "LoD/1.08": [
          "InitializeNetworkContext"
        ],
        "LoD/1.09": [
          "InitializeNetworkContext"
        ],
        "LoD/1.09b": [
          "InitializeNetworkContext"
        ],
        "LoD/1.09d": [
          "Ordinal_10149"
        ],
        "LoD/1.10": [
          "Ordinal_10149"
        ],
        "LoD/1.11": [
          "Ordinal_10149"
        ],
        "LoD/1.11b": [
          "InitializeGameSession"
        ],
        "LoD/1.12a": [
          "InitializeGameSession"
        ],
        "LoD/1.13c": [
          "InitializeGameSession"
        ],
        "LoD/1.13d": [
          "InitializeGameSession"
        ]
      },
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1,
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "6e27217d4e1042877a85c7ff189e2274",
        "LoD/1.08": "6e27217d4e1042877a85c7ff189e2274",
        "LoD/1.09": "6e27217d4e1042877a85c7ff189e2274",
        "LoD/1.09b": "6e27217d4e1042877a85c7ff189e2274",
        "LoD/1.09d": "6e27217d4e1042877a85c7ff189e2274",
        "LoD/1.10": "6e27217d4e1042877a85c7ff189e2274",
        "LoD/1.11": "6e27217d4e1042877a85c7ff189e2274",
        "LoD/1.11b": "6e27217d4e1042877a85c7ff189e2274",
        "LoD/1.12a": "6e27217d4e1042877a85c7ff189e2274",
        "LoD/1.13c": "6e27217d4e1042877a85c7ff189e2274",
        "LoD/1.13d": "6e27217d4e1042877a85c7ff189e2274"
      }
    },
    "d2net.dll_NET_ExchangeClientContextValue": {
      "addresses": {
        "LoD/1.07": "0x6FC32150",
        "LoD/1.08": "0x6FC32150",
        "LoD/1.09": "0x6FC02150",
        "LoD/1.09b": "0x6FC02150",
        "LoD/1.09d": "0x6FC02150",
        "LoD/1.10": "0x6FC02190",
        "LoD/1.11": "0x6FBF6220",
        "LoD/1.11b": "0x6FBF6220",
        "LoD/1.12a": "0x6FBF7390",
        "LoD/1.13c": "0x6FBF6290",
        "LoD/1.13d": "0x6FBF7320"
      },
      "rvas": {
        "LoD/1.07": "0x2150",
        "LoD/1.08": "0x2150",
        "LoD/1.09": "0x2150",
        "LoD/1.09b": "0x2150",
        "LoD/1.09d": "0x2150",
        "LoD/1.10": "0x2190",
        "LoD/1.11": "0x6220",
        "LoD/1.11b": "0x6220",
        "LoD/1.12a": "0x7390",
        "LoD/1.13c": "0x6290",
        "LoD/1.13d": "0x7320"
      },
      "sizes": {
        "LoD/1.07": 25,
        "LoD/1.08": 25,
        "LoD/1.09": 25,
        "LoD/1.09b": 25,
        "LoD/1.09d": 25,
        "LoD/1.10": 25,
        "LoD/1.11": 25,
        "LoD/1.11b": 25,
        "LoD/1.12a": 25,
        "LoD/1.13c": 25,
        "LoD/1.13d": 25
      },
      "name": "NET_ExchangeClientContextValue",
      "signature": "dword NET_ExchangeClientContextValue(int nFieldIndex, dword dwNewValue)",
      "calling_convention": "__stdcall",
      "comment": "Atomically exchanges a value in the network client context structure.\n\nOrdinal: 10035\nClassification: Thunk/Wrapper - wraps ExchangeStructArrayValue with g_pNetClientContext\n\nAlgorithm:\n1. Load dwNewValue from stack [ESP+0x8]\n2. Load nFieldIndex from stack [ESP+0x4]\n3. Load g_pNetClientContext base pointer from 0x6fc3b230\n4. Call ExchangeStructArrayValue(pContext, nFieldIndex, dwNewValue)\n5. Return exchanged value (previous value at field index)\n\nParameters:\n  nFieldIndex - int: Field offset/index within the client context structure\n  dwNewValue - dword: New value to store at the specified field\n\nReturns:\n  dword - Previous value at the field index before exchange (atomic swap)\n\nGlobal Dependencies:\n  g_pNetClientContext (0x6fc3b230) - Pointer to network client context structure\n    Initialized by NET_InitializeClientContext\n    Used by NET_SendDataPacket, NET_WaitForSendEvent, and other ordinal exports\n\nRelated Functions:\n  Ordinal_10036: Similar exchange wrapper (likely different field set)\n  Ordinal_10026-10034: Other client context accessor wrappers\n\nNotes:\n  This is a public API ordinal export providing atomic field exchange for\n  the network client context. The InterlockedExchange semantics ensure\n  thread-safe access to shared network state.",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:c898a7914d62b6cd004bb1dc557654ba",
      "callees": {
        "LoD/1.07": [
          "ExchangeStructArrayValue"
        ],
        "LoD/1.08": [
          "ExchangeStructArrayValue"
        ],
        "LoD/1.09": [
          "ExchangeStructArrayValue"
        ],
        "LoD/1.09b": [
          "ExchangeStructArrayValue"
        ],
        "LoD/1.09d": [
          "Ordinal_10186"
        ],
        "LoD/1.10": [
          "ExchangeStructArrayValue"
        ],
        "LoD/1.11": [
          "GetOrSetArrayElement"
        ],
        "LoD/1.11b": [
          "GetOrSetArrayElement"
        ],
        "LoD/1.12a": [
          "GetOrSetArrayElement"
        ],
        "LoD/1.13c": [
          "GetOrSetArrayElement"
        ],
        "LoD/1.13d": [
          "GetOrSetArrayElement"
        ]
      },
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1,
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "c898a7914d62b6cd004bb1dc557654ba",
        "LoD/1.08": "c898a7914d62b6cd004bb1dc557654ba",
        "LoD/1.09": "c898a7914d62b6cd004bb1dc557654ba",
        "LoD/1.09b": "c898a7914d62b6cd004bb1dc557654ba",
        "LoD/1.09d": "c898a7914d62b6cd004bb1dc557654ba",
        "LoD/1.10": "c898a7914d62b6cd004bb1dc557654ba",
        "LoD/1.11": "c898a7914d62b6cd004bb1dc557654ba",
        "LoD/1.11b": "c898a7914d62b6cd004bb1dc557654ba",
        "LoD/1.12a": "c898a7914d62b6cd004bb1dc557654ba",
        "LoD/1.13c": "c898a7914d62b6cd004bb1dc557654ba",
        "LoD/1.13d": "c898a7914d62b6cd004bb1dc557654ba"
      }
    },
    "d2net.dll_NET_AddUniqueKeyValuePair": {
      "addresses": {
        "LoD/1.07": "0x6FC32170",
        "LoD/1.08": "0x6FC32170",
        "LoD/1.09": "0x6FC02170",
        "LoD/1.09b": "0x6FC02170",
        "LoD/1.09d": "0x6FC02170",
        "LoD/1.10": "0x6FC021B0",
        "LoD/1.11": "0x6FBF6200",
        "LoD/1.11b": "0x6FBF6200",
        "LoD/1.12a": "0x6FBF7370",
        "LoD/1.13c": "0x6FBF6270",
        "LoD/1.13d": "0x6FBF7300"
      },
      "rvas": {
        "LoD/1.07": "0x2170",
        "LoD/1.08": "0x2170",
        "LoD/1.09": "0x2170",
        "LoD/1.09b": "0x2170",
        "LoD/1.09d": "0x2170",
        "LoD/1.10": "0x21B0",
        "LoD/1.11": "0x6200",
        "LoD/1.11b": "0x6200",
        "LoD/1.12a": "0x7370",
        "LoD/1.13c": "0x6270",
        "LoD/1.13d": "0x7300"
      },
      "sizes": {
        "LoD/1.07": 23,
        "LoD/1.08": 23,
        "LoD/1.09": 23,
        "LoD/1.09b": 23,
        "LoD/1.09d": 23,
        "LoD/1.10": 23,
        "LoD/1.11": 23,
        "LoD/1.11b": 23,
        "LoD/1.12a": 23,
        "LoD/1.13c": 23,
        "LoD/1.13d": 23
      },
      "name": "NET_AddUniqueKeyValuePair",
      "signature": "void NET_AddUniqueKeyValuePair(uint dwValue, int nKey)",
      "calling_convention": "__stdcall",
      "comment": "Adds a unique key-value pair to the network client context container.\n\nORDINAL: 10036\n\nAlgorithm:\n1. Load dwValue from first stack parameter\n2. Load nKey from second stack parameter  \n3. Load g_dwNetSendCount (client context pointer) into ECX\n4. Call AddUniqueKeyValuePair(pContainer, dwValue, nKey) via __fastcall thunk\n\nParameters:\n  dwValue (uint) - Value to associate with the key\n  nKey (int) - Unique key identifier for the value pair\n  IMPLICIT: ECX receives g_dwNetSendCount (client context pointer)\n\nReturns:\n  void - No return value\n\nGlobal References:\n  g_dwNetSendCount @ 0x6fc3b230 - Pointer to network client context container\n\nCalled Functions:\n  AddUniqueKeyValuePair @ 0x6fc325fe - Jump thunk to container insertion routine\n\nClassification: Thunk/Wrapper - Thin export wrapper providing __stdcall interface\nto internal __fastcall AddUniqueKeyValuePair with implicit container parameter.",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:de821c8832e2dd4b9c7f141c0654226f",
      "callees": {
        "LoD/1.07": [
          "AddUniqueKeyValuePair"
        ],
        "LoD/1.08": [
          "AddUniqueKeyValuePair"
        ],
        "LoD/1.09": [
          "AddUniqueKeyValuePair"
        ],
        "LoD/1.09b": [
          "AddUniqueKeyValuePair"
        ],
        "LoD/1.09d": [
          "AddUniqueKeyValuePair"
        ],
        "LoD/1.10": [
          "AddUniqueKeyValuePair"
        ],
        "LoD/1.11": [
          "RegisterSlotIfUnique"
        ],
        "LoD/1.11b": [
          "RegisterSlotIfUnique"
        ],
        "LoD/1.12a": [
          "RegisterSlotIfUnique"
        ],
        "LoD/1.13c": [
          "RegisterSlotIfUnique"
        ],
        "LoD/1.13d": [
          "RegisterSlotIfUnique"
        ]
      },
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1,
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "de821c8832e2dd4b9c7f141c0654226f",
        "LoD/1.08": "de821c8832e2dd4b9c7f141c0654226f",
        "LoD/1.09": "de821c8832e2dd4b9c7f141c0654226f",
        "LoD/1.09b": "de821c8832e2dd4b9c7f141c0654226f",
        "LoD/1.09d": "de821c8832e2dd4b9c7f141c0654226f",
        "LoD/1.10": "de821c8832e2dd4b9c7f141c0654226f",
        "LoD/1.11": "de821c8832e2dd4b9c7f141c0654226f",
        "LoD/1.11b": "de821c8832e2dd4b9c7f141c0654226f",
        "LoD/1.12a": "de821c8832e2dd4b9c7f141c0654226f",
        "LoD/1.13c": "de821c8832e2dd4b9c7f141c0654226f",
        "LoD/1.13d": "de821c8832e2dd4b9c7f141c0654226f"
      }
    },
    "d2net.dll_NET_SetArchivePriority": {
      "addresses": {
        "LoD/1.07": "0x6FC32190",
        "LoD/1.08": "0x6FC32190",
        "LoD/1.09": "0x6FC024A0",
        "LoD/1.09b": "0x6FC024A0",
        "LoD/1.09d": "0x6FC021C0",
        "LoD/1.10": "0x6FC02450",
        "LoD/1.11": "0x6FBF61E0",
        "LoD/1.11b": "0x6FBF5FE0",
        "LoD/1.12a": "0x6FBF7250",
        "LoD/1.13c": "0x6FBF5F40",
        "LoD/1.13d": "0x6FBF72B0"
      },
      "rvas": {
        "LoD/1.07": "0x2190",
        "LoD/1.08": "0x2190",
        "LoD/1.09": "0x24A0",
        "LoD/1.09b": "0x24A0",
        "LoD/1.09d": "0x21C0",
        "LoD/1.10": "0x2450",
        "LoD/1.11": "0x61E0",
        "LoD/1.11b": "0x5FE0",
        "LoD/1.12a": "0x7250",
        "LoD/1.13c": "0x5F40",
        "LoD/1.13d": "0x72B0"
      },
      "sizes": {
        "LoD/1.07": 20,
        "LoD/1.08": 20,
        "LoD/1.09": 20,
        "LoD/1.09b": 20,
        "LoD/1.09d": 20,
        "LoD/1.10": 20,
        "LoD/1.11": 20,
        "LoD/1.11b": 20,
        "LoD/1.12a": 20,
        "LoD/1.13c": 20,
        "LoD/1.13d": 20
      },
      "name": "NET_SetArchivePriority",
      "signature": "void NET_SetArchivePriority(dword dwPriority)",
      "calling_convention": "__stdcall",
      "comment": "Sets the priority level for the global network context archive.\n\nClassification: Thunk/Wrapper - Passes global network context and priority to SetArchivePriority import.\n\nAlgorithm:\n1. Load dwPriority parameter from stack [ESP+0x4]\n2. Load g_pNetworkContext global pointer from 0x6fc3b230\n3. Call SetArchivePriority(g_pNetworkContext, dwPriority)\n4. Return (stdcall - callee cleans 4 bytes)\n\nParameters:\n  dwPriority (uint) - Priority level to set for the network archive context\n\nReturns:\n  void - No return value\n\nCaller Context:\n  Exported as ordinal 10026. No internal callers detected - intended for external module use.\n\nNotes:\n  - g_pNetworkContext is shared across NET_* functions and multiple ordinal exports\n  - SetArchivePriority is imported from external DLL (ordinal 0x0f)\n  - Simple pass-through wrapper exposing archive priority control to external callers",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:0c7249cc723d27c36926c4cb05e7aa15",
      "callees": {
        "LoD/1.07": [
          "SetArchivePriority"
        ],
        "LoD/1.08": [
          "SetArchivePriority"
        ],
        "LoD/1.09": [
          "SetStructField0xBBC"
        ],
        "LoD/1.09b": [
          "SetStructField0xBBC"
        ],
        "LoD/1.09d": [
          "Ordinal_10178"
        ],
        "LoD/1.10": [
          "Ordinal_10161"
        ],
        "LoD/1.11": [
          "SetGameObjectProperty"
        ],
        "LoD/1.11b": [
          "SetUnitFieldBBC"
        ],
        "LoD/1.12a": [
          "SearchHashTableEntry"
        ],
        "LoD/1.13c": [
          "WaitOrProcessContextSlots"
        ],
        "LoD/1.13d": [
          "WriteValueToOffset0xBD0"
        ]
      },
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1,
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "0c7249cc723d27c36926c4cb05e7aa15",
        "LoD/1.08": "0c7249cc723d27c36926c4cb05e7aa15",
        "LoD/1.09": "0c7249cc723d27c36926c4cb05e7aa15",
        "LoD/1.09b": "0c7249cc723d27c36926c4cb05e7aa15",
        "LoD/1.09d": "0c7249cc723d27c36926c4cb05e7aa15",
        "LoD/1.10": "0c7249cc723d27c36926c4cb05e7aa15",
        "LoD/1.11": "0c7249cc723d27c36926c4cb05e7aa15",
        "LoD/1.11b": "0c7249cc723d27c36926c4cb05e7aa15",
        "LoD/1.12a": "0c7249cc723d27c36926c4cb05e7aa15",
        "LoD/1.13c": "0c7249cc723d27c36926c4cb05e7aa15",
        "LoD/1.13d": "0c7249cc723d27c36926c4cb05e7aa15"
      }
    },
    "d2net.dll_NET_GetContextField880": {
      "addresses": {
        "LoD/1.07": "0x6FC321B0",
        "LoD/1.08": "0x6FC321B0",
        "LoD/1.09": "0x6FC021B0",
        "LoD/1.09b": "0x6FC021B0",
        "LoD/1.09d": "0x6FC021B0",
        "LoD/1.10": "0x6FC02610",
        "LoD/1.11": "0x6FBF61D0",
        "LoD/1.11b": "0x6FBF61D0",
        "LoD/1.12a": "0x6FBF7030",
        "LoD/1.13c": "0x6FBF5F30",
        "LoD/1.13d": "0x6FBF6FC0"
      },
      "rvas": {
        "LoD/1.07": "0x21B0",
        "LoD/1.08": "0x21B0",
        "LoD/1.09": "0x21B0",
        "LoD/1.09b": "0x21B0",
        "LoD/1.09d": "0x21B0",
        "LoD/1.10": "0x2610",
        "LoD/1.11": "0x61D0",
        "LoD/1.11b": "0x61D0",
        "LoD/1.12a": "0x7030",
        "LoD/1.13c": "0x5F30",
        "LoD/1.13d": "0x6FC0"
      },
      "sizes": {
        "LoD/1.07": 12,
        "LoD/1.08": 12,
        "LoD/1.09": 12,
        "LoD/1.09b": 12,
        "LoD/1.09d": 12,
        "LoD/1.10": 12,
        "LoD/1.11": 12,
        "LoD/1.11b": 12,
        "LoD/1.12a": 12,
        "LoD/1.13c": 12,
        "LoD/1.13d": 12
      },
      "name": "NET_GetContextField880",
      "signature": "int NET_GetContextField880(void)",
      "calling_convention": "__stdcall",
      "comment": "Retrieves field at offset 0x880 from the global network context structure.\n\nClassification: Thunk/Wrapper (Public API - Ordinal 10027)\n\nAlgorithm:\n1. Load g_pNetworkContext global pointer into EAX\n2. Push EAX as parameter to GetField880\n3. Call FOG.GetField880 to retrieve field value at offset 0x880\n4. Return result in EAX\n\nParameters:\n  None\n\nReturns:\n  int - Value of field at offset 0x880 in the network context structure.\n        Actual semantics depend on FOG.DLL's network context layout.\n\nExternal Calls:\n  GetField880 (FOG.DLL) - Retrieves dword value at offset 0x880 from structure\n\nGlobal State Read:\n  g_pNetworkContext (0x6fc3b230) - Pointer to network context structure\n\nNotes:\n  This is a simple accessor thunk providing public API access to an internal\n  network context field. The specific purpose of field 0x880 is defined by\n  FOG.DLL's network context structure layout.",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:5acea7b093442b4d0fe7bb124f1c8b51",
      "callees": {
        "LoD/1.07": [
          "GetField880"
        ],
        "LoD/1.08": [
          "GetEntityFieldAt0x880"
        ],
        "LoD/1.09": [
          "GetEntityFieldAt0x880"
        ],
        "LoD/1.09b": [
          "GetEntityFieldAt0x880"
        ],
        "LoD/1.09d": [
          "GetEntityFieldAt0x880"
        ],
        "LoD/1.10": [
          "DoNothingStub"
        ],
        "LoD/1.11": [
          "GetEntityFieldAt0x880"
        ],
        "LoD/1.11b": [
          "GetEntityFieldAt0x880"
        ],
        "LoD/1.12a": [
          "DoNothingStub"
        ],
        "LoD/1.13c": [
          "DoNothingStub"
        ],
        "LoD/1.13d": [
          "DoNothingStub"
        ]
      },
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1,
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "5acea7b093442b4d0fe7bb124f1c8b51",
        "LoD/1.08": "5acea7b093442b4d0fe7bb124f1c8b51",
        "LoD/1.09": "5acea7b093442b4d0fe7bb124f1c8b51",
        "LoD/1.09b": "5acea7b093442b4d0fe7bb124f1c8b51",
        "LoD/1.09d": "5acea7b093442b4d0fe7bb124f1c8b51",
        "LoD/1.10": "5acea7b093442b4d0fe7bb124f1c8b51",
        "LoD/1.11": "5acea7b093442b4d0fe7bb124f1c8b51",
        "LoD/1.11b": "5acea7b093442b4d0fe7bb124f1c8b51",
        "LoD/1.12a": "5acea7b093442b4d0fe7bb124f1c8b51",
        "LoD/1.13c": "5acea7b093442b4d0fe7bb124f1c8b51",
        "LoD/1.13d": "5acea7b093442b4d0fe7bb124f1c8b51"
      }
    },
    "d2net.dll_NET_SetContextFieldBD0": {
      "addresses": {
        "LoD/1.07": "0x6FC321C0",
        "LoD/1.08": "0x6FC321C0",
        "LoD/1.09": "0x6FC020F0",
        "LoD/1.09b": "0x6FC020F0",
        "LoD/1.09d": "0x6FC02190",
        "LoD/1.10": "0x6FC02430",
        "LoD/1.11": "0x6FBF60E0",
        "LoD/1.11b": "0x6FBF60E0",
        "LoD/1.12a": "0x6FBF7320",
        "LoD/1.13c": "0x6FBF6050",
        "LoD/1.13d": "0x6FBF7340"
      },
      "rvas": {
        "LoD/1.07": "0x21C0",
        "LoD/1.08": "0x21C0",
        "LoD/1.09": "0x20F0",
        "LoD/1.09b": "0x20F0",
        "LoD/1.09d": "0x2190",
        "LoD/1.10": "0x2430",
        "LoD/1.11": "0x60E0",
        "LoD/1.11b": "0x60E0",
        "LoD/1.12a": "0x7320",
        "LoD/1.13c": "0x6050",
        "LoD/1.13d": "0x7340"
      },
      "sizes": {
        "LoD/1.07": 20,
        "LoD/1.08": 20,
        "LoD/1.09": 20,
        "LoD/1.09b": 20,
        "LoD/1.09d": 20,
        "LoD/1.10": 20,
        "LoD/1.11": 20,
        "LoD/1.11b": 20,
        "LoD/1.12a": 20,
        "LoD/1.13c": 20,
        "LoD/1.13d": 20
      },
      "name": "NET_SetContextFieldBD0",
      "signature": "void NET_SetContextFieldBD0(dword dwValue)",
      "calling_convention": "__stdcall",
      "comment": "Sets field at offset 0xBD0 in the global network context structure.\n\nClassification: Thunk/Wrapper (Public API - Ordinal 10023)\n\nAlgorithm:\n1. Load dwValue parameter from stack [ESP + 0x4]\n2. Load g_pNetworkContext global pointer from 0x6fc3b230\n3. Push dwValue and g_pNetworkContext as parameters\n4. Call FOG.SetFieldBD0 to store value at offset 0xBD0\n5. Return (stack cleaned by callee, __stdcall)\n\nParameters:\n  dwValue (dword) - Value to store at offset 0xBD0 in the network context.\n                    Actual semantics depend on FOG.DLL's network context layout.\n\nReturns:\n  void - No return value\n\nExternal Calls:\n  SetFieldBD0 (FOG.DLL via jump table at 0x6fc37040) - Stores dword value at offset 0xBD0\n\nGlobal State Read:\n  g_pNetworkContext (0x6fc3b230) - Pointer to network context structure\n\nNotes:\n  This is a simple setter thunk providing public API access to an internal\n  network context field. The specific purpose of field 0xBD0 is defined by\n  FOG.DLL's network context structure layout. Companion getter may exist\n  for reading this field.",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:0c7249cc723d27c36926c4cb05e7aa15",
      "callees": {
        "LoD/1.07": [
          "SetFieldBD0"
        ],
        "LoD/1.08": [
          "SetFieldBD0"
        ],
        "LoD/1.09": [
          "WaitForArchiveEvent"
        ],
        "LoD/1.09b": [
          "WaitForArchiveEvent"
        ],
        "LoD/1.09d": [
          "Ordinal_10151"
        ],
        "LoD/1.10": [
          "Ordinal_10158"
        ],
        "LoD/1.11": [
          "SearchHashTableEntry"
        ],
        "LoD/1.11b": [
          "SearchHashTableEntry"
        ],
        "LoD/1.12a": [
          "WriteValueToOffset0xBD0"
        ],
        "LoD/1.13c": [
          "SetUnitFieldBBC"
        ],
        "LoD/1.13d": [
          "WaitOnObjectHandle"
        ]
      },
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1,
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "0c7249cc723d27c36926c4cb05e7aa15",
        "LoD/1.08": "0c7249cc723d27c36926c4cb05e7aa15",
        "LoD/1.09": "0c7249cc723d27c36926c4cb05e7aa15",
        "LoD/1.09b": "0c7249cc723d27c36926c4cb05e7aa15",
        "LoD/1.09d": "0c7249cc723d27c36926c4cb05e7aa15",
        "LoD/1.10": "0c7249cc723d27c36926c4cb05e7aa15",
        "LoD/1.11": "0c7249cc723d27c36926c4cb05e7aa15",
        "LoD/1.11b": "0c7249cc723d27c36926c4cb05e7aa15",
        "LoD/1.12a": "0c7249cc723d27c36926c4cb05e7aa15",
        "LoD/1.13c": "0c7249cc723d27c36926c4cb05e7aa15",
        "LoD/1.13d": "0c7249cc723d27c36926c4cb05e7aa15"
      }
    },
    "d2net.dll_NET_ShutdownGlobalContext": {
      "addresses": {
        "LoD/1.07": "0x6FC321E0",
        "LoD/1.08": "0x6FC321E0",
        "LoD/1.09": "0x6FC021E0",
        "LoD/1.09b": "0x6FC021E0",
        "LoD/1.09d": "0x6FC021E0",
        "LoD/1.10": "0x6FC02220"
      },
      "rvas": {
        "LoD/1.07": "0x21E0",
        "LoD/1.08": "0x21E0",
        "LoD/1.09": "0x21E0",
        "LoD/1.09b": "0x21E0",
        "LoD/1.09d": "0x21E0",
        "LoD/1.10": "0x2220"
      },
      "sizes": {
        "LoD/1.07": 37,
        "LoD/1.08": 37,
        "LoD/1.09": 37,
        "LoD/1.09b": 37,
        "LoD/1.09d": 37,
        "LoD/1.10": 37
      },
      "name": "NET_ShutdownGlobalContext",
      "signature": "void NET_ShutdownGlobalContext(void)",
      "calling_convention": "__stdcall",
      "comment": "Shuts down and releases the global network context.\n\nExported as Ordinal 10004 - Public API for network cleanup.\n\nAlgorithm:\n1. Load the global network context pointer (g_pNetworkContext)\n2. Prepare a stack-based output buffer for shutdown status\n3. Set magic marker byte 0xA8 in the output buffer (shutdown identifier)\n4. Call ShutdownNetworkContext with context pointer, output buffer, and flag=1\n5. Clear g_pNetworkContext to NULL to prevent further use\n\nParameters:\n  None\n\nReturns:\n  void\n\nSpecial Cases:\n  - Must be called during application shutdown to release network resources\n  - The magic marker 0xA8 distinguishes this shutdown path from other cleanup modes\n  - After this call, g_pNetworkContext is NULL; other NET_* functions will fail\n\nMemory Model:\n  - Releases ownership of network context allocated by NET_InitializeClientContext\n  - Output buffer is stack-allocated, lifetime limited to this call\n  - g_pNetworkContext ownership transferred to ShutdownNetworkContext for cleanup\n\nCross-References:\n  - g_pNetworkContext: Global pointer initialized by NET_InitializeClientContext\n  - ShutdownNetworkContext: Performs actual teardown of network state",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:5e221f547b29198455c421e030bc75c0",
      "callees": {
        "LoD/1.07": [
          "ShutdownNetworkContext"
        ],
        "LoD/1.08": [
          "ShutdownNetworkContext"
        ],
        "LoD/1.09": [
          "ShutdownNetworkContext"
        ],
        "LoD/1.09b": [
          "ShutdownNetworkContext"
        ],
        "LoD/1.09d": [
          "Ordinal_10152"
        ],
        "LoD/1.10": [
          "Ordinal_10152"
        ]
      },
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "5e221f547b29198455c421e030bc75c0",
        "LoD/1.08": "5e221f547b29198455c421e030bc75c0",
        "LoD/1.09": "5e221f547b29198455c421e030bc75c0",
        "LoD/1.09b": "5e221f547b29198455c421e030bc75c0",
        "LoD/1.09d": "5e221f547b29198455c421e030bc75c0",
        "LoD/1.10": "5e221f547b29198455c421e030bc75c0"
      }
    },
    "d2net.dll_NET_ReceiveHighPriorityPacket": {
      "addresses": {
        "LoD/1.07": "0x6FC32210",
        "LoD/1.08": "0x6FC32210",
        "LoD/1.09": "0x6FC02210",
        "LoD/1.09b": "0x6FC02210",
        "LoD/1.09d": "0x6FC02210",
        "LoD/1.10": "0x6FC02250",
        "LoD/1.11": "0x6FBF6160",
        "LoD/1.11b": "0x6FBF6160",
        "LoD/1.12a": "0x6FBF72D0",
        "LoD/1.13c": "0x6FBF61D0",
        "LoD/1.13d": "0x6FBF7260"
      },
      "rvas": {
        "LoD/1.07": "0x2210",
        "LoD/1.08": "0x2210",
        "LoD/1.09": "0x2210",
        "LoD/1.09b": "0x2210",
        "LoD/1.09d": "0x2210",
        "LoD/1.10": "0x2250",
        "LoD/1.11": "0x6160",
        "LoD/1.11b": "0x6160",
        "LoD/1.12a": "0x72D0",
        "LoD/1.13c": "0x61D0",
        "LoD/1.13d": "0x7260"
      },
      "sizes": {
        "LoD/1.07": 27,
        "LoD/1.08": 27,
        "LoD/1.09": 27,
        "LoD/1.09b": 27,
        "LoD/1.09d": 27,
        "LoD/1.10": 27,
        "LoD/1.11": 27,
        "LoD/1.11b": 27,
        "LoD/1.12a": 27,
        "LoD/1.13c": 27,
        "LoD/1.13d": 27
      },
      "name": "NET_ReceiveHighPriorityPacket",
      "signature": "void NET_ReceiveHighPriorityPacket(byte * pbDestBuf, uint dwMaxSize)",
      "calling_convention": "__stdcall",
      "comment": "Receives high-priority network packet data from the global network context queue.\n\nClassification: Thunk/Wrapper - Wraps DequeueBufferAndCopy with fixed priority=1.\n\nAlgorithm:\n1. Load global network context pointer (g_pNetworkContext at 0x6fc3b230)\n2. Call DequeueBufferAndCopy with priority=1 (high priority queue)\n3. Copy dequeued data to caller's buffer up to dwMaxSize bytes\n\nParameters:\n  pbDestBuf  - byte *  - Destination buffer to receive packet data\n  dwMaxSize  - uint    - Maximum bytes to copy into destination buffer\n\nReturns:\n  void - No return value; data copied directly to pbDestBuf\n\nRelated Functions:\n  Ordinal_10011 (NET_ReceiveNormalPriorityPacket) - priority 0\n  Ordinal_10012 (NET_ReceiveLowPriorityPacket)    - priority 2\n\nPriority Levels:\n  0 = Normal priority (default game traffic)\n  1 = High priority (time-critical packets)\n  2 = Low priority (bulk/background data)\n\nGlobal Dependencies:\n  g_pNetworkContext (0x6fc3b230) - Network manager context pointer",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:fdbdac7cf379b9ff67380e3628f4513d",
      "callees": {
        "LoD/1.07": [
          "DequeueBufferAndCopy"
        ],
        "LoD/1.08": [
          "DequeueBufferAndCopy"
        ],
        "LoD/1.09": [
          "DequeueBufferAndCopy"
        ],
        "LoD/1.09b": [
          "DequeueBufferAndCopy"
        ],
        "LoD/1.09d": [
          "Ordinal_10156"
        ],
        "LoD/1.10": [
          "Ordinal_10156"
        ],
        "LoD/1.11": [
          "RemoveAndCopyPoolElement"
        ],
        "LoD/1.11b": [
          "RemoveAndCopyPoolElement"
        ],
        "LoD/1.12a": [
          "RemoveAndCopyPoolElement"
        ],
        "LoD/1.13c": [
          "RemoveAndCopyPoolElement"
        ],
        "LoD/1.13d": [
          "RemoveAndCopyPoolElement"
        ]
      },
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1,
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "fdbdac7cf379b9ff67380e3628f4513d",
        "LoD/1.08": "fdbdac7cf379b9ff67380e3628f4513d",
        "LoD/1.09": "fdbdac7cf379b9ff67380e3628f4513d",
        "LoD/1.09b": "fdbdac7cf379b9ff67380e3628f4513d",
        "LoD/1.09d": "fdbdac7cf379b9ff67380e3628f4513d",
        "LoD/1.10": "fdbdac7cf379b9ff67380e3628f4513d",
        "LoD/1.11": "fdbdac7cf379b9ff67380e3628f4513d",
        "LoD/1.11b": "fdbdac7cf379b9ff67380e3628f4513d",
        "LoD/1.12a": "fdbdac7cf379b9ff67380e3628f4513d",
        "LoD/1.13c": "fdbdac7cf379b9ff67380e3628f4513d",
        "LoD/1.13d": "fdbdac7cf379b9ff67380e3628f4513d"
      }
    },
    "d2net.dll_NET_DequeueBufferAndCopy": {
      "addresses": {
        "LoD/1.07": "0x6FC32230",
        "LoD/1.08": "0x6FC32230",
        "LoD/1.09": "0x6FC02230",
        "LoD/1.09b": "0x6FC02230",
        "LoD/1.09d": "0x6FC02230",
        "LoD/1.10": "0x6FC02270",
        "LoD/1.11": "0x6FBF6140",
        "LoD/1.11b": "0x6FBF6140",
        "LoD/1.12a": "0x6FBF72B0",
        "LoD/1.13c": "0x6FBF61B0",
        "LoD/1.13d": "0x6FBF7240"
      },
      "rvas": {
        "LoD/1.07": "0x2230",
        "LoD/1.08": "0x2230",
        "LoD/1.09": "0x2230",
        "LoD/1.09b": "0x2230",
        "LoD/1.09d": "0x2230",
        "LoD/1.10": "0x2270",
        "LoD/1.11": "0x6140",
        "LoD/1.11b": "0x6140",
        "LoD/1.12a": "0x72B0",
        "LoD/1.13c": "0x61B0",
        "LoD/1.13d": "0x7240"
      },
      "sizes": {
        "LoD/1.07": 27,
        "LoD/1.08": 27,
        "LoD/1.09": 27,
        "LoD/1.09b": 27,
        "LoD/1.09d": 27,
        "LoD/1.10": 27,
        "LoD/1.11": 27,
        "LoD/1.11b": 27,
        "LoD/1.12a": 27,
        "LoD/1.13c": 27,
        "LoD/1.13d": 27
      },
      "name": "NET_DequeueBufferAndCopy",
      "signature": "dword NET_DequeueBufferAndCopy(byte * pbDestBuf, dword dwMaxSize)",
      "calling_convention": "__stdcall",
      "comment": "Dequeues data from the network receive buffer into the destination buffer.\n\nWrapper function that calls DequeueBufferAndCopy using the global network context\n(g_pNetworkContext) with priority 0 (default/normal priority).\n\nClassification: Thunk/Wrapper - wraps DequeueBufferAndCopy with implicit context\n\nAlgorithm:\n1. Load destination buffer pointer (pbDestBuf) from stack [ESP+0x4]\n2. Load maximum size (dwMaxSize) from stack [ESP+0x8]\n3. Load global network context pointer from g_pNetworkContext (0x6fc3b230)\n4. Push parameters in reverse order: dwMaxSize, pbDestBuf, 0 (priority), pManager\n5. Call DequeueBufferAndCopy(g_pNetworkContext, 0, pbDestBuf, dwMaxSize)\n6. Return result from DequeueBufferAndCopy (in EAX)\n7. Clean up 8 bytes from stack (RET 0x8)\n\nParameters:\n  pbDestBuf  [byte *] - Pointer to destination buffer to receive dequeued data\n  dwMaxSize  [dword]  - Maximum number of bytes to copy into destination buffer\n  IMPLICIT: g_pNetworkContext (0x6fc3b230) - Global network manager context\n\nReturns:\n  dword - Number of bytes copied to destination buffer, or 0 if no data available\n\nGlobal References:\n  g_pNetworkContext (0x6fc3b230) - Pointer to network manager context structure\n\nRelated Functions:\n  DequeueBufferAndCopy - Internal implementation that performs actual dequeue\n  NET_InitializeClientContext - Initializes g_pNetworkContext\n  NET_SendDataPacket - Uses same g_pNetworkContext for sending",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:fdbdac7cf379b9ff67380e3628f4513d",
      "callees": {
        "LoD/1.07": [
          "DequeueBufferAndCopy"
        ],
        "LoD/1.08": [
          "DequeueBufferAndCopy"
        ],
        "LoD/1.09": [
          "DequeueBufferAndCopy"
        ],
        "LoD/1.09b": [
          "DequeueBufferAndCopy"
        ],
        "LoD/1.09d": [
          "Ordinal_10156"
        ],
        "LoD/1.10": [
          "Ordinal_10156"
        ],
        "LoD/1.11": [
          "RemoveAndCopyPoolElement"
        ],
        "LoD/1.11b": [
          "RemoveAndCopyPoolElement"
        ],
        "LoD/1.12a": [
          "RemoveAndCopyPoolElement"
        ],
        "LoD/1.13c": [
          "RemoveAndCopyPoolElement"
        ],
        "LoD/1.13d": [
          "RemoveAndCopyPoolElement"
        ]
      },
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1,
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "fdbdac7cf379b9ff67380e3628f4513d",
        "LoD/1.08": "fdbdac7cf379b9ff67380e3628f4513d",
        "LoD/1.09": "fdbdac7cf379b9ff67380e3628f4513d",
        "LoD/1.09b": "fdbdac7cf379b9ff67380e3628f4513d",
        "LoD/1.09d": "fdbdac7cf379b9ff67380e3628f4513d",
        "LoD/1.10": "fdbdac7cf379b9ff67380e3628f4513d",
        "LoD/1.11": "fdbdac7cf379b9ff67380e3628f4513d",
        "LoD/1.11b": "fdbdac7cf379b9ff67380e3628f4513d",
        "LoD/1.12a": "fdbdac7cf379b9ff67380e3628f4513d",
        "LoD/1.13c": "fdbdac7cf379b9ff67380e3628f4513d",
        "LoD/1.13d": "fdbdac7cf379b9ff67380e3628f4513d"
      }
    },
    "d2net.dll_NET_DequeueBufferMediumPriorit": {
      "addresses": {
        "LoD/1.07": "0x6FC32250",
        "LoD/1.08": "0x6FC32250",
        "LoD/1.09": "0x6FC02250",
        "LoD/1.09b": "0x6FC02250",
        "LoD/1.09d": "0x6FC02250",
        "LoD/1.10": "0x6FC02290",
        "LoD/1.11": "0x6FBF6120",
        "LoD/1.11b": "0x6FBF6120",
        "LoD/1.12a": "0x6FBF7290",
        "LoD/1.13c": "0x6FBF6190",
        "LoD/1.13d": "0x6FBF7220"
      },
      "rvas": {
        "LoD/1.07": "0x2250",
        "LoD/1.08": "0x2250",
        "LoD/1.09": "0x2250",
        "LoD/1.09b": "0x2250",
        "LoD/1.09d": "0x2250",
        "LoD/1.10": "0x2290",
        "LoD/1.11": "0x6120",
        "LoD/1.11b": "0x6120",
        "LoD/1.12a": "0x7290",
        "LoD/1.13c": "0x6190",
        "LoD/1.13d": "0x7220"
      },
      "sizes": {
        "LoD/1.07": 27,
        "LoD/1.08": 27,
        "LoD/1.09": 27,
        "LoD/1.09b": 27,
        "LoD/1.09d": 27,
        "LoD/1.10": 27,
        "LoD/1.11": 27,
        "LoD/1.11b": 27,
        "LoD/1.12a": 27,
        "LoD/1.13c": 27,
        "LoD/1.13d": 27
      },
      "name": "NET_DequeueBufferMediumPriority",
      "signature": "dword NET_DequeueBufferMediumPriority(byte * pbDestBuf, dword dwMaxSize)",
      "calling_convention": "__stdcall",
      "comment": "Dequeues data from the medium-priority network receive queue.\n\nWrapper function (Thunk) for DequeueBufferAndCopy using priority level 2 (medium).\nRelated functions: NET_DequeueBufferAndCopy (ordinal 10011) uses priority 0 (high).\n\nAlgorithm:\n1. Load global network context pointer from g_pNetworkContext\n2. Call DequeueBufferAndCopy with priority=2, destination buffer, and max size\n3. Return bytes copied (0 if queue empty or error)\n\nParameters:\n  pbDestBuf  - byte * - Destination buffer to receive packet data\n  dwMaxSize  - dword  - Maximum bytes to copy into destination buffer\n\nReturns:\n  dword - Number of bytes copied to pbDestBuf, or 0 if no data available\n\nSpecial Cases:\n  Returns 0 if network context is NULL or queue is empty\n  Priority 2 indicates medium-priority network traffic queue\n\nMagic Numbers:\n  0x2 - Priority level for medium-priority receive queue\n  g_pNetworkContext at 0x6fc3b230 - Global network manager instance",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:fdbdac7cf379b9ff67380e3628f4513d",
      "callees": {
        "LoD/1.07": [
          "DequeueBufferAndCopy"
        ],
        "LoD/1.08": [
          "DequeueBufferAndCopy"
        ],
        "LoD/1.09": [
          "DequeueBufferAndCopy"
        ],
        "LoD/1.09b": [
          "DequeueBufferAndCopy"
        ],
        "LoD/1.09d": [
          "Ordinal_10156"
        ],
        "LoD/1.10": [
          "Ordinal_10156"
        ],
        "LoD/1.11": [
          "RemoveAndCopyPoolElement"
        ],
        "LoD/1.11b": [
          "RemoveAndCopyPoolElement"
        ],
        "LoD/1.12a": [
          "RemoveAndCopyPoolElement"
        ],
        "LoD/1.13c": [
          "RemoveAndCopyPoolElement"
        ],
        "LoD/1.13d": [
          "RemoveAndCopyPoolElement"
        ]
      },
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1,
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "fdbdac7cf379b9ff67380e3628f4513d",
        "LoD/1.08": "fdbdac7cf379b9ff67380e3628f4513d",
        "LoD/1.09": "fdbdac7cf379b9ff67380e3628f4513d",
        "LoD/1.09b": "fdbdac7cf379b9ff67380e3628f4513d",
        "LoD/1.09d": "fdbdac7cf379b9ff67380e3628f4513d",
        "LoD/1.10": "fdbdac7cf379b9ff67380e3628f4513d",
        "LoD/1.11": "fdbdac7cf379b9ff67380e3628f4513d",
        "LoD/1.11b": "fdbdac7cf379b9ff67380e3628f4513d",
        "LoD/1.12a": "fdbdac7cf379b9ff67380e3628f4513d",
        "LoD/1.13c": "fdbdac7cf379b9ff67380e3628f4513d",
        "LoD/1.13d": "fdbdac7cf379b9ff67380e3628f4513d"
      }
    },
    "d2net.dll_NET_SendDataPacket": {
      "addresses": {
        "LoD/1.07": "0x6FC32270",
        "LoD/1.08": "0x6FC32270",
        "LoD/1.09": "0x6FC02270",
        "LoD/1.09b": "0x6FC02270",
        "LoD/1.09d": "0x6FC02270",
        "LoD/1.10": "0x6FC022B0"
      },
      "rvas": {
        "LoD/1.07": "0x2270",
        "LoD/1.08": "0x2270",
        "LoD/1.09": "0x2270",
        "LoD/1.09b": "0x2270",
        "LoD/1.09d": "0x2270",
        "LoD/1.10": "0x22B0"
      },
      "sizes": {
        "LoD/1.07": 327,
        "LoD/1.08": 327,
        "LoD/1.09": 327,
        "LoD/1.09b": 327,
        "LoD/1.09d": 327,
        "LoD/1.10": 344
      },
      "name": "NET_SendDataPacket",
      "signature": "dword NET_SendDataPacket(dword nClientId, byte * pbPacketData, dword nCompressionMode, dword nPacketLen)",
      "calling_convention": "__stdcall",
      "comment": "Sends a data packet to a client, optionally compressing it with Huffman encoding.\n\nOrdinal: 10006\n\nAlgorithm:\n1. Validate packet length does not exceed MAX_MSG_SIZE (0x204 = 516 bytes)\n2. If shutting down, queue packet for later transmission and return success\n3. If compression mode is non-zero OR first byte is not 0xA7 (uncompressed marker):\n   a. Update Huffman statistics for the packet data\n   b. If compression mode is not 2 (raw mode):\n      - Compress packet using Huffman encoding into stack buffer\n      - Assert compression produced non-zero output\n      - If compressed size + 1 < 0xF0 (240):\n        * Prepend 1-byte length header and send\n      - Else:\n        * Prepend 2-byte length header (high nibble 0xF0) and send\n4. Otherwise send packet data uncompressed via SendClientData\n\nParameters:\n  nClientId [Stack+0x4] - Client identifier for routing\n  pbPacketData [Stack+0x8] - Pointer to packet data buffer\n  nCompressionMode [Stack+0xC] - Compression mode (0=check first byte, 2=raw, other=compress)\n  nPacketLen [Stack+0x10] - Length of packet data in bytes\n\nReturns:\n  1 - Packet queued during shutdown\n  Result from SendClientData on success/failure\n\nSpecial Cases:\n  - Packet size > 516 triggers assertion and error exit\n  - Compression output size 0 triggers assertion\n  - Large compressed packets (>=240 bytes) use 2-byte length encoding\n\nMagic Numbers:\n  0x204 - MAX_MSG_SIZE (516 bytes maximum packet length)\n  0xA7 - Uncompressed packet marker byte\n  0x408 - Compression buffer size (1032 bytes)\n  0xF0 - Threshold for 2-byte length encoding (240)\n  0x14A - Source line 330 (length validation)\n  0x166 - Source line 358 (compression size validation)\n\nStack Frame:\n  ESP+0x0C to ESP+0x413 - Compression output buffer (1032 bytes)\n  ESP+0x0D - 1-byte length field for small packets\n  ESP+0x0C - 2-byte length field for large packets",
      "name_source": "LoD/1.07",
      "method": "STR",
      "index": "STR:1ee2c20a3383d9e2dea7fa6574cb7166",
      "callees": {
        "LoD/1.07": [
          "FogAssert",
          "UpdateHuffmanStatistics",
          "DecodeHuffmanData",
          "FogAssert",
          "SendClientData",
          "SendClientData",
          "SendClientData"
        ],
        "LoD/1.08": [
          "FogAssert",
          "UpdateHuffmanStatistics",
          "DecodeHuffmanData",
          "FogAssert",
          "SendClientData",
          "SendClientData",
          "SendClientData"
        ],
        "LoD/1.09": [
          "FogAssert",
          "UpdateHuffmanStatistics",
          "DecodeHuffmanData",
          "FogAssert",
          "SendClientData",
          "SendClientData",
          "SendClientData"
        ],
        "LoD/1.09b": [
          "FogAssert",
          "UpdateHuffmanStatistics",
          "DecodeHuffmanData",
          "FogAssert",
          "SendClientData",
          "SendClientData",
          "SendClientData"
        ],
        "LoD/1.09d": [
          "FogAssert",
          "UpdateHuffmanStatistics",
          "DecodeHuffmanData",
          "FogAssert",
          "Ordinal_10157",
          "Ordinal_10157",
          "Ordinal_10157"
        ],
        "LoD/1.10": [
          "FogAssert",
          "Ordinal_10222",
          "Ordinal_10223",
          "FogAssert",
          "Ordinal_10157",
          "Ordinal_10157",
          "Ordinal_10157"
        ]
      },
      "strings": {
        "LoD/1.07": [
          "\"nLen <= MAX_MSG_SIZE\"",
          "\"size != 0\"",
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2Net\\\\SRC\\\\Server..."
        ],
        "LoD/1.08": [
          "\"nLen <= MAX_MSG_SIZE\"",
          "\"size != 0\"",
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2Net\\\\SRC\\\\Server..."
        ],
        "LoD/1.09": [
          "\"nLen <= MAX_MSG_SIZE\"",
          "\"size != 0\"",
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2Net\\\\SRC\\\\Server..."
        ],
        "LoD/1.09b": [
          "\"nLen <= MAX_MSG_SIZE\"",
          "\"size != 0\"",
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2Net\\\\SRC\\\\Server..."
        ],
        "LoD/1.09d": [
          "\"nLen <= MAX_MSG_SIZE\"",
          "\"size != 0\"",
          "\"C:\\\\Src\\\\Diablo2\\\\Source\\\\D2Net\\\\SRC\\\\Server.cpp\""
        ],
        "LoD/1.10": [
          "\"C:\\\\projects\\\\D2\\\\head\\\\Diablo2\\\\Source\\\\D2Net\\\\S...",
          "\"nLen <= MAX_MSG_SIZE\"",
          "\"size != 0\""
        ]
      },
      "basic_block_counts": {
        "LoD/1.07": 13,
        "LoD/1.08": 13,
        "LoD/1.09": 13,
        "LoD/1.09b": 13,
        "LoD/1.09d": 13,
        "LoD/1.10": 13
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "54a7d40c116aec57f542ee36647048b8",
        "LoD/1.08": "54a7d40c116aec57f542ee36647048b8",
        "LoD/1.09": "54a7d40c116aec57f542ee36647048b8",
        "LoD/1.09b": "54a7d40c116aec57f542ee36647048b8",
        "LoD/1.09d": "54a7d40c116aec57f542ee36647048b8",
        "LoD/1.10": "da34f25e8d5d0559668fa24dd0cdaf91"
      }
    },
    "d2net.dll_NET_GetPeerIPAddressByID": {
      "addresses": {
        "LoD/1.07": "0x6FC323C0",
        "LoD/1.08": "0x6FC323C0",
        "LoD/1.09": "0x6FC023E0",
        "LoD/1.09b": "0x6FC023C0",
        "LoD/1.09d": "0x6FC02440",
        "LoD/1.10": "0x6FC024D0",
        "LoD/1.11": "0x6FBF6040",
        "LoD/1.11b": "0x6FBF6060",
        "LoD/1.12a": "0x6FBF71D0",
        "LoD/1.13c": "0x6FBF60D0",
        "LoD/1.13d": "0x6FBF7140"
      },
      "rvas": {
        "LoD/1.07": "0x23C0",
        "LoD/1.08": "0x23C0",
        "LoD/1.09": "0x23E0",
        "LoD/1.09b": "0x23C0",
        "LoD/1.09d": "0x2440",
        "LoD/1.10": "0x24D0",
        "LoD/1.11": "0x6040",
        "LoD/1.11b": "0x6060",
        "LoD/1.12a": "0x71D0",
        "LoD/1.13c": "0x60D0",
        "LoD/1.13d": "0x7140"
      },
      "sizes": {
        "LoD/1.07": 29,
        "LoD/1.08": 29,
        "LoD/1.09": 29,
        "LoD/1.09b": 29,
        "LoD/1.09d": 29,
        "LoD/1.10": 29,
        "LoD/1.11": 29,
        "LoD/1.11b": 29,
        "LoD/1.12a": 29,
        "LoD/1.13c": 29,
        "LoD/1.13d": 29
      },
      "name": "NET_GetPeerIPAddressByID",
      "signature": "void NET_GetPeerIPAddressByID(uint dwPeerID, char * szIPBuffer, uint dwBufferSize)",
      "calling_convention": "__stdcall",
      "comment": "Exported wrapper that retrieves the IP address string for a connected peer by ID.\n\nClassification: Thunk/Wrapper - forwards call to internal GetPeerIPAddressByID with global context.\n\nAlgorithm:\n1. Load dwBufferSize from stack [ESP+0xC]\n2. Load szIPBuffer pointer from stack [ESP+0x8]\n3. Load dwPeerID from stack [ESP+0x4]\n4. Load g_pNetworkContext (FogHashTable*) from global 0x6fc3b230\n5. Push all four parameters and call GetPeerIPAddressByID\n6. Return (stdcall cleans 12 bytes from stack)\n\nParameters:\n  dwPeerID     - uint, peer identifier to look up in network context hash table\n  szIPBuffer   - char*, output buffer to receive null-terminated IP address string\n  dwBufferSize - uint, size of szIPBuffer in bytes\n\nReturns: void (IP string written to szIPBuffer if peer found)\n\nWraps: GetPeerIPAddressByID(g_pNetworkContext, dwPeerID, szIPBuffer, dwBufferSize)\n\nGlobal Dependencies:\n  g_pNetworkContext (0x6fc3b230) - FogHashTable* initialized by NET_InitializeClientContext",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:ad7ceb3ac6ae530901e650af4923938e",
      "callees": {
        "LoD/1.07": [
          "GetPeerIPAddressByID"
        ],
        "LoD/1.08": [
          "GetPeerIPAddressByID"
        ],
        "LoD/1.09": [
          "DisconnectClientAndBlock"
        ],
        "LoD/1.09b": [
          "GetPeerIPAddressByID"
        ],
        "LoD/1.09d": [
          "Ordinal_10166"
        ],
        "LoD/1.10": [
          "Ordinal_10166"
        ],
        "LoD/1.11": [
          "DisconnectSocketByIP"
        ],
        "LoD/1.11b": [
          "UnlistHackedIP"
        ],
        "LoD/1.12a": [
          "UnlistHackedIP"
        ],
        "LoD/1.13c": [
          "UnlistHackedIP"
        ],
        "LoD/1.13d": [
          "DisconnectSocketByIP"
        ]
      },
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1,
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "ad7ceb3ac6ae530901e650af4923938e",
        "LoD/1.08": "ad7ceb3ac6ae530901e650af4923938e",
        "LoD/1.09": "ad7ceb3ac6ae530901e650af4923938e",
        "LoD/1.09b": "ad7ceb3ac6ae530901e650af4923938e",
        "LoD/1.09d": "ad7ceb3ac6ae530901e650af4923938e",
        "LoD/1.10": "ad7ceb3ac6ae530901e650af4923938e",
        "LoD/1.11": "ad7ceb3ac6ae530901e650af4923938e",
        "LoD/1.11b": "ad7ceb3ac6ae530901e650af4923938e",
        "LoD/1.12a": "ad7ceb3ac6ae530901e650af4923938e",
        "LoD/1.13c": "ad7ceb3ac6ae530901e650af4923938e",
        "LoD/1.13d": "ad7ceb3ac6ae530901e650af4923938e"
      }
    },
    "d2net.dll_NET_DisconnectClientAndBlock": {
      "addresses": {
        "LoD/1.07": "0x6FC323E0",
        "LoD/1.08": "0x6FC32440",
        "LoD/1.09": "0x6FC02420",
        "LoD/1.09b": "0x6FC02440",
        "LoD/1.09d": "0x6FC02400",
        "LoD/1.10": "0x6FC02410",
        "LoD/1.11": "0x6FBF6100",
        "LoD/1.11b": "0x6FBF60A0",
        "LoD/1.12a": "0x6FBF7210",
        "LoD/1.13c": "0x6FBF60F0",
        "LoD/1.13d": "0x6FBF7180"
      },
      "rvas": {
        "LoD/1.07": "0x23E0",
        "LoD/1.08": "0x2440",
        "LoD/1.09": "0x2420",
        "LoD/1.09b": "0x2440",
        "LoD/1.09d": "0x2400",
        "LoD/1.10": "0x2410",
        "LoD/1.11": "0x6100",
        "LoD/1.11b": "0x60A0",
        "LoD/1.12a": "0x7210",
        "LoD/1.13c": "0x60F0",
        "LoD/1.13d": "0x7180"
      },
      "sizes": {
        "LoD/1.07": 29,
        "LoD/1.08": 29,
        "LoD/1.09": 29,
        "LoD/1.09b": 29,
        "LoD/1.09d": 29,
        "LoD/1.10": 29,
        "LoD/1.11": 29,
        "LoD/1.11b": 29,
        "LoD/1.12a": 29,
        "LoD/1.13c": 29,
        "LoD/1.13d": 29
      },
      "name": "NET_DisconnectClientAndBlock",
      "signature": "void NET_DisconnectClientAndBlock(uint dwClientId, uint dwReason, uint dwBlockDuration)",
      "calling_convention": "__stdcall",
      "comment": "Disconnect a client from the server and optionally block reconnection.\n\nOrdinal: 10015\nClassification: Thunk/Wrapper - wraps DisconnectClientAndBlock with global network context\n\nAlgorithm:\n1. Load dwBlockDuration from stack [ESP+0xC]\n2. Load dwReason from stack [ESP+0x8]\n3. Load dwClientId from stack [ESP+0x4]\n4. Load g_pNetworkContext global pointer\n5. Call DisconnectClientAndBlock(g_pNetworkContext, dwClientId, dwReason, dwBlockDuration)\n6. Return (stack cleanup via RET 0xC)\n\nParameters:\n  dwClientId - Client identifier to disconnect\n  dwReason - Reason code for disconnection\n  dwBlockDuration - Duration to block client reconnection (0 = no block)\n\nReturns: void\n\nWraps: DisconnectClientAndBlock with implicit g_pNetworkContext parameter",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:ad7ceb3ac6ae530901e650af4923938e",
      "callees": {
        "LoD/1.07": [
          "DisconnectClientAndBlock"
        ],
        "LoD/1.08": [
          "RemoveClientByIpAddress"
        ],
        "LoD/1.09": [
          "UnlistIPFromHackList"
        ],
        "LoD/1.09b": [
          "RemoveClientByIpAddress"
        ],
        "LoD/1.09d": [
          "Ordinal_10163"
        ],
        "LoD/1.10": [
          "Ordinal_10159"
        ],
        "LoD/1.11": [
          "SearchHashTableForNetworkAddress"
        ],
        "LoD/1.11b": [
          "ProcessAndTrackSocketAddress"
        ],
        "LoD/1.12a": [
          "ProcessAndTrackSocketAddress"
        ],
        "LoD/1.13c": [
          "ProcessNetworkAddressTracking"
        ],
        "LoD/1.13d": [
          "ProcessNetworkAddressTracking"
        ]
      },
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1,
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "ad7ceb3ac6ae530901e650af4923938e",
        "LoD/1.08": "ad7ceb3ac6ae530901e650af4923938e",
        "LoD/1.09": "ad7ceb3ac6ae530901e650af4923938e",
        "LoD/1.09b": "ad7ceb3ac6ae530901e650af4923938e",
        "LoD/1.09d": "ad7ceb3ac6ae530901e650af4923938e",
        "LoD/1.10": "ad7ceb3ac6ae530901e650af4923938e",
        "LoD/1.11": "ad7ceb3ac6ae530901e650af4923938e",
        "LoD/1.11b": "ad7ceb3ac6ae530901e650af4923938e",
        "LoD/1.12a": "ad7ceb3ac6ae530901e650af4923938e",
        "LoD/1.13c": "ad7ceb3ac6ae530901e650af4923938e",
        "LoD/1.13d": "ad7ceb3ac6ae530901e650af4923938e"
      }
    },
    "d2net.dll_SNET_DisconnectClientByAddress": {
      "addresses": {
        "LoD/1.07": "0x6FC32400",
        "LoD/1.08": "0x6FC32420",
        "LoD/1.09": "0x6FC02440",
        "LoD/1.09b": "0x6FC02420",
        "LoD/1.09d": "0x6FC02420",
        "LoD/1.10": "0x6FC02470",
        "LoD/1.11": "0x6FBF6080",
        "LoD/1.11b": "0x6FBF6100",
        "LoD/1.12a": "0x6FBF71F0",
        "LoD/1.13c": "0x6FBF6110",
        "LoD/1.13d": "0x6FBF7200"
      },
      "rvas": {
        "LoD/1.07": "0x2400",
        "LoD/1.08": "0x2420",
        "LoD/1.09": "0x2440",
        "LoD/1.09b": "0x2420",
        "LoD/1.09d": "0x2420",
        "LoD/1.10": "0x2470",
        "LoD/1.11": "0x6080",
        "LoD/1.11b": "0x6100",
        "LoD/1.12a": "0x71F0",
        "LoD/1.13c": "0x6110",
        "LoD/1.13d": "0x7200"
      },
      "sizes": {
        "LoD/1.07": 29,
        "LoD/1.08": 29,
        "LoD/1.09": 29,
        "LoD/1.09b": 29,
        "LoD/1.09d": 29,
        "LoD/1.10": 29,
        "LoD/1.11": 29,
        "LoD/1.11b": 29,
        "LoD/1.12a": 29,
        "LoD/1.13c": 29,
        "LoD/1.13d": 29
      },
      "name": "SNET_DisconnectClientByAddress",
      "signature": "void SNET_DisconnectClientByAddress(uint dwClientAddr, uint dwUnused, uint dwBlockDuration)",
      "calling_convention": "__stdcall",
      "comment": "SNET_DisconnectClientByAddress - Exported ordinal wrapper for client disconnection\n\nThunk function exposing DisconnectClientByAddress to external callers via ordinal export.\nPasses the global network context (g_pNetworkContext) as the first parameter.\n\nAlgorithm:\n1. Load parameters from stack (dwClientAddr, dwUnused, dwBlockDuration)\n2. Push global g_pNetworkContext as pServerContext\n3. Call DisconnectClientByAddress with all four parameters\n4. Return (stack cleanup via RET 0xc)\n\nParameters:\n  dwClientAddr (uint) - IPv4 address of client to disconnect (in_addr as 32-bit value)\n  dwUnused (uint) - Unused parameter, passed through to callee\n  dwBlockDuration (uint) - Duration in milliseconds to block reconnection\n\nReturns:\n  void - No return value\n\nCalling Convention:\n  __stdcall - Callee cleans stack (RET 0xc removes 12 bytes)\n\nRelated Functions:\n  DisconnectClientByAddress @ 0x6fc32640 - Internal implementation\n\nGlobals Referenced:\n  g_pNetworkContext @ 0x6fc3b230 - Server/network context pointer",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:ad7ceb3ac6ae530901e650af4923938e",
      "callees": {
        "LoD/1.07": [
          "DisconnectClientByAddress"
        ],
        "LoD/1.08": [
          "UnlistIPFromHackList"
        ],
        "LoD/1.09": [
          "RemoveClientByIpAddress"
        ],
        "LoD/1.09b": [
          "UnlistIPFromHackList"
        ],
        "LoD/1.09d": [
          "Ordinal_10164"
        ],
        "LoD/1.10": [
          "Ordinal_10162"
        ],
        "LoD/1.11": [
          "ProcessNetworkAddressTracking"
        ],
        "LoD/1.11b": [
          "SearchHashTableForNetworkAddress"
        ],
        "LoD/1.12a": [
          "ProcessNetworkAddressTracking"
        ],
        "LoD/1.13c": [
          "ProcessAndTrackSocketAddress"
        ],
        "LoD/1.13d": [
          "SearchHashTableForNetworkAddress"
        ]
      },
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1,
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "ad7ceb3ac6ae530901e650af4923938e",
        "LoD/1.08": "ad7ceb3ac6ae530901e650af4923938e",
        "LoD/1.09": "ad7ceb3ac6ae530901e650af4923938e",
        "LoD/1.09b": "ad7ceb3ac6ae530901e650af4923938e",
        "LoD/1.09d": "ad7ceb3ac6ae530901e650af4923938e",
        "LoD/1.10": "ad7ceb3ac6ae530901e650af4923938e",
        "LoD/1.11": "ad7ceb3ac6ae530901e650af4923938e",
        "LoD/1.11b": "ad7ceb3ac6ae530901e650af4923938e",
        "LoD/1.12a": "ad7ceb3ac6ae530901e650af4923938e",
        "LoD/1.13c": "ad7ceb3ac6ae530901e650af4923938e",
        "LoD/1.13d": "ad7ceb3ac6ae530901e650af4923938e"
      }
    },
    "d2net.dll_SNET_UnlistIPFromHackList": {
      "addresses": {
        "LoD/1.07": "0x6FC32420",
        "LoD/1.08": "0x6FC32400",
        "LoD/1.09": "0x6FC02400",
        "LoD/1.09b": "0x6FC02400",
        "LoD/1.09d": "0x6FC023C0",
        "LoD/1.10": "0x6FC02490",
        "LoD/1.11": "0x6FBF60A0",
        "LoD/1.11b": "0x6FBF6080",
        "LoD/1.12a": "0x6FBF7270",
        "LoD/1.13c": "0x6FBF6170",
        "LoD/1.13d": "0x6FBF71A0"
      },
      "rvas": {
        "LoD/1.07": "0x2420",
        "LoD/1.08": "0x2400",
        "LoD/1.09": "0x2400",
        "LoD/1.09b": "0x2400",
        "LoD/1.09d": "0x23C0",
        "LoD/1.10": "0x2490",
        "LoD/1.11": "0x60A0",
        "LoD/1.11b": "0x6080",
        "LoD/1.12a": "0x7270",
        "LoD/1.13c": "0x6170",
        "LoD/1.13d": "0x71A0"
      },
      "sizes": {
        "LoD/1.07": 29,
        "LoD/1.08": 29,
        "LoD/1.09": 29,
        "LoD/1.09b": 29,
        "LoD/1.09d": 29,
        "LoD/1.10": 29,
        "LoD/1.11": 29,
        "LoD/1.11b": 29,
        "LoD/1.12a": 29,
        "LoD/1.13c": 29,
        "LoD/1.13d": 29
      },
      "name": "SNET_UnlistIPFromHackList",
      "signature": "void SNET_UnlistIPFromHackList(uint dwIPAddress, uint dwUnused1, uint dwUnused2)",
      "calling_convention": "__stdcall",
      "comment": "SNET_UnlistIPFromHackList - Remove IP from Network Hack/Ban List\n\nExported API (Ordinal 10033) that removes an IP address from the network\nhack list (ban list). This is a thunk wrapper that forwards to the internal\nUnlistIPFromHackList function with the global network context.\n\nAlgorithm:\n1. Load 3 stack parameters (dwIPAddress, dwUnused1, dwUnused2)\n2. Load global network context from g_pNetworkContext (0x6fc3b230)\n3. Push parameters and context onto stack\n4. Call UnlistIPFromHackList import to perform actual unban operation\n5. Return (stdcall cleanup of 12 bytes)\n\nParameters:\n  dwIPAddress (uint) - IPv4 address in network byte order to remove from ban list\n  dwUnused1 (uint) - Unused parameter (pushed but not passed to callee)\n  dwUnused2 (uint) - Unused parameter (pushed but not passed to callee)\n\nReturns:\n  void - No return value\n\nSpecial Cases:\n  - Only dwIPAddress is actually used by UnlistIPFromHackList\n  - dwUnused1 and dwUnused2 are pushed to stack but ignored by callee\n  - Requires g_pNetworkContext to be initialized (via NET_InitializeClientContext)\n\nGlobal Dependencies:\n  g_pNetworkContext @ 0x6fc3b230 - Pointer to network context structure\n\nRelated Functions:\n  SNET_DisconnectClientByAddress (Ordinal 10032) - Disconnect and ban by address\n  NET_DisconnectClientAndBlock - Similar disconnect with blocking",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:ad7ceb3ac6ae530901e650af4923938e",
      "callees": {
        "LoD/1.07": [
          "UnlistIPFromHackList"
        ],
        "LoD/1.08": [
          "DisconnectClientByAddress"
        ],
        "LoD/1.09": [
          "DisconnectClientByAddress"
        ],
        "LoD/1.09b": [
          "DisconnectClientByAddress"
        ],
        "LoD/1.09d": [
          "Ordinal_10159"
        ],
        "LoD/1.10": [
          "Ordinal_10163"
        ],
        "LoD/1.11": [
          "ProcessAndTrackSocketAddress"
        ],
        "LoD/1.11b": [
          "ProcessNetworkAddressTracking"
        ],
        "LoD/1.12a": [
          "SearchHashTableForNetworkAddress"
        ],
        "LoD/1.13c": [
          "SearchHashTableForNetworkAddress"
        ],
        "LoD/1.13d": [
          "ProcessAndTrackSocketAddress"
        ]
      },
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1,
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "ad7ceb3ac6ae530901e650af4923938e",
        "LoD/1.08": "ad7ceb3ac6ae530901e650af4923938e",
        "LoD/1.09": "ad7ceb3ac6ae530901e650af4923938e",
        "LoD/1.09b": "ad7ceb3ac6ae530901e650af4923938e",
        "LoD/1.09d": "ad7ceb3ac6ae530901e650af4923938e",
        "LoD/1.10": "ad7ceb3ac6ae530901e650af4923938e",
        "LoD/1.11": "ad7ceb3ac6ae530901e650af4923938e",
        "LoD/1.11b": "ad7ceb3ac6ae530901e650af4923938e",
        "LoD/1.12a": "ad7ceb3ac6ae530901e650af4923938e",
        "LoD/1.13c": "ad7ceb3ac6ae530901e650af4923938e",
        "LoD/1.13d": "ad7ceb3ac6ae530901e650af4923938e"
      }
    },
    "d2net.dll_SNET_RemoveClientByIPAddress": {
      "addresses": {
        "LoD/1.07": "0x6FC32440",
        "LoD/1.08": "0x6FC323E0",
        "LoD/1.09": "0x6FC023C0",
        "LoD/1.09b": "0x6FC023E0",
        "LoD/1.09d": "0x6FC023E0",
        "LoD/1.10": "0x6FC024B0",
        "LoD/1.11": "0x6FBF6060",
        "LoD/1.11b": "0x6FBF6040",
        "LoD/1.12a": "0x6FBF71B0",
        "LoD/1.13c": "0x6FBF60B0",
        "LoD/1.13d": "0x6FBF7160"
      },
      "rvas": {
        "LoD/1.07": "0x2440",
        "LoD/1.08": "0x23E0",
        "LoD/1.09": "0x23C0",
        "LoD/1.09b": "0x23E0",
        "LoD/1.09d": "0x23E0",
        "LoD/1.10": "0x24B0",
        "LoD/1.11": "0x6060",
        "LoD/1.11b": "0x6040",
        "LoD/1.12a": "0x71B0",
        "LoD/1.13c": "0x60B0",
        "LoD/1.13d": "0x7160"
      },
      "sizes": {
        "LoD/1.07": 29,
        "LoD/1.08": 29,
        "LoD/1.09": 29,
        "LoD/1.09b": 29,
        "LoD/1.09d": 29,
        "LoD/1.10": 29,
        "LoD/1.11": 29,
        "LoD/1.11b": 29,
        "LoD/1.12a": 29,
        "LoD/1.13c": 29,
        "LoD/1.13d": 29
      },
      "name": "SNET_RemoveClientByIPAddress",
      "signature": "void SNET_RemoveClientByIPAddress(in_addr addrClient, uint dwUnused1, uint dwUnused2)",
      "calling_convention": "__stdcall",
      "comment": "Exported thunk (Ordinal 10034) that removes a client from the network by IP address.\n\nAlgorithm:\n1. Load global network context from g_pNetworkContext\n2. Call RemoveClientByIpAddress with context and client IP address\n3. Return (stdcall cleanup of 3 parameters)\n\nParameters:\n  addrClient (in_addr) - IPv4 address of client to remove\n  dwUnused1 (uint) - Unused parameter passed to callee\n  dwUnused2 (uint) - Unused parameter passed to callee\n\nReturns:\n  void - No return value\n\nSpecial Cases:\n  Decompiler Discrepancy: Assembly shows 4 parameters pushed to RemoveClientByIpAddress\n  (pServerCtx, addrClient, dwUnused1, dwUnused2) but decompiler only displays 2.\n  The callee signature may be incomplete.\n\nGlobal References:\n  g_pNetworkContext (0x6fc3b230) - Global network/server context pointer",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:ad7ceb3ac6ae530901e650af4923938e",
      "callees": {
        "LoD/1.07": [
          "RemoveClientByIpAddress"
        ],
        "LoD/1.08": [
          "DisconnectClientAndBlock"
        ],
        "LoD/1.09": [
          "GetPeerIPAddressByID"
        ],
        "LoD/1.09b": [
          "DisconnectClientAndBlock"
        ],
        "LoD/1.09d": [
          "Ordinal_10162"
        ],
        "LoD/1.10": [
          "Ordinal_10164"
        ],
        "LoD/1.11": [
          "UnlistHackedIP"
        ],
        "LoD/1.11b": [
          "DisconnectSocketByIP"
        ],
        "LoD/1.12a": [
          "DisconnectSocketByIP"
        ],
        "LoD/1.13c": [
          "DisconnectSocketByIP"
        ],
        "LoD/1.13d": [
          "UnlistHackedIP"
        ]
      },
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1,
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "ad7ceb3ac6ae530901e650af4923938e",
        "LoD/1.08": "ad7ceb3ac6ae530901e650af4923938e",
        "LoD/1.09": "ad7ceb3ac6ae530901e650af4923938e",
        "LoD/1.09b": "ad7ceb3ac6ae530901e650af4923938e",
        "LoD/1.09d": "ad7ceb3ac6ae530901e650af4923938e",
        "LoD/1.10": "ad7ceb3ac6ae530901e650af4923938e",
        "LoD/1.11": "ad7ceb3ac6ae530901e650af4923938e",
        "LoD/1.11b": "ad7ceb3ac6ae530901e650af4923938e",
        "LoD/1.12a": "ad7ceb3ac6ae530901e650af4923938e",
        "LoD/1.13c": "ad7ceb3ac6ae530901e650af4923938e",
        "LoD/1.13d": "ad7ceb3ac6ae530901e650af4923938e"
      }
    },
    "d2net.dll_SNET_DisconnectClient": {
      "addresses": {
        "LoD/1.07": "0x6FC32460",
        "LoD/1.08": "0x6FC32460",
        "LoD/1.09": "0x6FC02460",
        "LoD/1.09b": "0x6FC02460",
        "LoD/1.09d": "0x6FC02460",
        "LoD/1.10": "0x6FC024F0",
        "LoD/1.11": "0x6FBF6020",
        "LoD/1.11b": "0x6FBF6020",
        "LoD/1.12a": "0x6FBF7190",
        "LoD/1.13c": "0x6FBF6090",
        "LoD/1.13d": "0x6FBF7120"
      },
      "rvas": {
        "LoD/1.07": "0x2460",
        "LoD/1.08": "0x2460",
        "LoD/1.09": "0x2460",
        "LoD/1.09b": "0x2460",
        "LoD/1.09d": "0x2460",
        "LoD/1.10": "0x24F0",
        "LoD/1.11": "0x6020",
        "LoD/1.11b": "0x6020",
        "LoD/1.12a": "0x7190",
        "LoD/1.13c": "0x6090",
        "LoD/1.13d": "0x7120"
      },
      "sizes": {
        "LoD/1.07": 30,
        "LoD/1.08": 30,
        "LoD/1.09": 30,
        "LoD/1.09b": 30,
        "LoD/1.09d": 30,
        "LoD/1.10": 30,
        "LoD/1.11": 30,
        "LoD/1.11b": 30,
        "LoD/1.12a": 30,
        "LoD/1.13c": 30,
        "LoD/1.13d": 30
      },
      "name": "SNET_DisconnectClient",
      "signature": "void SNET_DisconnectClient(DWORD dwClientId)",
      "calling_convention": "__stdcall",
      "comment": "Disconnects a network client by its unique identifier.\n\nClassification: Thunk/Wrapper - forwards call to DisconnectClientById with global context\n\nAlgorithm:\n1. Load client ID from stack parameter [ESP+4]\n2. Load global network context pointer from g_pNetworkContext (0x6fc3b230)\n3. Push debug trace parameters: line number 0x1AD (429) and source file pointer 0x6fc38608\n4. Call DisconnectClientById via jump table with (pNetworkContext, dwClientId)\n5. Return with stack cleanup (RET 4 for __stdcall)\n\nParameters:\n  dwClientId [ESP+4] - DWORD - Client identifier to disconnect from the network\n\nReturns:\n  void - No return value\n\nGlobals Accessed:\n  g_pNetworkContext (0x6fc3b230) - READ - Global network server context pointer\n\nCallees:\n  DisconnectClientById (0x6fc32652) - Performs actual client disconnection via indirect jump\n\nSpecial Cases:\n  - Debug/trace info: Line 429, file at 0x6fc38608 passed to callee\n  - Exported as Ordinal 10016 for external callers",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:46dc89d3eb6328b2b92becc1d6b257ac",
      "callees": {
        "LoD/1.07": [
          "DisconnectClientById"
        ],
        "LoD/1.08": [
          "DisconnectClientById"
        ],
        "LoD/1.09": [
          "DisconnectClientById"
        ],
        "LoD/1.09b": [
          "DisconnectClientById"
        ],
        "LoD/1.09d": [
          "Ordinal_10165"
        ],
        "LoD/1.10": [
          "Ordinal_10165"
        ],
        "LoD/1.11": [
          "CloseSocketEntry"
        ],
        "LoD/1.11b": [
          "CloseSocketEntry"
        ],
        "LoD/1.12a": [
          "CloseSocketEntry"
        ],
        "LoD/1.13c": [
          "CloseSocketEntry"
        ],
        "LoD/1.13d": [
          "CloseSocketEntry"
        ]
      },
      "strings": {
        "LoD/1.07": [
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2Net\\\\SRC\\\\Server..."
        ],
        "LoD/1.08": [
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2Net\\\\SRC\\\\Server..."
        ],
        "LoD/1.09": [
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2Net\\\\SRC\\\\Server..."
        ],
        "LoD/1.09b": [
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2Net\\\\SRC\\\\Server..."
        ],
        "LoD/1.09d": [
          "\"C:\\\\Src\\\\Diablo2\\\\Source\\\\D2Net\\\\SRC\\\\Server.cpp\""
        ],
        "LoD/1.10": [
          "\"C:\\\\projects\\\\D2\\\\head\\\\Diablo2\\\\Source\\\\D2Net\\\\S..."
        ],
        "LoD/1.11": [
          "\"..\\\\Source\\\\D2Net\\\\SRC\\\\Server.cpp\""
        ],
        "LoD/1.11b": [
          "\"..\\\\Source\\\\D2Net\\\\SRC\\\\Server.cpp\""
        ],
        "LoD/1.12a": [
          "\"..\\\\Source\\\\D2Net\\\\SRC\\\\Server.cpp\""
        ],
        "LoD/1.13c": [
          "\"..\\\\Source\\\\D2Net\\\\SRC\\\\Server.cpp\""
        ],
        "LoD/1.13d": [
          "\"..\\\\Source\\\\D2Net\\\\SRC\\\\Server.cpp\""
        ]
      },
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1,
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "46dc89d3eb6328b2b92becc1d6b257ac",
        "LoD/1.08": "46dc89d3eb6328b2b92becc1d6b257ac",
        "LoD/1.09": "46dc89d3eb6328b2b92becc1d6b257ac",
        "LoD/1.09b": "46dc89d3eb6328b2b92becc1d6b257ac",
        "LoD/1.09d": "46dc89d3eb6328b2b92becc1d6b257ac",
        "LoD/1.10": "46dc89d3eb6328b2b92becc1d6b257ac",
        "LoD/1.11": "46dc89d3eb6328b2b92becc1d6b257ac",
        "LoD/1.11b": "46dc89d3eb6328b2b92becc1d6b257ac",
        "LoD/1.12a": "46dc89d3eb6328b2b92becc1d6b257ac",
        "LoD/1.13c": "46dc89d3eb6328b2b92becc1d6b257ac",
        "LoD/1.13d": "46dc89d3eb6328b2b92becc1d6b257ac"
      }
    },
    "d2net.dll_SNET_SetServerHandle": {
      "addresses": {
        "LoD/1.07": "0x6FC32480",
        "LoD/1.08": "0x6FC32480",
        "LoD/1.09": "0x6FC02480",
        "LoD/1.09b": "0x6FC02480",
        "LoD/1.09d": "0x6FC02480",
        "LoD/1.10": "0x6FC02510",
        "LoD/1.11": "0x6FBF6000",
        "LoD/1.11b": "0x6FBF6000",
        "LoD/1.12a": "0x6FBF7170",
        "LoD/1.13c": "0x6FBF6070",
        "LoD/1.13d": "0x6FBF7100"
      },
      "rvas": {
        "LoD/1.07": "0x2480",
        "LoD/1.08": "0x2480",
        "LoD/1.09": "0x2480",
        "LoD/1.09b": "0x2480",
        "LoD/1.09d": "0x2480",
        "LoD/1.10": "0x2510",
        "LoD/1.11": "0x6000",
        "LoD/1.11b": "0x6000",
        "LoD/1.12a": "0x7170",
        "LoD/1.13c": "0x6070",
        "LoD/1.13d": "0x7100"
      },
      "sizes": {
        "LoD/1.07": 23,
        "LoD/1.08": 23,
        "LoD/1.09": 23,
        "LoD/1.09b": 23,
        "LoD/1.09d": 23,
        "LoD/1.10": 23,
        "LoD/1.11": 23,
        "LoD/1.11b": 23,
        "LoD/1.12a": 23,
        "LoD/1.13c": 23,
        "LoD/1.13d": 23
      },
      "name": "SNET_SetServerHandle",
      "signature": "void SNET_SetServerHandle(uint dwHandle)",
      "calling_convention": "__stdcall",
      "comment": "Sets a handle value on the global server context if it exists.\n\nCLASSIFICATION: Public API / Thunk wrapper\n\nAlgorithm:\n1. Load global server context pointer (g_pServerContext)\n2. If context is NULL, return immediately (no server initialized)\n3. Push dwHandle parameter and context pointer\n4. Call SetServerHandle to store the handle in context\n\nParameters:\n  dwHandle (uint) - Handle value to associate with the server context.\n                    Meaning is context-dependent (socket, event, resource).\n\nReturns:\n  void - No return value\n\nSpecial Cases:\n  - If g_pServerContext is NULL, function returns without action\n  - This is a safe no-op when called before server initialization\n\nRelated Globals:\n  g_pServerContext (0x6fc3b230) - Pointer to server context structure,\n                                  used by NET_* and SNET_* functions",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:0938ea9023b6c13026d77f08255b267d",
      "callees": {
        "LoD/1.07": [
          "SetServerHandle"
        ],
        "LoD/1.08": [
          "SetServerHandle"
        ],
        "LoD/1.09": [
          "SetServerHandle"
        ],
        "LoD/1.09b": [
          "SetServerHandle"
        ],
        "LoD/1.09d": [
          "Ordinal_10170"
        ],
        "LoD/1.10": [
          "Ordinal_10170"
        ],
        "LoD/1.11": [
          "SetResourceStateOrHandleError"
        ],
        "LoD/1.11b": [
          "SetResourceStateOrHandleError"
        ],
        "LoD/1.12a": [
          "SetResourceStateOrHandleError"
        ],
        "LoD/1.13c": [
          "SetResourceStateOrHandleError"
        ],
        "LoD/1.13d": [
          "SetResourceStateOrHandleError"
        ]
      },
      "basic_block_counts": {
        "LoD/1.07": 3,
        "LoD/1.08": 3,
        "LoD/1.09": 3,
        "LoD/1.09b": 3,
        "LoD/1.09d": 3,
        "LoD/1.10": 3,
        "LoD/1.11": 3,
        "LoD/1.11b": 3,
        "LoD/1.12a": 3,
        "LoD/1.13c": 3,
        "LoD/1.13d": 3
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "0938ea9023b6c13026d77f08255b267d",
        "LoD/1.08": "0938ea9023b6c13026d77f08255b267d",
        "LoD/1.09": "0938ea9023b6c13026d77f08255b267d",
        "LoD/1.09b": "0938ea9023b6c13026d77f08255b267d",
        "LoD/1.09d": "0938ea9023b6c13026d77f08255b267d",
        "LoD/1.10": "0938ea9023b6c13026d77f08255b267d",
        "LoD/1.11": "0938ea9023b6c13026d77f08255b267d",
        "LoD/1.11b": "0938ea9023b6c13026d77f08255b267d",
        "LoD/1.12a": "0938ea9023b6c13026d77f08255b267d",
        "LoD/1.13c": "0938ea9023b6c13026d77f08255b267d",
        "LoD/1.13d": "0938ea9023b6c13026d77f08255b267d"
      }
    },
    "d2net.dll_NET_SetServerContextField0xBBC": {
      "addresses": {
        "LoD/1.07": "0x6FC324A0",
        "LoD/1.08": "0x6FC324A0",
        "LoD/1.09": "0x6FC021C0",
        "LoD/1.09b": "0x6FC021C0",
        "LoD/1.09d": "0x6FC020F0",
        "LoD/1.10": "0x6FC025F0",
        "LoD/1.11": "0x6FBF61B0",
        "LoD/1.11b": "0x6FBF61E0",
        "LoD/1.12a": "0x6FBF7350",
        "LoD/1.13c": "0x6FBF6220",
        "LoD/1.13d": "0x6FBF6FD0"
      },
      "rvas": {
        "LoD/1.07": "0x24A0",
        "LoD/1.08": "0x24A0",
        "LoD/1.09": "0x21C0",
        "LoD/1.09b": "0x21C0",
        "LoD/1.09d": "0x20F0",
        "LoD/1.10": "0x25F0",
        "LoD/1.11": "0x61B0",
        "LoD/1.11b": "0x61E0",
        "LoD/1.12a": "0x7350",
        "LoD/1.13c": "0x6220",
        "LoD/1.13d": "0x6FD0"
      },
      "sizes": {
        "LoD/1.07": 20,
        "LoD/1.08": 20,
        "LoD/1.09": 20,
        "LoD/1.09b": 20,
        "LoD/1.09d": 20,
        "LoD/1.10": 20,
        "LoD/1.11": 20,
        "LoD/1.11b": 20,
        "LoD/1.12a": 20,
        "LoD/1.13c": 20,
        "LoD/1.13d": 20
      },
      "name": "NET_SetServerContextField0xBBC",
      "signature": "void NET_SetServerContextField0xBBC(uint dwValue)",
      "calling_convention": "__stdcall",
      "comment": "Sets a value at offset 0xBBC in the global server context structure.\n\nExported as Ordinal 10019. Thin wrapper that passes the global server context\npointer and the provided value to the external SetStructField0xBBC function.\n\nClassification: Thunk/Wrapper - delegates to external import\n\nAlgorithm:\n1. Load dwValue parameter from stack [ESP+0x4]\n2. Load g_pServerContext global pointer from [0x6fc3b230]\n3. Call SetStructField0xBBC(g_pServerContext, dwValue) to set field at offset 0xBBC\n4. Return (stack cleanup via RET 0x4)\n\nParameters:\n  dwValue - uint value to store at offset 0xBBC in the server context structure\n\nReturns:\n  void - no return value\n\nGlobal Data:\n  g_pServerContext [0x6fc3b230] - Pointer to global server/network context structure\n\nExternal Calls:\n  SetStructField0xBBC (Ordinal 0x1e) - Sets dword value at struct offset 0xBBC",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:0c7249cc723d27c36926c4cb05e7aa15",
      "callees": {
        "LoD/1.07": [
          "SetStructField0xBBC"
        ],
        "LoD/1.08": [
          "SetStructField0xBBC"
        ],
        "LoD/1.09": [
          "SetFieldBD0"
        ],
        "LoD/1.09b": [
          "SetFieldBD0"
        ],
        "LoD/1.09d": [
          "Ordinal_10154"
        ],
        "LoD/1.10": [
          "WaitForAsyncIO"
        ],
        "LoD/1.11": [
          "WriteValueToOffset0xBD0"
        ],
        "LoD/1.11b": [
          "SetGameObjectProperty"
        ],
        "LoD/1.12a": [
          "SetGameObjectProperty"
        ],
        "LoD/1.13c": [
          "WriteValueToOffset0xBD0"
        ],
        "LoD/1.13d": [
          "WaitOrProcessContextSlots"
        ]
      },
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1,
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "0c7249cc723d27c36926c4cb05e7aa15",
        "LoD/1.08": "0c7249cc723d27c36926c4cb05e7aa15",
        "LoD/1.09": "0c7249cc723d27c36926c4cb05e7aa15",
        "LoD/1.09b": "0c7249cc723d27c36926c4cb05e7aa15",
        "LoD/1.09d": "0c7249cc723d27c36926c4cb05e7aa15",
        "LoD/1.10": "0c7249cc723d27c36926c4cb05e7aa15",
        "LoD/1.11": "0c7249cc723d27c36926c4cb05e7aa15",
        "LoD/1.11b": "0c7249cc723d27c36926c4cb05e7aa15",
        "LoD/1.12a": "0c7249cc723d27c36926c4cb05e7aa15",
        "LoD/1.13c": "0c7249cc723d27c36926c4cb05e7aa15",
        "LoD/1.13d": "0c7249cc723d27c36926c4cb05e7aa15"
      }
    },
    "d2net.dll_NET_SetServerContextValue": {
      "addresses": {
        "LoD/1.07": "0x6FC324C0",
        "LoD/1.08": "0x6FC324C0",
        "LoD/1.09": "0x6FC024C0",
        "LoD/1.09b": "0x6FC024C0",
        "LoD/1.09d": "0x6FC024C0",
        "LoD/1.10": "0x6FC02550",
        "LoD/1.11": "0x6FBF5FB0",
        "LoD/1.11b": "0x6FBF5FB0",
        "LoD/1.12a": "0x6FBF7120",
        "LoD/1.13c": "0x6FBF6020",
        "LoD/1.13d": "0x6FBF70B0"
      },
      "rvas": {
        "LoD/1.07": "0x24C0",
        "LoD/1.08": "0x24C0",
        "LoD/1.09": "0x24C0",
        "LoD/1.09b": "0x24C0",
        "LoD/1.09d": "0x24C0",
        "LoD/1.10": "0x2550",
        "LoD/1.11": "0x5FB0",
        "LoD/1.11b": "0x5FB0",
        "LoD/1.12a": "0x7120",
        "LoD/1.13c": "0x6020",
        "LoD/1.13d": "0x70B0"
      },
      "sizes": {
        "LoD/1.07": 41,
        "LoD/1.08": 41,
        "LoD/1.09": 41,
        "LoD/1.09b": 41,
        "LoD/1.09d": 41,
        "LoD/1.10": 41,
        "LoD/1.11": 41,
        "LoD/1.11b": 41,
        "LoD/1.12a": 41,
        "LoD/1.13c": 41,
        "LoD/1.13d": 41
      },
      "name": "NET_SetServerContextValue",
      "signature": "void NET_SetServerContextValue(uint dwKey, uint dwValue)",
      "calling_convention": "__stdcall",
      "comment": "Sets a key-value pair in the server network context hash table or updates global receive counter.\n\nExported as Ordinal 10020. This is a public API wrapper function that routes value storage\nbased on whether a key is provided. When dwKey is non-zero, stores the value in the server\ncontext hash table (g_pServerContext). When dwKey is zero, directly sets g_dwNetRecvCount.\n\nClassification: Public API / Wrapper\n\nAlgorithm:\n1. Test if dwKey is zero\n2. If dwKey != 0: Call HashTableSetValue(g_pServerContext, dwKey, dwValue) to store in hash table\n3. If dwKey == 0: Set g_dwNetRecvCount = dwValue directly (special case for receive counter)\n4. Return\n\nParameters:\n  dwKey   - uint [Stack+0x4] Hash table key. When 0, value is stored in g_dwNetRecvCount instead\n  dwValue - uint [Stack+0x8] Value to store in hash table or as receive counter\n\nReturns:\n  void - No return value\n\nSpecial Cases:\n  - dwKey == 0: Bypasses hash table, directly sets g_dwNetRecvCount global\n  - This allows single API to handle both keyed storage and the special receive counter\n\nGlobals Accessed:\n  g_pServerContext  [0x6fc3b230] - READ  - FogHashTable* for server context storage\n  g_dwNetRecvCount  [0x6fc3b234] - WRITE - Network receive counter (when dwKey == 0)\n\nCross-References:\n  - Called via export ordinal 10020 (external entry point only)\n  - g_dwNetRecvCount read by Ordinal_10021",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:6fc4a74c19cd8579017953fa5f53fefb",
      "callees": {
        "LoD/1.07": [
          "HashTableSetValue"
        ],
        "LoD/1.08": [
          "HashTableSetValue"
        ],
        "LoD/1.09": [
          "HashTableSetValue"
        ],
        "LoD/1.09b": [
          "HashTableSetValue"
        ],
        "LoD/1.09d": [
          "Ordinal_10172"
        ],
        "LoD/1.10": [
          "Ordinal_10172"
        ],
        "LoD/1.11": [
          "SetHashTableEntryValue"
        ],
        "LoD/1.11b": [
          "SetHashTableEntryValue"
        ],
        "LoD/1.12a": [
          "SetHashTableEntryValue"
        ],
        "LoD/1.13c": [
          "SetHashTableEntryValue"
        ],
        "LoD/1.13d": [
          "SetHashTableEntryValue"
        ]
      },
      "basic_block_counts": {
        "LoD/1.07": 3,
        "LoD/1.08": 3,
        "LoD/1.09": 3,
        "LoD/1.09b": 3,
        "LoD/1.09d": 3,
        "LoD/1.10": 3,
        "LoD/1.11": 3,
        "LoD/1.11b": 3,
        "LoD/1.12a": 3,
        "LoD/1.13c": 3,
        "LoD/1.13d": 3
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "6fc4a74c19cd8579017953fa5f53fefb",
        "LoD/1.08": "6fc4a74c19cd8579017953fa5f53fefb",
        "LoD/1.09": "6fc4a74c19cd8579017953fa5f53fefb",
        "LoD/1.09b": "6fc4a74c19cd8579017953fa5f53fefb",
        "LoD/1.09d": "6fc4a74c19cd8579017953fa5f53fefb",
        "LoD/1.10": "6fc4a74c19cd8579017953fa5f53fefb",
        "LoD/1.11": "6fc4a74c19cd8579017953fa5f53fefb",
        "LoD/1.11b": "6fc4a74c19cd8579017953fa5f53fefb",
        "LoD/1.12a": "6fc4a74c19cd8579017953fa5f53fefb",
        "LoD/1.13c": "6fc4a74c19cd8579017953fa5f53fefb",
        "LoD/1.13d": "6fc4a74c19cd8579017953fa5f53fefb"
      }
    },
    "d2net.dll_SNET_GetServerHashValue": {
      "addresses": {
        "LoD/1.07": "0x6FC324F0",
        "LoD/1.08": "0x6FC324F0",
        "LoD/1.09": "0x6FC024F0",
        "LoD/1.09b": "0x6FC024F0",
        "LoD/1.09d": "0x6FC024F0",
        "LoD/1.10": "0x6FC02580",
        "LoD/1.11": "0x6FBF5F90",
        "LoD/1.11b": "0x6FBF5F90",
        "LoD/1.12a": "0x6FBF7100",
        "LoD/1.13c": "0x6FBF6000",
        "LoD/1.13d": "0x6FBF7090"
      },
      "rvas": {
        "LoD/1.07": "0x24F0",
        "LoD/1.08": "0x24F0",
        "LoD/1.09": "0x24F0",
        "LoD/1.09b": "0x24F0",
        "LoD/1.09d": "0x24F0",
        "LoD/1.10": "0x2580",
        "LoD/1.11": "0x5F90",
        "LoD/1.11b": "0x5F90",
        "LoD/1.12a": "0x7100",
        "LoD/1.13c": "0x6000",
        "LoD/1.13d": "0x7090"
      },
      "sizes": {
        "LoD/1.07": 31,
        "LoD/1.08": 31,
        "LoD/1.09": 31,
        "LoD/1.09b": 31,
        "LoD/1.09d": 31,
        "LoD/1.10": 31,
        "LoD/1.11": 31,
        "LoD/1.11b": 31,
        "LoD/1.12a": 31,
        "LoD/1.13c": 31,
        "LoD/1.13d": 31
      },
      "name": "SNET_GetServerHashValue",
      "signature": "uint SNET_GetServerHashValue(uint dwKey)",
      "calling_convention": "__stdcall",
      "comment": "SNET_GetServerHashValue - Retrieves a value from the server hash table by key.\n\nExported as Ordinal 10021.\n\nAlgorithm:\n1. Check if dwKey is zero (special case for receive count query)\n2. If dwKey is 0, return g_dwNetRecvCount (global receive counter)\n3. Otherwise, call GetHashTableValue with g_pServerContext and dwKey\n4. Return the retrieved hash table value\n\nParameters:\n  dwKey [Stack+0x4] - Hash key to look up. If 0, returns global receive count instead of hash lookup.\n\nReturns:\n  uint - The value from the hash table for the given key, or g_dwNetRecvCount if key is 0.\n\nSpecial Cases:\n  - dwKey == 0: Returns g_dwNetRecvCount instead of performing hash lookup\n  - This allows callers to query the receive count using this function\n\nGlobals:\n  g_pServerContext (0x6fc3b230) - Pointer to server context structure containing hash table\n  g_dwNetRecvCount (0x6fc3b234) - Global network receive counter",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:4d80b7e96a37b6848a97510f46ba4048",
      "callees": {
        "LoD/1.07": [
          "GetHashTableValue"
        ],
        "LoD/1.08": [
          "GetHashTableValue"
        ],
        "LoD/1.09": [
          "GetHashTableValue"
        ],
        "LoD/1.09b": [
          "GetHashTableValue"
        ],
        "LoD/1.09d": [
          "Ordinal_10173"
        ],
        "LoD/1.10": [
          "Ordinal_10173"
        ],
        "LoD/1.11": [
          "GetHashTableEntryValue"
        ],
        "LoD/1.11b": [
          "GetHashTableEntryValue"
        ],
        "LoD/1.12a": [
          "GetHashTableEntryValue"
        ],
        "LoD/1.13c": [
          "GetHashTableEntryValue"
        ],
        "LoD/1.13d": [
          "GetHashTableEntryValue"
        ]
      },
      "basic_block_counts": {
        "LoD/1.07": 3,
        "LoD/1.08": 3,
        "LoD/1.09": 3,
        "LoD/1.09b": 3,
        "LoD/1.09d": 3,
        "LoD/1.10": 3,
        "LoD/1.11": 3,
        "LoD/1.11b": 3,
        "LoD/1.12a": 3,
        "LoD/1.13c": 3,
        "LoD/1.13d": 3
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "4d80b7e96a37b6848a97510f46ba4048",
        "LoD/1.08": "4d80b7e96a37b6848a97510f46ba4048",
        "LoD/1.09": "4d80b7e96a37b6848a97510f46ba4048",
        "LoD/1.09b": "4d80b7e96a37b6848a97510f46ba4048",
        "LoD/1.09d": "4d80b7e96a37b6848a97510f46ba4048",
        "LoD/1.10": "4d80b7e96a37b6848a97510f46ba4048",
        "LoD/1.11": "4d80b7e96a37b6848a97510f46ba4048",
        "LoD/1.11b": "4d80b7e96a37b6848a97510f46ba4048",
        "LoD/1.12a": "4d80b7e96a37b6848a97510f46ba4048",
        "LoD/1.13c": "4d80b7e96a37b6848a97510f46ba4048",
        "LoD/1.13d": "4d80b7e96a37b6848a97510f46ba4048"
      }
    },
    "d2net.dll_NET_QueueMessageDuringShutdown": {
      "addresses": {
        "LoD/1.07": "0x6FC32510",
        "LoD/1.08": "0x6FC32510",
        "LoD/1.09": "0x6FC02510",
        "LoD/1.09b": "0x6FC02510",
        "LoD/1.09d": "0x6FC02510",
        "LoD/1.10": "0x6FC025A0"
      },
      "rvas": {
        "LoD/1.07": "0x2510",
        "LoD/1.08": "0x2510",
        "LoD/1.09": "0x2510",
        "LoD/1.09b": "0x2510",
        "LoD/1.09d": "0x2510",
        "LoD/1.10": "0x25A0"
      },
      "sizes": {
        "LoD/1.07": 65,
        "LoD/1.08": 65,
        "LoD/1.09": 65,
        "LoD/1.09b": 65,
        "LoD/1.09d": 65,
        "LoD/1.10": 65
      },
      "name": "NET_QueueMessageDuringShutdown",
      "signature": "bool NET_QueueMessageDuringShutdown(byte * pbData, uint dwDataSize)",
      "calling_convention": "__fastcall",
      "comment": "Queues a message to the server context during network shutdown.\n\nCalled by NET_SendClientData when network is shutting down to queue messages\nfor later processing instead of sending directly via Winsock.\n\nAlgorithm:\n1. Validate message size against MAX_MSG_SIZE (0x204 = 516 bytes)\n2. If size exceeds limit, assert failure and signal error via FUN_6fc326bb(-1)\n3. Call QueueReceivedMessage(g_pServerContext) to queue the message\n4. Return true if queue succeeded, false otherwise\n\nParameters:\n  pbData (ECX) - Pointer to message data buffer to queue\n  dwDataSize (EDX) - Size of message in bytes (cast to ushort for comparison)\n\nReturns:\n  bool - true if message was successfully queued, false otherwise\n\nSpecial Cases:\n  - Message size check uses ushort cast (max valid size 0x204)\n  - Assert triggers on size > 0x204 but continues to queue attempt\n  - pbData is passed through to QueueReceivedMessage via g_pServerContext\n\nMagic Numbers:\n  0x204 - MAX_MSG_SIZE (516 bytes maximum message size)\n  0x1f0 - Assert line number in Server.cpp (496)\n  -1 (0xFFFFFFFF) - Error signal to FUN_6fc326bb\n\nError Handling:\n  FogAssert called with szAssertWsizeValid on size violation\n  FUN_6fc326bb(-1) called to propagate error state",
      "name_source": "LoD/1.07",
      "method": "API",
      "index": "API:a1f3b560b011585ea8d1483438887d89",
      "callees": {
        "LoD/1.07": [
          "FogAssert",
          "QueueReceivedMessage"
        ],
        "LoD/1.08": [
          "FogAssert",
          "QueueReceivedMessage"
        ],
        "LoD/1.09": [
          "FogAssert",
          "QueueReceivedMessage"
        ],
        "LoD/1.09b": [
          "FogAssert",
          "QueueReceivedMessage"
        ],
        "LoD/1.09d": [
          "FogAssert",
          "Ordinal_10175"
        ],
        "LoD/1.10": [
          "FogAssert",
          "Ordinal_10175"
        ]
      },
      "strings": {
        "LoD/1.07": [
          "\"wSize <= MAX_MSG_SIZE\"",
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2Net\\\\SRC\\\\Server..."
        ],
        "LoD/1.08": [
          "\"wSize <= MAX_MSG_SIZE\"",
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2Net\\\\SRC\\\\Server..."
        ],
        "LoD/1.09": [
          "\"wSize <= MAX_MSG_SIZE\"",
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2Net\\\\SRC\\\\Server..."
        ],
        "LoD/1.09b": [
          "\"wSize <= MAX_MSG_SIZE\"",
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2Net\\\\SRC\\\\Server..."
        ],
        "LoD/1.09d": [
          "\"wSize <= MAX_MSG_SIZE\"",
          "\"C:\\\\Src\\\\Diablo2\\\\Source\\\\D2Net\\\\SRC\\\\Server.cpp\""
        ],
        "LoD/1.10": [
          "\"C:\\\\projects\\\\D2\\\\head\\\\Diablo2\\\\Source\\\\D2Net\\\\S...",
          "\"wSize <= MAX_MSG_SIZE\""
        ]
      },
      "basic_block_counts": {
        "LoD/1.07": 3,
        "LoD/1.08": 3,
        "LoD/1.09": 3,
        "LoD/1.09b": 3,
        "LoD/1.09d": 3,
        "LoD/1.10": 3
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "5c4e4a9bf953fe1be4d8b69f0ab7aea6",
        "LoD/1.08": "5c4e4a9bf953fe1be4d8b69f0ab7aea6",
        "LoD/1.09": "5c4e4a9bf953fe1be4d8b69f0ab7aea6",
        "LoD/1.09b": "5c4e4a9bf953fe1be4d8b69f0ab7aea6",
        "LoD/1.09d": "5c4e4a9bf953fe1be4d8b69f0ab7aea6",
        "LoD/1.10": "5c4e4a9bf953fe1be4d8b69f0ab7aea6"
      }
    },
    "d2net.dll_NET_WaitForAsyncIOWithContext": {
      "addresses": {
        "LoD/1.07": "0x6FC32560",
        "LoD/1.08": "0x6FC32560",
        "LoD/1.09": "0x6FC02560",
        "LoD/1.09b": "0x6FC02560",
        "LoD/1.09d": "0x6FC02560",
        "LoD/1.10": "0x6FC021D0",
        "LoD/1.11": "0x6FBF5ED0",
        "LoD/1.11b": "0x6FBF60C0",
        "LoD/1.12a": "0x6FBF7150",
        "LoD/1.13c": "0x6FBF6130",
        "LoD/1.13d": "0x6FBF72E0"
      },
      "rvas": {
        "LoD/1.07": "0x2560",
        "LoD/1.08": "0x2560",
        "LoD/1.09": "0x2560",
        "LoD/1.09b": "0x2560",
        "LoD/1.09d": "0x2560",
        "LoD/1.10": "0x21D0",
        "LoD/1.11": "0x5ED0",
        "LoD/1.11b": "0x60C0",
        "LoD/1.12a": "0x7150",
        "LoD/1.13c": "0x6130",
        "LoD/1.13d": "0x72E0"
      },
      "sizes": {
        "LoD/1.07": 20,
        "LoD/1.08": 20,
        "LoD/1.09": 20,
        "LoD/1.09b": 20,
        "LoD/1.09d": 20,
        "LoD/1.10": 20,
        "LoD/1.11": 20,
        "LoD/1.11b": 20,
        "LoD/1.12a": 20,
        "LoD/1.13c": 20,
        "LoD/1.13d": 20
      },
      "name": "NET_WaitForAsyncIOWithContext",
      "signature": "void NET_WaitForAsyncIOWithContext(uint dwTimeoutMs)",
      "calling_convention": "__stdcall",
      "comment": "Waits for asynchronous I/O operations to complete using the global server context.\n\nClassification: Thunk/Wrapper\nOrdinal: 10022\n\nAlgorithm:\n1. Load global server context pointer (g_pServerContext) from 0x6fc3b230\n2. Call WaitForAsyncIO with the context and timeout parameter\n3. Return (void function)\n\nParameters:\n  dwTimeoutMs (uint) - Timeout in milliseconds for the wait operation\n\nReturns:\n  void\n\nNotes:\n  - This is a convenience wrapper that supplies the global g_pServerContext\n  - The underlying WaitForAsyncIO function is a thunk to an external function pointer\n  - g_pServerContext is initialized by NET_InitializeClientContext and cleared by NET_ShutdownGlobalContext\n  - Used by network subsystem for synchronizing async I/O operations",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:0c7249cc723d27c36926c4cb05e7aa15",
      "callees": {
        "LoD/1.07": [
          "WaitForAsyncIO"
        ],
        "LoD/1.08": [
          "WaitForAsyncIO"
        ],
        "LoD/1.09": [
          "WaitForAsyncIO"
        ],
        "LoD/1.09b": [
          "WaitForAsyncIO"
        ],
        "LoD/1.09d": [
          "Ordinal_10177"
        ],
        "LoD/1.10": [
          "Ordinal_10151"
        ],
        "LoD/1.11": [
          "WaitOrProcessContextSlots"
        ],
        "LoD/1.11b": [
          "FindHashTableEntryById"
        ],
        "LoD/1.12a": [
          "SetUnitFieldBBC"
        ],
        "LoD/1.13c": [
          "FindHashTableEntryById"
        ],
        "LoD/1.13d": [
          "SetGameObjectProperty"
        ]
      },
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1,
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "0c7249cc723d27c36926c4cb05e7aa15",
        "LoD/1.08": "0c7249cc723d27c36926c4cb05e7aa15",
        "LoD/1.09": "0c7249cc723d27c36926c4cb05e7aa15",
        "LoD/1.09b": "0c7249cc723d27c36926c4cb05e7aa15",
        "LoD/1.09d": "0c7249cc723d27c36926c4cb05e7aa15",
        "LoD/1.10": "0c7249cc723d27c36926c4cb05e7aa15",
        "LoD/1.11": "0c7249cc723d27c36926c4cb05e7aa15",
        "LoD/1.11b": "0c7249cc723d27c36926c4cb05e7aa15",
        "LoD/1.12a": "0c7249cc723d27c36926c4cb05e7aa15",
        "LoD/1.13c": "0c7249cc723d27c36926c4cb05e7aa15",
        "LoD/1.13d": "0c7249cc723d27c36926c4cb05e7aa15"
      }
    },
    "d2net.dll_NET_ForwardToContextStub": {
      "addresses": {
        "LoD/1.07": "0x6FC32580",
        "LoD/1.08": "0x6FC32580",
        "LoD/1.09": "0x6FC02580",
        "LoD/1.09b": "0x6FC02580",
        "LoD/1.09d": "0x6FC02580",
        "LoD/1.10": "0x6FC021F0",
        "LoD/1.11": "0x6FBF5EC0",
        "LoD/1.11b": "0x6FBF5EC0",
        "LoD/1.12a": "0x6FBF7340",
        "LoD/1.13c": "0x6FBF6240",
        "LoD/1.13d": "0x6FBF72D0"
      },
      "rvas": {
        "LoD/1.07": "0x2580",
        "LoD/1.08": "0x2580",
        "LoD/1.09": "0x2580",
        "LoD/1.09b": "0x2580",
        "LoD/1.09d": "0x2580",
        "LoD/1.10": "0x21F0",
        "LoD/1.11": "0x5EC0",
        "LoD/1.11b": "0x5EC0",
        "LoD/1.12a": "0x7340",
        "LoD/1.13c": "0x6240",
        "LoD/1.13d": "0x72D0"
      },
      "sizes": {
        "LoD/1.07": 12,
        "LoD/1.08": 12,
        "LoD/1.09": 12,
        "LoD/1.09b": 12,
        "LoD/1.09d": 12,
        "LoD/1.10": 12,
        "LoD/1.11": 12,
        "LoD/1.11b": 12,
        "LoD/1.12a": 12,
        "LoD/1.13c": 12,
        "LoD/1.13d": 12
      },
      "name": "NET_ForwardToContextStub",
      "signature": "void NET_ForwardToContextStub(void)",
      "calling_convention": "__stdcall",
      "comment": "Forwards global server context to an external stub function.\n\nExported as Ordinal 10028 - Thunk/Wrapper for external function dispatch.\n\nClassification: Thunk/Wrapper - Single indirect call through function pointer table.\n\nAlgorithm:\n1. Load g_pServerContext from global address 0x6fc3b230\n2. Push context pointer as single parameter\n3. Call NoOpStub (indirect JMP through [0x6fc37084])\n4. Return to caller\n\nParameters:\n  None - Uses implicit global g_pServerContext\n\nReturns:\n  void - No explicit return value (external function may modify context)\n\nMemory Model:\n  - g_pServerContext: Global network context pointer, initialized by NET_InitializeClientContext\n  - NoOpStub: Import thunk that jumps to external function via pointer table\n  - Pointer table at 0x6fc37084 resolved at load time to external implementation\n\nSpecial Cases:\n  - If g_pServerContext is NULL (not initialized or after shutdown), behavior undefined\n  - External function implementation determines actual operation performed\n  - Named \"NoOpStub\" suggests the external target may be a placeholder or optional handler\n\nCross-References:\n  - g_pServerContext: Used by 30+ NET_* functions for network operations\n  - NoOpStub at 0x6fc32676: JMP [0x6fc37084] - indirect to external\n  - Similar pattern: NET_ForwardToStub10183 (Ordinal 10029) adds extra parameter\n\nDecompiler Discrepancy:\n  - Decompiler shows recursive NoOpStub() call due to unresolved indirect jump\n  - Actual behavior: single-param call to external function via import table",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:5acea7b093442b4d0fe7bb124f1c8b51",
      "callees": {
        "LoD/1.07": [
          "NoOpStub"
        ],
        "LoD/1.08": [
          "DoNothingStub"
        ],
        "LoD/1.09": [
          "DoNothingStub"
        ],
        "LoD/1.09b": [
          "DoNothingStub"
        ],
        "LoD/1.09d": [
          "DoNothingStub"
        ],
        "LoD/1.10": [
          "GetEntityFieldAt0x880"
        ],
        "LoD/1.11": [
          "DoNothingStub"
        ],
        "LoD/1.11b": [
          "DoNothingStub"
        ],
        "LoD/1.12a": [
          "GetEntityFieldAt0x880"
        ],
        "LoD/1.13c": [
          "GetEntityFieldAt0x880"
        ],
        "LoD/1.13d": [
          "GetEntityFieldAt0x880"
        ]
      },
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1,
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "5acea7b093442b4d0fe7bb124f1c8b51",
        "LoD/1.08": "5acea7b093442b4d0fe7bb124f1c8b51",
        "LoD/1.09": "5acea7b093442b4d0fe7bb124f1c8b51",
        "LoD/1.09b": "5acea7b093442b4d0fe7bb124f1c8b51",
        "LoD/1.09d": "5acea7b093442b4d0fe7bb124f1c8b51",
        "LoD/1.10": "5acea7b093442b4d0fe7bb124f1c8b51",
        "LoD/1.11": "5acea7b093442b4d0fe7bb124f1c8b51",
        "LoD/1.11b": "5acea7b093442b4d0fe7bb124f1c8b51",
        "LoD/1.12a": "5acea7b093442b4d0fe7bb124f1c8b51",
        "LoD/1.13c": "5acea7b093442b4d0fe7bb124f1c8b51",
        "LoD/1.13d": "5acea7b093442b4d0fe7bb124f1c8b51"
      }
    },
    "d2net.dll_NET_ForwardToStub10183": {
      "addresses": {
        "LoD/1.07": "0x6FC32590",
        "LoD/1.08": "0x6FC32590",
        "LoD/1.09": "0x6FC02590",
        "LoD/1.09b": "0x6FC02590",
        "LoD/1.09d": "0x6FC02590",
        "LoD/1.10": "0x6FC02620",
        "LoD/1.11": "0x6FBF5EA0",
        "LoD/1.11b": "0x6FBF5EA0",
        "LoD/1.12a": "0x6FBF7010",
        "LoD/1.13c": "0x6FBF5F10",
        "LoD/1.13d": "0x6FBF6FA0"
      },
      "rvas": {
        "LoD/1.07": "0x2590",
        "LoD/1.08": "0x2590",
        "LoD/1.09": "0x2590",
        "LoD/1.09b": "0x2590",
        "LoD/1.09d": "0x2590",
        "LoD/1.10": "0x2620",
        "LoD/1.11": "0x5EA0",
        "LoD/1.11b": "0x5EA0",
        "LoD/1.12a": "0x7010",
        "LoD/1.13c": "0x5F10",
        "LoD/1.13d": "0x6FA0"
      },
      "sizes": {
        "LoD/1.07": 20,
        "LoD/1.08": 20,
        "LoD/1.09": 20,
        "LoD/1.09b": 20,
        "LoD/1.09d": 20,
        "LoD/1.10": 20,
        "LoD/1.11": 20,
        "LoD/1.11b": 20,
        "LoD/1.12a": 20,
        "LoD/1.13c": 20,
        "LoD/1.13d": 20
      },
      "name": "NET_ForwardToStub10183",
      "signature": "void NET_ForwardToStub10183(int nParam)",
      "calling_convention": "__stdcall",
      "comment": "Forwards a parameter to FOG.StubOrdinal10183 with the global server context.\n\nClassification: Thunk/Wrapper\n\nAlgorithm:\n1. Load nParam from stack [ESP+4]\n2. Load g_pServerContext from global 0x6fc3b230\n3. Push nParam, then g_pServerContext\n4. Call StubOrdinal10183 (FOG.DLL import thunk)\n5. Return (cleans 4 bytes per __stdcall)\n\nParameters:\n  nParam (int) - Value forwarded as second parameter to StubOrdinal10183\n\nReturns:\n  void - No return value\n\nGlobals Referenced:\n  g_pServerContext (0x6fc3b230) - Server/network context pointer used by 30+ NET_/SNET_ functions\n\nCallees:\n  StubOrdinal10183 - FOG.DLL import thunk at 0x6fc3267c (JMP [0x6fc37088])\n\nNotes:\n  This is a thin wrapper that prepends the global server context before\n  forwarding to the FOG library. The actual implementation resides in FOG.DLL.",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:0c7249cc723d27c36926c4cb05e7aa15",
      "callees": {
        "LoD/1.07": [
          "StubOrdinal10183"
        ],
        "LoD/1.08": [
          "NoOpStub_v2"
        ],
        "LoD/1.09": [
          "NoOpStub_v2"
        ],
        "LoD/1.09b": [
          "NoOpStub_v2"
        ],
        "LoD/1.09d": [
          "NoOpStub_v2"
        ],
        "LoD/1.10": [
          "NoOpStub_v2"
        ],
        "LoD/1.11": [
          "NoOpStub_v2"
        ],
        "LoD/1.11b": [
          "NoOpStub_v2"
        ],
        "LoD/1.12a": [
          "NoOpStub_v2"
        ],
        "LoD/1.13c": [
          "NoOpStub_v2"
        ],
        "LoD/1.13d": [
          "NoOpStub_v2"
        ]
      },
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1,
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "0c7249cc723d27c36926c4cb05e7aa15",
        "LoD/1.08": "0c7249cc723d27c36926c4cb05e7aa15",
        "LoD/1.09": "0c7249cc723d27c36926c4cb05e7aa15",
        "LoD/1.09b": "0c7249cc723d27c36926c4cb05e7aa15",
        "LoD/1.09d": "0c7249cc723d27c36926c4cb05e7aa15",
        "LoD/1.10": "0c7249cc723d27c36926c4cb05e7aa15",
        "LoD/1.11": "0c7249cc723d27c36926c4cb05e7aa15",
        "LoD/1.11b": "0c7249cc723d27c36926c4cb05e7aa15",
        "LoD/1.12a": "0c7249cc723d27c36926c4cb05e7aa15",
        "LoD/1.13c": "0c7249cc723d27c36926c4cb05e7aa15",
        "LoD/1.13d": "0c7249cc723d27c36926c4cb05e7aa15"
      }
    },
    "d2net.dll_EnterCriticalSectionWrapper": {
      "addresses": {
        "LoD/1.07": "0x6FC325B0",
        "LoD/1.08": "0x6FC325B0",
        "LoD/1.09": "0x6FC025B0",
        "LoD/1.09b": "0x6FC025B0",
        "LoD/1.09d": "0x6FC025B0",
        "LoD/1.10": "0x6FC02640",
        "LoD/1.11": "0x6FBF5E66",
        "LoD/1.11b": "0x6FBF5E66",
        "LoD/1.12a": "0x6FBF5EAC",
        "LoD/1.13c": "0x6FBF5ED6",
        "LoD/1.13d": "0x6FBF5E3C"
      },
      "rvas": {
        "LoD/1.07": "0x25B0",
        "LoD/1.08": "0x25B0",
        "LoD/1.09": "0x25B0",
        "LoD/1.09b": "0x25B0",
        "LoD/1.09d": "0x25B0",
        "LoD/1.10": "0x2640",
        "LoD/1.11": "0x5E66",
        "LoD/1.11b": "0x5E66",
        "LoD/1.12a": "0x5EAC",
        "LoD/1.13c": "0x5ED6",
        "LoD/1.13d": "0x5E3C"
      },
      "sizes": {
        "LoD/1.07": 6,
        "LoD/1.08": 6,
        "LoD/1.09": 6,
        "LoD/1.09b": 6,
        "LoD/1.09d": 6,
        "LoD/1.10": 6,
        "LoD/1.11": 6,
        "LoD/1.11b": 6,
        "LoD/1.12a": 6,
        "LoD/1.13c": 6,
        "LoD/1.13d": 6
      },
      "name": "EnterCriticalSectionWrapper",
      "signature": "void EnterCriticalSectionWrapper(LPCRITICAL_SECTION pCritSect)",
      "calling_convention": "__fastcall",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:e3e7225badfcf3c2e051c42d71d7237a",
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1,
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.08": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09d": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.10": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.12a": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13c": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13d": "e3e7225badfcf3c2e051c42d71d7237a"
      }
    },
    "d2net.dll_ResolveHostnameToIP": {
      "addresses": {
        "LoD/1.07": "0x6FC325B6",
        "LoD/1.08": "0x6FC325B6",
        "LoD/1.09": "0x6FC025B6",
        "LoD/1.09b": "0x6FC025B6",
        "LoD/1.09d": "0x6FC025B6",
        "LoD/1.10": "0x6FC02646",
        "LoD/1.11": "0x6FBF5DA6",
        "LoD/1.11b": "0x6FBF5DA6",
        "LoD/1.12a": "0x6FBF5E16",
        "LoD/1.13c": "0x6FBF5E16",
        "LoD/1.13d": "0x6FBF5DA6"
      },
      "rvas": {
        "LoD/1.07": "0x25B6",
        "LoD/1.08": "0x25B6",
        "LoD/1.09": "0x25B6",
        "LoD/1.09b": "0x25B6",
        "LoD/1.09d": "0x25B6",
        "LoD/1.10": "0x2646",
        "LoD/1.11": "0x5DA6",
        "LoD/1.11b": "0x5DA6",
        "LoD/1.12a": "0x5E16",
        "LoD/1.13c": "0x5E16",
        "LoD/1.13d": "0x5DA6"
      },
      "sizes": {
        "LoD/1.07": 6,
        "LoD/1.08": 6,
        "LoD/1.09": 6,
        "LoD/1.09b": 6,
        "LoD/1.09d": 6,
        "LoD/1.10": 6,
        "LoD/1.11": 6,
        "LoD/1.11b": 6,
        "LoD/1.12a": 6,
        "LoD/1.13c": 6,
        "LoD/1.13d": 6
      },
      "name": "ResolveHostnameToIP",
      "signature": "char * ResolveHostnameToIP(char * szHostname)",
      "calling_convention": "__fastcall",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:e3e7225badfcf3c2e051c42d71d7237a",
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1,
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.08": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09d": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.10": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.12a": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13c": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13d": "e3e7225badfcf3c2e051c42d71d7237a"
      }
    },
    "d2net.dll_FogFatalError": {
      "addresses": {
        "LoD/1.07": "0x6FC325BC",
        "LoD/1.08": "0x6FC325BC",
        "LoD/1.09": "0x6FC025BC",
        "LoD/1.09b": "0x6FC025BC",
        "LoD/1.09d": "0x6FC025BC",
        "LoD/1.10": "0x6FC0264C",
        "LoD/1.11": "0x6FBF5DD0",
        "LoD/1.11b": "0x6FBF5DD6",
        "LoD/1.12a": "0x6FBF5E64",
        "LoD/1.13c": "0x6FBF5E40",
        "LoD/1.13d": "0x6FBF5DF4"
      },
      "rvas": {
        "LoD/1.07": "0x25BC",
        "LoD/1.08": "0x25BC",
        "LoD/1.09": "0x25BC",
        "LoD/1.09b": "0x25BC",
        "LoD/1.09d": "0x25BC",
        "LoD/1.10": "0x264C",
        "LoD/1.11": "0x5DD0",
        "LoD/1.11b": "0x5DD6",
        "LoD/1.12a": "0x5E64",
        "LoD/1.13c": "0x5E40",
        "LoD/1.13d": "0x5DF4"
      },
      "sizes": {
        "LoD/1.07": 6,
        "LoD/1.08": 6,
        "LoD/1.09": 6,
        "LoD/1.09b": 6,
        "LoD/1.09d": 6,
        "LoD/1.10": 6,
        "LoD/1.11": 6,
        "LoD/1.11b": 6,
        "LoD/1.12a": 6,
        "LoD/1.13c": 6,
        "LoD/1.13d": 6
      },
      "name": "FogFatalError",
      "signature": "void FogFatalError(char * szMessage, char * szFile, int nLine)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:e3e7225badfcf3c2e051c42d71d7237a",
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1,
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.08": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09d": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.10": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.12a": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13c": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13d": "e3e7225badfcf3c2e051c42d71d7237a"
      }
    },
    "d2net.dll_FogMemAlloc": {
      "addresses": {
        "LoD/1.07": "0x6FC325C2",
        "LoD/1.08": "0x6FC325C2",
        "LoD/1.09": "0x6FC025C2",
        "LoD/1.09b": "0x6FC025C2",
        "LoD/1.09d": "0x6FC025C2",
        "LoD/1.10": "0x6FC02652",
        "LoD/1.11": "0x6FBF5DC4",
        "LoD/1.11b": "0x6FBF5DCA",
        "LoD/1.12a": "0x6FBF5EE8",
        "LoD/1.13c": "0x6FBF5E34",
        "LoD/1.13d": "0x6FBF5E78"
      },
      "rvas": {
        "LoD/1.07": "0x25C2",
        "LoD/1.08": "0x25C2",
        "LoD/1.09": "0x25C2",
        "LoD/1.09b": "0x25C2",
        "LoD/1.09d": "0x25C2",
        "LoD/1.10": "0x2652",
        "LoD/1.11": "0x5DC4",
        "LoD/1.11b": "0x5DCA",
        "LoD/1.12a": "0x5EE8",
        "LoD/1.13c": "0x5E34",
        "LoD/1.13d": "0x5E78"
      },
      "sizes": {
        "LoD/1.07": 6,
        "LoD/1.08": 6,
        "LoD/1.09": 6,
        "LoD/1.09b": 6,
        "LoD/1.09d": 6,
        "LoD/1.10": 6,
        "LoD/1.11": 6,
        "LoD/1.11b": 6,
        "LoD/1.12a": 6,
        "LoD/1.13c": 6,
        "LoD/1.13d": 6
      },
      "name": "FogMemAlloc",
      "signature": "void * FogMemAlloc(dword nSize, char * szFile, int nLine)",
      "calling_convention": "__fastcall",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:e3e7225badfcf3c2e051c42d71d7237a",
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1,
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.08": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09d": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.10": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.12a": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13c": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13d": "e3e7225badfcf3c2e051c42d71d7237a"
      }
    },
    "d2net.dll_closesocket": {
      "addresses": {
        "LoD/1.07": "0x6FC325C8",
        "LoD/1.08": "0x6FC325C8",
        "LoD/1.09": "0x6FC025C8",
        "LoD/1.09b": "0x6FC025C8",
        "LoD/1.09d": "0x6FC025C8",
        "LoD/1.10": "0x6FC02658",
        "LoD/1.11": "0x6FBF5D8E",
        "LoD/1.11b": "0x6FBF5D8E",
        "LoD/1.12a": "0x6FBF5DFE",
        "LoD/1.13c": "0x6FBF5DFE",
        "LoD/1.13d": "0x6FBF5D8E"
      },
      "rvas": {
        "LoD/1.07": "0x25C8",
        "LoD/1.08": "0x25C8",
        "LoD/1.09": "0x25C8",
        "LoD/1.09b": "0x25C8",
        "LoD/1.09d": "0x25C8",
        "LoD/1.10": "0x2658",
        "LoD/1.11": "0x5D8E",
        "LoD/1.11b": "0x5D8E",
        "LoD/1.12a": "0x5DFE",
        "LoD/1.13c": "0x5DFE",
        "LoD/1.13d": "0x5D8E"
      },
      "sizes": {
        "LoD/1.07": 6,
        "LoD/1.08": 6,
        "LoD/1.09": 6,
        "LoD/1.09b": 6,
        "LoD/1.09d": 6,
        "LoD/1.10": 6,
        "LoD/1.11": 6,
        "LoD/1.11b": 6,
        "LoD/1.12a": 6,
        "LoD/1.13c": 6,
        "LoD/1.13d": 6
      },
      "name": "closesocket",
      "signature": "void closesocket(SOCKET sSocket)",
      "calling_convention": "__fastcall",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:e3e7225badfcf3c2e051c42d71d7237a",
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1,
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.08": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09d": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.10": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.12a": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13c": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13d": "e3e7225badfcf3c2e051c42d71d7237a"
      }
    },
    "d2net.dll_ReleasePoolAllocation": {
      "addresses": {
        "LoD/1.07": "0x6FC325CE",
        "LoD/1.08": "0x6FC325CE",
        "LoD/1.09": "0x6FC025CE",
        "LoD/1.09b": "0x6FC025CE",
        "LoD/1.09d": "0x6FC025CE",
        "LoD/1.10": "0x6FC0265E",
        "LoD/1.11": "0x6FBF5D70",
        "LoD/1.11b": "0x6FBF5D76",
        "LoD/1.12a": "0x6FBF5DE0",
        "LoD/1.13c": "0x6FBF5DE0",
        "LoD/1.13d": "0x6FBF5D70"
      },
      "rvas": {
        "LoD/1.07": "0x25CE",
        "LoD/1.08": "0x25CE",
        "LoD/1.09": "0x25CE",
        "LoD/1.09b": "0x25CE",
        "LoD/1.09d": "0x25CE",
        "LoD/1.10": "0x265E",
        "LoD/1.11": "0x5D70",
        "LoD/1.11b": "0x5D76",
        "LoD/1.12a": "0x5DE0",
        "LoD/1.13c": "0x5DE0",
        "LoD/1.13d": "0x5D70"
      },
      "sizes": {
        "LoD/1.07": 6,
        "LoD/1.08": 6,
        "LoD/1.09": 6,
        "LoD/1.09b": 6,
        "LoD/1.09d": 6,
        "LoD/1.10": 6,
        "LoD/1.11": 6,
        "LoD/1.11b": 6,
        "LoD/1.12a": 6,
        "LoD/1.13c": 6,
        "LoD/1.13d": 6
      },
      "name": "ReleasePoolAllocation",
      "signature": "int ReleasePoolAllocation(void)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:e3e7225badfcf3c2e051c42d71d7237a",
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1,
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.08": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09d": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.10": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.12a": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13c": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13d": "e3e7225badfcf3c2e051c42d71d7237a"
      }
    },
    "d2net.dll_DecodeHuffmanStream": {
      "addresses": {
        "LoD/1.07": "0x6FC325D4",
        "LoD/1.08": "0x6FC325D4",
        "LoD/1.09": "0x6FC025D4",
        "LoD/1.09b": "0x6FC025D4",
        "LoD/1.09d": "0x6FC025D4",
        "LoD/1.10": "0x6FC02664",
        "LoD/1.11": "0x6FBF5D7C",
        "LoD/1.11b": "0x6FBF5D82",
        "LoD/1.12a": "0x6FBF5DEC",
        "LoD/1.13c": "0x6FBF5DEC",
        "LoD/1.13d": "0x6FBF5D7C"
      },
      "rvas": {
        "LoD/1.07": "0x25D4",
        "LoD/1.08": "0x25D4",
        "LoD/1.09": "0x25D4",
        "LoD/1.09b": "0x25D4",
        "LoD/1.09d": "0x25D4",
        "LoD/1.10": "0x2664",
        "LoD/1.11": "0x5D7C",
        "LoD/1.11b": "0x5D82",
        "LoD/1.12a": "0x5DEC",
        "LoD/1.13c": "0x5DEC",
        "LoD/1.13d": "0x5D7C"
      },
      "sizes": {
        "LoD/1.07": 6,
        "LoD/1.08": 6,
        "LoD/1.09": 6,
        "LoD/1.09b": 6,
        "LoD/1.09d": 6,
        "LoD/1.10": 6,
        "LoD/1.11": 6,
        "LoD/1.11b": 6,
        "LoD/1.12a": 6,
        "LoD/1.13c": 6,
        "LoD/1.13d": 6
      },
      "name": "DecodeHuffmanStream",
      "signature": "int DecodeHuffmanStream(byte * pbOutBuf, int nOutSize, byte * pbInBuf, int nInSize)",
      "calling_convention": "__fastcall",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:e3e7225badfcf3c2e051c42d71d7237a",
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1,
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.08": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09d": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.10": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.12a": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13c": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13d": "e3e7225badfcf3c2e051c42d71d7237a"
      }
    },
    "d2net.dll_FogAssert": {
      "addresses": {
        "LoD/1.07": "0x6FC325DA",
        "LoD/1.08": "0x6FC325DA",
        "LoD/1.09": "0x6FC025DA",
        "LoD/1.09b": "0x6FC025DA",
        "LoD/1.09d": "0x6FC025DA",
        "LoD/1.10": "0x6FC0266A",
        "LoD/1.11": "0x6FBF5D9A",
        "LoD/1.11b": "0x6FBF5D9A",
        "LoD/1.12a": "0x6FBF5E0A",
        "LoD/1.13c": "0x6FBF5E0A",
        "LoD/1.13d": "0x6FBF5D9A"
      },
      "rvas": {
        "LoD/1.07": "0x25DA",
        "LoD/1.08": "0x25DA",
        "LoD/1.09": "0x25DA",
        "LoD/1.09b": "0x25DA",
        "LoD/1.09d": "0x25DA",
        "LoD/1.10": "0x266A",
        "LoD/1.11": "0x5D9A",
        "LoD/1.11b": "0x5D9A",
        "LoD/1.12a": "0x5E0A",
        "LoD/1.13c": "0x5E0A",
        "LoD/1.13d": "0x5D9A"
      },
      "sizes": {
        "LoD/1.07": 6,
        "LoD/1.08": 6,
        "LoD/1.09": 6,
        "LoD/1.09b": 6,
        "LoD/1.09d": 6,
        "LoD/1.10": 6,
        "LoD/1.11": 6,
        "LoD/1.11b": 6,
        "LoD/1.12a": 6,
        "LoD/1.13c": 6,
        "LoD/1.13d": 6
      },
      "name": "FogAssert",
      "signature": "void FogAssert(char * szExpr, char * szFile, int nLine)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:e3e7225badfcf3c2e051c42d71d7237a",
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1,
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.08": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09d": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.10": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.12a": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13c": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13d": "e3e7225badfcf3c2e051c42d71d7237a"
      }
    },
    "d2net.dll_BuildHuffmanDecodeTables": {
      "addresses": {
        "LoD/1.07": "0x6FC325E0",
        "LoD/1.08": "0x6FC325E0",
        "LoD/1.09": "0x6FC025E0",
        "LoD/1.09b": "0x6FC025E0",
        "LoD/1.09d": "0x6FC025E0",
        "LoD/1.10": "0x6FC02670",
        "LoD/1.11": "0x6FBF5DD6",
        "LoD/1.11b": "0x6FBF5DBE",
        "LoD/1.12a": "0x6FBF5EF4",
        "LoD/1.13c": "0x6FBF5E46",
        "LoD/1.13d": "0x6FBF5E84"
      },
      "rvas": {
        "LoD/1.07": "0x25E0",
        "LoD/1.08": "0x25E0",
        "LoD/1.09": "0x25E0",
        "LoD/1.09b": "0x25E0",
        "LoD/1.09d": "0x25E0",
        "LoD/1.10": "0x2670",
        "LoD/1.11": "0x5DD6",
        "LoD/1.11b": "0x5DBE",
        "LoD/1.12a": "0x5EF4",
        "LoD/1.13c": "0x5E46",
        "LoD/1.13d": "0x5E84"
      },
      "sizes": {
        "LoD/1.07": 6,
        "LoD/1.08": 6,
        "LoD/1.09": 6,
        "LoD/1.09b": 6,
        "LoD/1.09d": 6,
        "LoD/1.10": 6,
        "LoD/1.11": 6,
        "LoD/1.11b": 6,
        "LoD/1.12a": 6,
        "LoD/1.13c": 6,
        "LoD/1.13d": 6
      },
      "name": "BuildHuffmanDecodeTables",
      "signature": "int BuildHuffmanDecodeTables(byte * pbBitLengths)",
      "calling_convention": "__fastcall",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:e3e7225badfcf3c2e051c42d71d7237a",
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1,
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.08": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09d": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.10": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.12a": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13c": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13d": "e3e7225badfcf3c2e051c42d71d7237a"
      }
    },
    "d2net.dll_QueueReceivedMessage": {
      "addresses": {
        "LoD/1.07": "0x6FC325E6",
        "LoD/1.08": "0x6FC325E6",
        "LoD/1.09": "0x6FC025E6",
        "LoD/1.09b": "0x6FC025E6",
        "LoD/1.09d": "0x6FC025E6",
        "LoD/1.10": "0x6FC02676",
        "LoD/1.11": "0x6FBF5DEE",
        "LoD/1.11b": "0x6FBF5DEE",
        "LoD/1.12a": "0x6FBF5E28",
        "LoD/1.13c": "0x6FBF5E5E",
        "LoD/1.13d": "0x6FBF5DB8"
      },
      "rvas": {
        "LoD/1.07": "0x25E6",
        "LoD/1.08": "0x25E6",
        "LoD/1.09": "0x25E6",
        "LoD/1.09b": "0x25E6",
        "LoD/1.09d": "0x25E6",
        "LoD/1.10": "0x2676",
        "LoD/1.11": "0x5DEE",
        "LoD/1.11b": "0x5DEE",
        "LoD/1.12a": "0x5E28",
        "LoD/1.13c": "0x5E5E",
        "LoD/1.13d": "0x5DB8"
      },
      "sizes": {
        "LoD/1.07": 6,
        "LoD/1.08": 6,
        "LoD/1.09": 6,
        "LoD/1.09b": 6,
        "LoD/1.09d": 6,
        "LoD/1.10": 6,
        "LoD/1.11": 6,
        "LoD/1.11b": 6,
        "LoD/1.12a": 6,
        "LoD/1.13c": 6,
        "LoD/1.13d": 6
      },
      "name": "QueueReceivedMessage",
      "signature": "int QueueReceivedMessage(int nServerCtx)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:e3e7225badfcf3c2e051c42d71d7237a",
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1,
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.08": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09d": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.10": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.12a": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13c": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13d": "e3e7225badfcf3c2e051c42d71d7237a"
      }
    },
    "d2net.dll_WaitForArchiveEvent": {
      "addresses": {
        "LoD/1.07": "0x6FC325EC",
        "LoD/1.08": "0x6FC325EC",
        "LoD/1.09": "0x6FC025EC",
        "LoD/1.09b": "0x6FC025EC",
        "LoD/1.09d": "0x6FC025EC",
        "LoD/1.10": "0x6FC026CA",
        "LoD/1.11": "0x6FBF5E3C",
        "LoD/1.11b": "0x6FBF5E3C",
        "LoD/1.12a": "0x6FBF5E7C",
        "LoD/1.13c": "0x6FBF5EAC",
        "LoD/1.13d": "0x6FBF5E0C"
      },
      "rvas": {
        "LoD/1.07": "0x25EC",
        "LoD/1.08": "0x25EC",
        "LoD/1.09": "0x25EC",
        "LoD/1.09b": "0x25EC",
        "LoD/1.09d": "0x25EC",
        "LoD/1.10": "0x26CA",
        "LoD/1.11": "0x5E3C",
        "LoD/1.11b": "0x5E3C",
        "LoD/1.12a": "0x5E7C",
        "LoD/1.13c": "0x5EAC",
        "LoD/1.13d": "0x5E0C"
      },
      "sizes": {
        "LoD/1.07": 6,
        "LoD/1.08": 6,
        "LoD/1.09": 6,
        "LoD/1.09b": 6,
        "LoD/1.09d": 6,
        "LoD/1.10": 6,
        "LoD/1.11": 6,
        "LoD/1.11b": 6,
        "LoD/1.12a": 6,
        "LoD/1.13c": 6,
        "LoD/1.13d": 6
      },
      "name": "WaitForArchiveEvent",
      "signature": "DWORD WaitForArchiveEvent(int * pArchive, DWORD dwTimeout)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:e3e7225badfcf3c2e051c42d71d7237a",
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1,
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.08": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09d": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.10": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.12a": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13c": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13d": "e3e7225badfcf3c2e051c42d71d7237a"
      }
    },
    "d2net.dll_InitializeNetworkContext": {
      "addresses": {
        "LoD/1.07": "0x6FC325F2",
        "LoD/1.08": "0x6FC325F2",
        "LoD/1.09": "0x6FC025F2",
        "LoD/1.09b": "0x6FC025F2",
        "LoD/1.09d": "0x6FC025F2",
        "LoD/1.10": "0x6FC02682",
        "LoD/1.11": "0x6FBF5E24",
        "LoD/1.11b": "0x6FBF5E24",
        "LoD/1.12a": "0x6FBF5E5E",
        "LoD/1.13c": "0x6FBF5E94",
        "LoD/1.13d": "0x6FBF5DEE"
      },
      "rvas": {
        "LoD/1.07": "0x25F2",
        "LoD/1.08": "0x25F2",
        "LoD/1.09": "0x25F2",
        "LoD/1.09b": "0x25F2",
        "LoD/1.09d": "0x25F2",
        "LoD/1.10": "0x2682",
        "LoD/1.11": "0x5E24",
        "LoD/1.11b": "0x5E24",
        "LoD/1.12a": "0x5E5E",
        "LoD/1.13c": "0x5E94",
        "LoD/1.13d": "0x5DEE"
      },
      "sizes": {
        "LoD/1.07": 6,
        "LoD/1.08": 6,
        "LoD/1.09": 6,
        "LoD/1.09b": 6,
        "LoD/1.09d": 6,
        "LoD/1.10": 6,
        "LoD/1.11": 6,
        "LoD/1.11b": 6,
        "LoD/1.12a": 6,
        "LoD/1.13c": 6,
        "LoD/1.13d": 6
      },
      "name": "InitializeNetworkContext",
      "signature": "int * InitializeNetworkContext(int nNetworkMode, int nMaxConnections, ushort wPort, int nUseWinNT, int nOnConnect, int nOnDisconnect, int nOnReceive, int nOnSend)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:e3e7225badfcf3c2e051c42d71d7237a",
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1,
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.08": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09d": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.10": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.12a": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13c": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13d": "e3e7225badfcf3c2e051c42d71d7237a"
      }
    },
    "d2net.dll_ExchangeStructArrayValue": {
      "addresses": {
        "LoD/1.07": "0x6FC325F8",
        "LoD/1.08": "0x6FC325F8",
        "LoD/1.09": "0x6FC025F8",
        "LoD/1.09b": "0x6FC025F8",
        "LoD/1.09d": "0x6FC025F8",
        "LoD/1.10": "0x6FC02688",
        "LoD/1.11": "0x6FBF5E90",
        "LoD/1.11b": "0x6FBF5E90",
        "LoD/1.12a": "0x6FBF5ED6",
        "LoD/1.13c": "0x6FBF5F00",
        "LoD/1.13d": "0x6FBF5E66"
      },
      "rvas": {
        "LoD/1.07": "0x25F8",
        "LoD/1.08": "0x25F8",
        "LoD/1.09": "0x25F8",
        "LoD/1.09b": "0x25F8",
        "LoD/1.09d": "0x25F8",
        "LoD/1.10": "0x2688",
        "LoD/1.11": "0x5E90",
        "LoD/1.11b": "0x5E90",
        "LoD/1.12a": "0x5ED6",
        "LoD/1.13c": "0x5F00",
        "LoD/1.13d": "0x5E66"
      },
      "sizes": {
        "LoD/1.07": 6,
        "LoD/1.08": 6,
        "LoD/1.09": 6,
        "LoD/1.09b": 6,
        "LoD/1.09d": 6,
        "LoD/1.10": 6,
        "LoD/1.11": 6,
        "LoD/1.11b": 6,
        "LoD/1.12a": 6,
        "LoD/1.13c": 6,
        "LoD/1.13d": 6
      },
      "name": "ExchangeStructArrayValue",
      "signature": "dword ExchangeStructArrayValue(void * pStruct, int nIndex, dword dwNewValue)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:e3e7225badfcf3c2e051c42d71d7237a",
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1,
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.08": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09d": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.10": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.12a": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13c": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13d": "e3e7225badfcf3c2e051c42d71d7237a"
      }
    },
    "d2net.dll_AddUniqueKeyValuePair": {
      "addresses": {
        "LoD/1.07": "0x6FC325FE",
        "LoD/1.08": "0x6FC325FE",
        "LoD/1.09": "0x6FC025FE",
        "LoD/1.09b": "0x6FC025FE",
        "LoD/1.09d": "0x6FC025FE",
        "LoD/1.10": "0x6FC0268E",
        "LoD/1.11": "0x6FBF5E8A",
        "LoD/1.11b": "0x6FBF5E8A",
        "LoD/1.12a": "0x6FBF5ED0",
        "LoD/1.13c": "0x6FBF5EFA",
        "LoD/1.13d": "0x6FBF5E60"
      },
      "rvas": {
        "LoD/1.07": "0x25FE",
        "LoD/1.08": "0x25FE",
        "LoD/1.09": "0x25FE",
        "LoD/1.09b": "0x25FE",
        "LoD/1.09d": "0x25FE",
        "LoD/1.10": "0x268E",
        "LoD/1.11": "0x5E8A",
        "LoD/1.11b": "0x5E8A",
        "LoD/1.12a": "0x5ED0",
        "LoD/1.13c": "0x5EFA",
        "LoD/1.13d": "0x5E60"
      },
      "sizes": {
        "LoD/1.07": 6,
        "LoD/1.08": 6,
        "LoD/1.09": 6,
        "LoD/1.09b": 6,
        "LoD/1.09d": 6,
        "LoD/1.10": 6,
        "LoD/1.11": 6,
        "LoD/1.11b": 6,
        "LoD/1.12a": 6,
        "LoD/1.13c": 6,
        "LoD/1.13d": 6
      },
      "name": "AddUniqueKeyValuePair",
      "signature": "void AddUniqueKeyValuePair(void * pContainer, dword dwValue, int nKey)",
      "calling_convention": "__fastcall",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:e3e7225badfcf3c2e051c42d71d7237a",
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1,
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.08": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09d": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.10": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.12a": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13c": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13d": "e3e7225badfcf3c2e051c42d71d7237a"
      }
    },
    "d2net.dll_SetArchivePriority": {
      "addresses": {
        "LoD/1.07": "0x6FC32604",
        "LoD/1.08": "0x6FC32604",
        "LoD/1.09": "0x6FC02604",
        "LoD/1.09b": "0x6FC02604",
        "LoD/1.09d": "0x6FC02604",
        "LoD/1.10": "0x6FC02694",
        "LoD/1.11": "0x6FBF5E0C",
        "LoD/1.11b": "0x6FBF5E0C",
        "LoD/1.12a": "0x6FBF5E46",
        "LoD/1.13c": "0x6FBF5E7C",
        "LoD/1.13d": "0x6FBF5DD6"
      },
      "rvas": {
        "LoD/1.07": "0x2604",
        "LoD/1.08": "0x2604",
        "LoD/1.09": "0x2604",
        "LoD/1.09b": "0x2604",
        "LoD/1.09d": "0x2604",
        "LoD/1.10": "0x2694",
        "LoD/1.11": "0x5E0C",
        "LoD/1.11b": "0x5E0C",
        "LoD/1.12a": "0x5E46",
        "LoD/1.13c": "0x5E7C",
        "LoD/1.13d": "0x5DD6"
      },
      "sizes": {
        "LoD/1.07": 6,
        "LoD/1.08": 6,
        "LoD/1.09": 6,
        "LoD/1.09b": 6,
        "LoD/1.09d": 6,
        "LoD/1.10": 6,
        "LoD/1.11": 6,
        "LoD/1.11b": 6,
        "LoD/1.12a": 6,
        "LoD/1.13c": 6,
        "LoD/1.13d": 6
      },
      "name": "SetArchivePriority",
      "signature": "void SetArchivePriority(void * pArchive, uint dwPriority)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:e3e7225badfcf3c2e051c42d71d7237a",
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1,
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.08": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09d": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.10": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.12a": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13c": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13d": "e3e7225badfcf3c2e051c42d71d7237a"
      }
    },
    "d2net.dll_GetField880": {
      "addresses": {
        "LoD/1.07": "0x6FC3260A",
        "LoD/1.08": "0x6FC3260A",
        "LoD/1.09": "0x6FC0260A",
        "LoD/1.09b": "0x6FC0260A",
        "LoD/1.09d": "0x6FC0260A",
        "LoD/1.10": "0x6FC0269A",
        "LoD/1.11": "0x6FBF5E78",
        "LoD/1.11b": "0x6FBF5E78",
        "LoD/1.12a": "0x6FBF5EBE",
        "LoD/1.13c": "0x6FBF5EE8",
        "LoD/1.13d": "0x6FBF5E4E"
      },
      "rvas": {
        "LoD/1.07": "0x260A",
        "LoD/1.08": "0x260A",
        "LoD/1.09": "0x260A",
        "LoD/1.09b": "0x260A",
        "LoD/1.09d": "0x260A",
        "LoD/1.10": "0x269A",
        "LoD/1.11": "0x5E78",
        "LoD/1.11b": "0x5E78",
        "LoD/1.12a": "0x5EBE",
        "LoD/1.13c": "0x5EE8",
        "LoD/1.13d": "0x5E4E"
      },
      "sizes": {
        "LoD/1.07": 6,
        "LoD/1.08": 6,
        "LoD/1.09": 6,
        "LoD/1.09b": 6,
        "LoD/1.09d": 6,
        "LoD/1.10": 6,
        "LoD/1.11": 6,
        "LoD/1.11b": 6,
        "LoD/1.12a": 6,
        "LoD/1.13c": 6,
        "LoD/1.13d": 6
      },
      "name": "GetField880",
      "signature": "int GetField880(void * pStruct)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:e3e7225badfcf3c2e051c42d71d7237a",
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1,
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.08": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09d": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.10": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.12a": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13c": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13d": "e3e7225badfcf3c2e051c42d71d7237a"
      }
    },
    "d2net.dll_SetFieldBD0": {
      "addresses": {
        "LoD/1.07": "0x6FC32610",
        "LoD/1.08": "0x6FC32610",
        "LoD/1.09": "0x6FC02610",
        "LoD/1.09b": "0x6FC02610",
        "LoD/1.09d": "0x6FC02610",
        "LoD/1.10": "0x6FC026D0",
        "LoD/1.11": "0x6FBF5E6C",
        "LoD/1.11b": "0x6FBF5E6C",
        "LoD/1.12a": "0x6FBF5EB2",
        "LoD/1.13c": "0x6FBF5EDC",
        "LoD/1.13d": "0x6FBF5E42"
      },
      "rvas": {
        "LoD/1.07": "0x2610",
        "LoD/1.08": "0x2610",
        "LoD/1.09": "0x2610",
        "LoD/1.09b": "0x2610",
        "LoD/1.09d": "0x2610",
        "LoD/1.10": "0x26D0",
        "LoD/1.11": "0x5E6C",
        "LoD/1.11b": "0x5E6C",
        "LoD/1.12a": "0x5EB2",
        "LoD/1.13c": "0x5EDC",
        "LoD/1.13d": "0x5E42"
      },
      "sizes": {
        "LoD/1.07": 6,
        "LoD/1.08": 6,
        "LoD/1.09": 6,
        "LoD/1.09b": 6,
        "LoD/1.09d": 6,
        "LoD/1.10": 6,
        "LoD/1.11": 6,
        "LoD/1.11b": 6,
        "LoD/1.12a": 6,
        "LoD/1.13c": 6,
        "LoD/1.13d": 6
      },
      "name": "SetFieldBD0",
      "signature": "void SetFieldBD0(void * pStruct, dword dwValue)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:e3e7225badfcf3c2e051c42d71d7237a",
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1,
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.08": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09d": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.10": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.12a": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13c": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13d": "e3e7225badfcf3c2e051c42d71d7237a"
      }
    },
    "d2net.dll_ShutdownNetworkContext": {
      "addresses": {
        "LoD/1.07": "0x6FC32616",
        "LoD/1.08": "0x6FC32616",
        "LoD/1.09": "0x6FC02616",
        "LoD/1.09b": "0x6FC02616",
        "LoD/1.09d": "0x6FC02616",
        "LoD/1.10": "0x6FC026A6",
        "LoD/1.11": "0x6FBF5DE8",
        "LoD/1.11b": "0x6FBF5DE8",
        "LoD/1.12a": "0x6FBF5EA0",
        "LoD/1.13c": "0x6FBF5E58",
        "LoD/1.13d": "0x6FBF5E30"
      },
      "rvas": {
        "LoD/1.07": "0x2616",
        "LoD/1.08": "0x2616",
        "LoD/1.09": "0x2616",
        "LoD/1.09b": "0x2616",
        "LoD/1.09d": "0x2616",
        "LoD/1.10": "0x26A6",
        "LoD/1.11": "0x5DE8",
        "LoD/1.11b": "0x5DE8",
        "LoD/1.12a": "0x5EA0",
        "LoD/1.13c": "0x5E58",
        "LoD/1.13d": "0x5E30"
      },
      "sizes": {
        "LoD/1.07": 6,
        "LoD/1.08": 6,
        "LoD/1.09": 6,
        "LoD/1.09b": 6,
        "LoD/1.09d": 6,
        "LoD/1.10": 6,
        "LoD/1.11": 6,
        "LoD/1.11b": 6,
        "LoD/1.12a": 6,
        "LoD/1.13c": 6,
        "LoD/1.13d": 6
      },
      "name": "ShutdownNetworkContext",
      "signature": "int ShutdownNetworkContext(int * pContext, uint * pdwBuffer, uint dwSize)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:e3e7225badfcf3c2e051c42d71d7237a",
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1,
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.08": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09d": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.10": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.12a": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13c": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13d": "e3e7225badfcf3c2e051c42d71d7237a"
      }
    },
    "d2net.dll_DequeueBufferAndCopy": {
      "addresses": {
        "LoD/1.07": "0x6FC3261C",
        "LoD/1.08": "0x6FC3261C",
        "LoD/1.09": "0x6FC0261C",
        "LoD/1.09b": "0x6FC0261C",
        "LoD/1.09d": "0x6FC0261C",
        "LoD/1.10": "0x6FC026AC",
        "LoD/1.11": "0x6FBF5E54",
        "LoD/1.11b": "0x6FBF5E54",
        "LoD/1.12a": "0x6FBF5E94",
        "LoD/1.13c": "0x6FBF5EC4",
        "LoD/1.13d": "0x6FBF5E24"
      },
      "rvas": {
        "LoD/1.07": "0x261C",
        "LoD/1.08": "0x261C",
        "LoD/1.09": "0x261C",
        "LoD/1.09b": "0x261C",
        "LoD/1.09d": "0x261C",
        "LoD/1.10": "0x26AC",
        "LoD/1.11": "0x5E54",
        "LoD/1.11b": "0x5E54",
        "LoD/1.12a": "0x5E94",
        "LoD/1.13c": "0x5EC4",
        "LoD/1.13d": "0x5E24"
      },
      "sizes": {
        "LoD/1.07": 6,
        "LoD/1.08": 6,
        "LoD/1.09": 6,
        "LoD/1.09b": 6,
        "LoD/1.09d": 6,
        "LoD/1.10": 6,
        "LoD/1.11": 6,
        "LoD/1.11b": 6,
        "LoD/1.12a": 6,
        "LoD/1.13c": 6,
        "LoD/1.13d": 6
      },
      "name": "DequeueBufferAndCopy",
      "signature": "dword DequeueBufferAndCopy(void * pManager, int nPriority, byte * pbDestBuf, dword dwMaxSize)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:e3e7225badfcf3c2e051c42d71d7237a",
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1,
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.08": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09d": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.10": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.12a": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13c": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13d": "e3e7225badfcf3c2e051c42d71d7237a"
      }
    },
    "d2net.dll_SendClientData": {
      "addresses": {
        "LoD/1.07": "0x6FC32622",
        "LoD/1.08": "0x6FC32622",
        "LoD/1.09": "0x6FC02622",
        "LoD/1.09b": "0x6FC02622",
        "LoD/1.09d": "0x6FC02622",
        "LoD/1.10": "0x6FC026EE",
        "LoD/1.11": "0x6FBF5E12",
        "LoD/1.11b": "0x6FBF5E12",
        "LoD/1.12a": "0x6FBF5E4C",
        "LoD/1.13c": "0x6FBF5E82",
        "LoD/1.13d": "0x6FBF5DDC"
      },
      "rvas": {
        "LoD/1.07": "0x2622",
        "LoD/1.08": "0x2622",
        "LoD/1.09": "0x2622",
        "LoD/1.09b": "0x2622",
        "LoD/1.09d": "0x2622",
        "LoD/1.10": "0x26EE",
        "LoD/1.11": "0x5E12",
        "LoD/1.11b": "0x5E12",
        "LoD/1.12a": "0x5E4C",
        "LoD/1.13c": "0x5E82",
        "LoD/1.13d": "0x5DDC"
      },
      "sizes": {
        "LoD/1.07": 6,
        "LoD/1.08": 6,
        "LoD/1.09": 6,
        "LoD/1.09b": 6,
        "LoD/1.09d": 6,
        "LoD/1.10": 6,
        "LoD/1.11": 6,
        "LoD/1.11b": 6,
        "LoD/1.12a": 6,
        "LoD/1.13c": 6,
        "LoD/1.13d": 6
      },
      "name": "SendClientData",
      "signature": "int SendClientData(uint * pClientMgr, uint dwClientId, void * pvData, uint dwDataSize)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:e3e7225badfcf3c2e051c42d71d7237a",
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1,
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.08": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09d": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.10": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.12a": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13c": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13d": "e3e7225badfcf3c2e051c42d71d7237a"
      }
    },
    "d2net.dll_DecodeHuffmanData": {
      "addresses": {
        "LoD/1.07": "0x6FC32628",
        "LoD/1.08": "0x6FC32628",
        "LoD/1.09": "0x6FC02628",
        "LoD/1.09b": "0x6FC02628",
        "LoD/1.09d": "0x6FC02628",
        "LoD/1.10": "0x6FC026B8",
        "LoD/1.11": "0x6FBF5DBE",
        "LoD/1.11b": "0x6FBF5DC4",
        "LoD/1.12a": "0x6FBF5EE2",
        "LoD/1.13c": "0x6FBF5E2E",
        "LoD/1.13d": "0x6FBF5E72"
      },
      "rvas": {
        "LoD/1.07": "0x2628",
        "LoD/1.08": "0x2628",
        "LoD/1.09": "0x2628",
        "LoD/1.09b": "0x2628",
        "LoD/1.09d": "0x2628",
        "LoD/1.10": "0x26B8",
        "LoD/1.11": "0x5DBE",
        "LoD/1.11b": "0x5DC4",
        "LoD/1.12a": "0x5EE2",
        "LoD/1.13c": "0x5E2E",
        "LoD/1.13d": "0x5E72"
      },
      "sizes": {
        "LoD/1.07": 6,
        "LoD/1.08": 6,
        "LoD/1.09": 6,
        "LoD/1.09b": 6,
        "LoD/1.09d": 6,
        "LoD/1.10": 6,
        "LoD/1.11": 6,
        "LoD/1.11b": 6,
        "LoD/1.12a": 6,
        "LoD/1.13c": 6,
        "LoD/1.13d": 6
      },
      "name": "DecodeHuffmanData",
      "signature": "int DecodeHuffmanData(byte * pbDest, int nDestLen, byte * pbSrc, int nSrcLen)",
      "calling_convention": "__fastcall",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:e3e7225badfcf3c2e051c42d71d7237a",
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1,
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.08": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09d": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.10": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.12a": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13c": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13d": "e3e7225badfcf3c2e051c42d71d7237a"
      }
    },
    "d2net.dll_UpdateHuffmanStatistics": {
      "addresses": {
        "LoD/1.07": "0x6FC3262E",
        "LoD/1.08": "0x6FC3262E",
        "LoD/1.09": "0x6FC0262E",
        "LoD/1.09b": "0x6FC0262E",
        "LoD/1.09d": "0x6FC0262E",
        "LoD/1.10": "0x6FC026BE",
        "LoD/1.11": "0x6FBF5DE2",
        "LoD/1.11b": "0x6FBF5DE2",
        "LoD/1.12a": "0x6FBF5F00",
        "LoD/1.13c": "0x6FBF5E52",
        "LoD/1.13d": "0x6FBF5E90"
      },
      "rvas": {
        "LoD/1.07": "0x262E",
        "LoD/1.08": "0x262E",
        "LoD/1.09": "0x262E",
        "LoD/1.09b": "0x262E",
        "LoD/1.09d": "0x262E",
        "LoD/1.10": "0x26BE",
        "LoD/1.11": "0x5DE2",
        "LoD/1.11b": "0x5DE2",
        "LoD/1.12a": "0x5F00",
        "LoD/1.13c": "0x5E52",
        "LoD/1.13d": "0x5E90"
      },
      "sizes": {
        "LoD/1.07": 6,
        "LoD/1.08": 6,
        "LoD/1.09": 6,
        "LoD/1.09b": 6,
        "LoD/1.09d": 6,
        "LoD/1.10": 6,
        "LoD/1.11": 6,
        "LoD/1.11b": 6,
        "LoD/1.12a": 6,
        "LoD/1.13c": 6,
        "LoD/1.13d": 6
      },
      "name": "UpdateHuffmanStatistics",
      "signature": "void UpdateHuffmanStatistics(byte * pbSrcData, uint dwByteCount)",
      "calling_convention": "__fastcall",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:e3e7225badfcf3c2e051c42d71d7237a",
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1,
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.08": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09d": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.10": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.12a": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13c": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13d": "e3e7225badfcf3c2e051c42d71d7237a"
      }
    },
    "d2net.dll_GetPeerIPAddressByID": {
      "addresses": {
        "LoD/1.07": "0x6FC32634",
        "LoD/1.08": "0x6FC32634",
        "LoD/1.09": "0x6FC02634",
        "LoD/1.09b": "0x6FC02634",
        "LoD/1.09d": "0x6FC02634",
        "LoD/1.10": "0x6FC026C4",
        "LoD/1.11": "0x6FBF5E06",
        "LoD/1.11b": "0x6FBF5E06",
        "LoD/1.12a": "0x6FBF5E40",
        "LoD/1.13c": "0x6FBF5E76",
        "LoD/1.13d": "0x6FBF5DD0"
      },
      "rvas": {
        "LoD/1.07": "0x2634",
        "LoD/1.08": "0x2634",
        "LoD/1.09": "0x2634",
        "LoD/1.09b": "0x2634",
        "LoD/1.09d": "0x2634",
        "LoD/1.10": "0x26C4",
        "LoD/1.11": "0x5E06",
        "LoD/1.11b": "0x5E06",
        "LoD/1.12a": "0x5E40",
        "LoD/1.13c": "0x5E76",
        "LoD/1.13d": "0x5DD0"
      },
      "sizes": {
        "LoD/1.07": 6,
        "LoD/1.08": 6,
        "LoD/1.09": 6,
        "LoD/1.09b": 6,
        "LoD/1.09d": 6,
        "LoD/1.10": 6,
        "LoD/1.11": 6,
        "LoD/1.11b": 6,
        "LoD/1.12a": 6,
        "LoD/1.13c": 6,
        "LoD/1.13d": 6
      },
      "name": "GetPeerIPAddressByID",
      "signature": "void GetPeerIPAddressByID(FogHashTable * pHashTable, DWORD dwPeerID, char * szIPBuffer, DWORD dwBufferSize)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:e3e7225badfcf3c2e051c42d71d7237a",
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1,
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.08": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09d": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.10": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.12a": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13c": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13d": "e3e7225badfcf3c2e051c42d71d7237a"
      }
    },
    "d2net.dll_DisconnectClientAndBlock": {
      "addresses": {
        "LoD/1.07": "0x6FC3263A",
        "LoD/1.08": "0x6FC3263A",
        "LoD/1.09": "0x6FC0263A",
        "LoD/1.09b": "0x6FC0263A",
        "LoD/1.09d": "0x6FC0263A",
        "LoD/1.10": "0x6FC026E8",
        "LoD/1.11": "0x6FBF5E1E",
        "LoD/1.11b": "0x6FBF5E1E",
        "LoD/1.12a": "0x6FBF5E58",
        "LoD/1.13c": "0x6FBF5E8E",
        "LoD/1.13d": "0x6FBF5DE8"
      },
      "rvas": {
        "LoD/1.07": "0x263A",
        "LoD/1.08": "0x263A",
        "LoD/1.09": "0x263A",
        "LoD/1.09b": "0x263A",
        "LoD/1.09d": "0x263A",
        "LoD/1.10": "0x26E8",
        "LoD/1.11": "0x5E1E",
        "LoD/1.11b": "0x5E1E",
        "LoD/1.12a": "0x5E58",
        "LoD/1.13c": "0x5E8E",
        "LoD/1.13d": "0x5DE8"
      },
      "sizes": {
        "LoD/1.07": 6,
        "LoD/1.08": 6,
        "LoD/1.09": 6,
        "LoD/1.09b": 6,
        "LoD/1.09d": 6,
        "LoD/1.10": 6,
        "LoD/1.11": 6,
        "LoD/1.11b": 6,
        "LoD/1.12a": 6,
        "LoD/1.13c": 6,
        "LoD/1.13d": 6
      },
      "name": "DisconnectClientAndBlock",
      "signature": "void DisconnectClientAndBlock(void * pServer, uint dwClientId, uint dwReason, uint dwBlockDuration)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:e3e7225badfcf3c2e051c42d71d7237a",
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1,
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.08": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09d": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.10": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.12a": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13c": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13d": "e3e7225badfcf3c2e051c42d71d7237a"
      }
    },
    "d2net.dll_DisconnectClientByAddress": {
      "addresses": {
        "LoD/1.07": "0x6FC32640",
        "LoD/1.08": "0x6FC32640",
        "LoD/1.09": "0x6FC02640",
        "LoD/1.09b": "0x6FC02640",
        "LoD/1.09d": "0x6FC02640",
        "LoD/1.10": "0x6FC026E2",
        "LoD/1.11": "0x6FBF5E00",
        "LoD/1.11b": "0x6FBF5E00",
        "LoD/1.12a": "0x6FBF5E3A",
        "LoD/1.13c": "0x6FBF5E70",
        "LoD/1.13d": "0x6FBF5DCA"
      },
      "rvas": {
        "LoD/1.07": "0x2640",
        "LoD/1.08": "0x2640",
        "LoD/1.09": "0x2640",
        "LoD/1.09b": "0x2640",
        "LoD/1.09d": "0x2640",
        "LoD/1.10": "0x26E2",
        "LoD/1.11": "0x5E00",
        "LoD/1.11b": "0x5E00",
        "LoD/1.12a": "0x5E3A",
        "LoD/1.13c": "0x5E70",
        "LoD/1.13d": "0x5DCA"
      },
      "sizes": {
        "LoD/1.07": 6,
        "LoD/1.08": 6,
        "LoD/1.09": 6,
        "LoD/1.09b": 6,
        "LoD/1.09d": 6,
        "LoD/1.10": 6,
        "LoD/1.11": 6,
        "LoD/1.11b": 6,
        "LoD/1.12a": 6,
        "LoD/1.13c": 6,
        "LoD/1.13d": 6
      },
      "name": "DisconnectClientByAddress",
      "signature": "void DisconnectClientByAddress(void * pServerContext, in_addr addrClient, uint dwUnused1, uint dwBlockDuration)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:e3e7225badfcf3c2e051c42d71d7237a",
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1,
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.08": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09d": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.10": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.12a": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13c": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13d": "e3e7225badfcf3c2e051c42d71d7237a"
      }
    },
    "d2net.dll_UnlistIPFromHackList": {
      "addresses": {
        "LoD/1.07": "0x6FC32646",
        "LoD/1.08": "0x6FC32646",
        "LoD/1.09": "0x6FC02646",
        "LoD/1.09b": "0x6FC02646",
        "LoD/1.09d": "0x6FC02646",
        "LoD/1.10": "0x6FC026D6",
        "LoD/1.11": "0x6FBF5E4E",
        "LoD/1.11b": "0x6FBF5E4E",
        "LoD/1.12a": "0x6FBF5E8E",
        "LoD/1.13c": "0x6FBF5EBE",
        "LoD/1.13d": "0x6FBF5E1E"
      },
      "rvas": {
        "LoD/1.07": "0x2646",
        "LoD/1.08": "0x2646",
        "LoD/1.09": "0x2646",
        "LoD/1.09b": "0x2646",
        "LoD/1.09d": "0x2646",
        "LoD/1.10": "0x26D6",
        "LoD/1.11": "0x5E4E",
        "LoD/1.11b": "0x5E4E",
        "LoD/1.12a": "0x5E8E",
        "LoD/1.13c": "0x5EBE",
        "LoD/1.13d": "0x5E1E"
      },
      "sizes": {
        "LoD/1.07": 6,
        "LoD/1.08": 6,
        "LoD/1.09": 6,
        "LoD/1.09b": 6,
        "LoD/1.09d": 6,
        "LoD/1.10": 6,
        "LoD/1.11": 6,
        "LoD/1.11b": 6,
        "LoD/1.12a": 6,
        "LoD/1.13c": 6,
        "LoD/1.13d": 6
      },
      "name": "UnlistIPFromHackList",
      "signature": "void UnlistIPFromHackList(void * pHackList, in_addr ipAddr)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:e3e7225badfcf3c2e051c42d71d7237a",
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1,
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.08": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09d": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.10": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.12a": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13c": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13d": "e3e7225badfcf3c2e051c42d71d7237a"
      }
    },
    "d2net.dll_RemoveClientByIpAddress": {
      "addresses": {
        "LoD/1.07": "0x6FC3264C",
        "LoD/1.08": "0x6FC3264C",
        "LoD/1.09": "0x6FC0264C",
        "LoD/1.09b": "0x6FC0264C",
        "LoD/1.09d": "0x6FC0264C",
        "LoD/1.10": "0x6FC026DC",
        "LoD/1.11": "0x6FBF5E18",
        "LoD/1.11b": "0x6FBF5E18",
        "LoD/1.12a": "0x6FBF5E52",
        "LoD/1.13c": "0x6FBF5E88",
        "LoD/1.13d": "0x6FBF5DE2"
      },
      "rvas": {
        "LoD/1.07": "0x264C",
        "LoD/1.08": "0x264C",
        "LoD/1.09": "0x264C",
        "LoD/1.09b": "0x264C",
        "LoD/1.09d": "0x264C",
        "LoD/1.10": "0x26DC",
        "LoD/1.11": "0x5E18",
        "LoD/1.11b": "0x5E18",
        "LoD/1.12a": "0x5E52",
        "LoD/1.13c": "0x5E88",
        "LoD/1.13d": "0x5DE2"
      },
      "sizes": {
        "LoD/1.07": 6,
        "LoD/1.08": 6,
        "LoD/1.09": 6,
        "LoD/1.09b": 6,
        "LoD/1.09d": 6,
        "LoD/1.10": 6,
        "LoD/1.11": 6,
        "LoD/1.11b": 6,
        "LoD/1.12a": 6,
        "LoD/1.13c": 6,
        "LoD/1.13d": 6
      },
      "name": "RemoveClientByIpAddress",
      "signature": "void RemoveClientByIpAddress(void * pServerCtx, in_addr addrClient)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:e3e7225badfcf3c2e051c42d71d7237a",
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1,
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.08": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09d": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.10": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.12a": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13c": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13d": "e3e7225badfcf3c2e051c42d71d7237a"
      }
    },
    "d2net.dll_DisconnectClientById": {
      "addresses": {
        "LoD/1.07": "0x6FC32652",
        "LoD/1.08": "0x6FC32652",
        "LoD/1.09": "0x6FC02652",
        "LoD/1.09b": "0x6FC02652",
        "LoD/1.09d": "0x6FC02652",
        "LoD/1.10": "0x6FC026B2",
        "LoD/1.11": "0x6FBF5DB2",
        "LoD/1.11b": "0x6FBF5DAC",
        "LoD/1.12a": "0x6FBF5E22",
        "LoD/1.13c": "0x6FBF5E22",
        "LoD/1.13d": "0x6FBF5DB2"
      },
      "rvas": {
        "LoD/1.07": "0x2652",
        "LoD/1.08": "0x2652",
        "LoD/1.09": "0x2652",
        "LoD/1.09b": "0x2652",
        "LoD/1.09d": "0x2652",
        "LoD/1.10": "0x26B2",
        "LoD/1.11": "0x5DB2",
        "LoD/1.11b": "0x5DAC",
        "LoD/1.12a": "0x5E22",
        "LoD/1.13c": "0x5E22",
        "LoD/1.13d": "0x5DB2"
      },
      "sizes": {
        "LoD/1.07": 6,
        "LoD/1.08": 6,
        "LoD/1.09": 6,
        "LoD/1.09b": 6,
        "LoD/1.09d": 6,
        "LoD/1.10": 6,
        "LoD/1.11": 6,
        "LoD/1.11b": 6,
        "LoD/1.12a": 6,
        "LoD/1.13c": 6,
        "LoD/1.13d": 6
      },
      "name": "DisconnectClientById",
      "signature": "void DisconnectClientById(void * pServer, dword dwClientId)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:e3e7225badfcf3c2e051c42d71d7237a",
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1,
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.08": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09d": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.10": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.12a": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13c": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13d": "e3e7225badfcf3c2e051c42d71d7237a"
      }
    },
    "d2net.dll_SetServerHandle": {
      "addresses": {
        "LoD/1.07": "0x6FC32658",
        "LoD/1.08": "0x6FC32658",
        "LoD/1.09": "0x6FC02658",
        "LoD/1.09b": "0x6FC02658",
        "LoD/1.09d": "0x6FC02658",
        "LoD/1.10": "0x6FC026F4",
        "LoD/1.11": "0x6FBF5E5A",
        "LoD/1.11b": "0x6FBF5E5A",
        "LoD/1.12a": "0x6FBF5E9A",
        "LoD/1.13c": "0x6FBF5ECA",
        "LoD/1.13d": "0x6FBF5E2A"
      },
      "rvas": {
        "LoD/1.07": "0x2658",
        "LoD/1.08": "0x2658",
        "LoD/1.09": "0x2658",
        "LoD/1.09b": "0x2658",
        "LoD/1.09d": "0x2658",
        "LoD/1.10": "0x26F4",
        "LoD/1.11": "0x5E5A",
        "LoD/1.11b": "0x5E5A",
        "LoD/1.12a": "0x5E9A",
        "LoD/1.13c": "0x5ECA",
        "LoD/1.13d": "0x5E2A"
      },
      "sizes": {
        "LoD/1.07": 6,
        "LoD/1.08": 6,
        "LoD/1.09": 6,
        "LoD/1.09b": 6,
        "LoD/1.09d": 6,
        "LoD/1.10": 6,
        "LoD/1.11": 6,
        "LoD/1.11b": 6,
        "LoD/1.12a": 6,
        "LoD/1.13c": 6,
        "LoD/1.13d": 6
      },
      "name": "SetServerHandle",
      "signature": "void SetServerHandle(void * pServerContext, uint dwHandle)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:e3e7225badfcf3c2e051c42d71d7237a",
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1,
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.08": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09d": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.10": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.12a": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13c": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13d": "e3e7225badfcf3c2e051c42d71d7237a"
      }
    },
    "d2net.dll_SetStructField0xBBC": {
      "addresses": {
        "LoD/1.07": "0x6FC3265E",
        "LoD/1.08": "0x6FC3265E",
        "LoD/1.09": "0x6FC0265E",
        "LoD/1.09b": "0x6FC0265E",
        "LoD/1.09d": "0x6FC0265E",
        "LoD/1.10": "0x6FC026FA",
        "LoD/1.11": "0x6FBF5E84",
        "LoD/1.11b": "0x6FBF5E84",
        "LoD/1.12a": "0x6FBF5ECA",
        "LoD/1.13c": "0x6FBF5EF4",
        "LoD/1.13d": "0x6FBF5E5A"
      },
      "rvas": {
        "LoD/1.07": "0x265E",
        "LoD/1.08": "0x265E",
        "LoD/1.09": "0x265E",
        "LoD/1.09b": "0x265E",
        "LoD/1.09d": "0x265E",
        "LoD/1.10": "0x26FA",
        "LoD/1.11": "0x5E84",
        "LoD/1.11b": "0x5E84",
        "LoD/1.12a": "0x5ECA",
        "LoD/1.13c": "0x5EF4",
        "LoD/1.13d": "0x5E5A"
      },
      "sizes": {
        "LoD/1.07": 6,
        "LoD/1.08": 6,
        "LoD/1.09": 6,
        "LoD/1.09b": 6,
        "LoD/1.09d": 6,
        "LoD/1.10": 6,
        "LoD/1.11": 6,
        "LoD/1.11b": 6,
        "LoD/1.12a": 6,
        "LoD/1.13c": 6,
        "LoD/1.13d": 6
      },
      "name": "SetStructField0xBBC",
      "signature": "void SetStructField0xBBC(void * pStruct, uint dwValue)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:e3e7225badfcf3c2e051c42d71d7237a",
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1,
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.08": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09d": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.10": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.12a": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13c": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13d": "e3e7225badfcf3c2e051c42d71d7237a"
      }
    },
    "d2net.dll_HashTableSetValue": {
      "addresses": {
        "LoD/1.07": "0x6FC32664",
        "LoD/1.08": "0x6FC32664",
        "LoD/1.09": "0x6FC02664",
        "LoD/1.09b": "0x6FC02664",
        "LoD/1.09d": "0x6FC02664",
        "LoD/1.10": "0x6FC02700",
        "LoD/1.11": "0x6FBF5DF4",
        "LoD/1.11b": "0x6FBF5DF4",
        "LoD/1.12a": "0x6FBF5E2E",
        "LoD/1.13c": "0x6FBF5E64",
        "LoD/1.13d": "0x6FBF5DBE"
      },
      "rvas": {
        "LoD/1.07": "0x2664",
        "LoD/1.08": "0x2664",
        "LoD/1.09": "0x2664",
        "LoD/1.09b": "0x2664",
        "LoD/1.09d": "0x2664",
        "LoD/1.10": "0x2700",
        "LoD/1.11": "0x5DF4",
        "LoD/1.11b": "0x5DF4",
        "LoD/1.12a": "0x5E2E",
        "LoD/1.13c": "0x5E64",
        "LoD/1.13d": "0x5DBE"
      },
      "sizes": {
        "LoD/1.07": 6,
        "LoD/1.08": 6,
        "LoD/1.09": 6,
        "LoD/1.09b": 6,
        "LoD/1.09d": 6,
        "LoD/1.10": 6,
        "LoD/1.11": 6,
        "LoD/1.11b": 6,
        "LoD/1.12a": 6,
        "LoD/1.13c": 6,
        "LoD/1.13d": 6
      },
      "name": "HashTableSetValue",
      "signature": "void HashTableSetValue(FogHashTable * pHashTable, uint dwKey, uint dwValue)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:e3e7225badfcf3c2e051c42d71d7237a",
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1,
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.08": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09d": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.10": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.12a": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13c": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13d": "e3e7225badfcf3c2e051c42d71d7237a"
      }
    },
    "d2net.dll_GetHashTableValue": {
      "addresses": {
        "LoD/1.07": "0x6FC3266A",
        "LoD/1.08": "0x6FC3266A",
        "LoD/1.09": "0x6FC0266A",
        "LoD/1.09b": "0x6FC0266A",
        "LoD/1.09d": "0x6FC0266A",
        "LoD/1.10": "0x6FC02706",
        "LoD/1.11": "0x6FBF5E72",
        "LoD/1.11b": "0x6FBF5E72",
        "LoD/1.12a": "0x6FBF5EB8",
        "LoD/1.13c": "0x6FBF5EE2",
        "LoD/1.13d": "0x6FBF5E48"
      },
      "rvas": {
        "LoD/1.07": "0x266A",
        "LoD/1.08": "0x266A",
        "LoD/1.09": "0x266A",
        "LoD/1.09b": "0x266A",
        "LoD/1.09d": "0x266A",
        "LoD/1.10": "0x2706",
        "LoD/1.11": "0x5E72",
        "LoD/1.11b": "0x5E72",
        "LoD/1.12a": "0x5EB8",
        "LoD/1.13c": "0x5EE2",
        "LoD/1.13d": "0x5E48"
      },
      "sizes": {
        "LoD/1.07": 6,
        "LoD/1.08": 6,
        "LoD/1.09": 6,
        "LoD/1.09b": 6,
        "LoD/1.09d": 6,
        "LoD/1.10": 6,
        "LoD/1.11": 6,
        "LoD/1.11b": 6,
        "LoD/1.12a": 6,
        "LoD/1.13c": 6,
        "LoD/1.13d": 6
      },
      "name": "GetHashTableValue",
      "signature": "uint GetHashTableValue(void * pHashTable, uint dwKey)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:e3e7225badfcf3c2e051c42d71d7237a",
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1,
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.08": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09d": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.10": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.12a": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13c": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13d": "e3e7225badfcf3c2e051c42d71d7237a"
      }
    },
    "d2net.dll_WaitForAsyncIO": {
      "addresses": {
        "LoD/1.07": "0x6FC32670",
        "LoD/1.08": "0x6FC32670",
        "LoD/1.09": "0x6FC02670",
        "LoD/1.09b": "0x6FC02670",
        "LoD/1.09d": "0x6FC02670",
        "LoD/1.10": "0x6FC0267C",
        "LoD/1.11": "0x6FBF5E48",
        "LoD/1.11b": "0x6FBF5E48",
        "LoD/1.12a": "0x6FBF5E88",
        "LoD/1.13c": "0x6FBF5EB8",
        "LoD/1.13d": "0x6FBF5E18"
      },
      "rvas": {
        "LoD/1.07": "0x2670",
        "LoD/1.08": "0x2670",
        "LoD/1.09": "0x2670",
        "LoD/1.09b": "0x2670",
        "LoD/1.09d": "0x2670",
        "LoD/1.10": "0x267C",
        "LoD/1.11": "0x5E48",
        "LoD/1.11b": "0x5E48",
        "LoD/1.12a": "0x5E88",
        "LoD/1.13c": "0x5EB8",
        "LoD/1.13d": "0x5E18"
      },
      "sizes": {
        "LoD/1.07": 6,
        "LoD/1.08": 6,
        "LoD/1.09": 6,
        "LoD/1.09b": 6,
        "LoD/1.09d": 6,
        "LoD/1.10": 6,
        "LoD/1.11": 6,
        "LoD/1.11b": 6,
        "LoD/1.12a": 6,
        "LoD/1.13c": 6,
        "LoD/1.13d": 6
      },
      "name": "WaitForAsyncIO",
      "signature": "uint WaitForAsyncIO(void * pContext, uint dwTimeout)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:e3e7225badfcf3c2e051c42d71d7237a",
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1,
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.08": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09d": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.10": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.12a": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13c": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13d": "e3e7225badfcf3c2e051c42d71d7237a"
      }
    },
    "d2net.dll_NoOpStub": {
      "addresses": {
        "LoD/1.07": "0x6FC32676",
        "LoD/1.08": "0x6FC32676",
        "LoD/1.09": "0x6FC02676",
        "LoD/1.09b": "0x6FC02676",
        "LoD/1.09d": "0x6FC02676",
        "LoD/1.10": "0x6FC02712",
        "LoD/1.11": "0x6FBF5E60",
        "LoD/1.11b": "0x6FBF5E60",
        "LoD/1.12a": "0x6FBF5EA6",
        "LoD/1.13c": "0x6FBF5ED0",
        "LoD/1.13d": "0x6FBF5E36"
      },
      "rvas": {
        "LoD/1.07": "0x2676",
        "LoD/1.08": "0x2676",
        "LoD/1.09": "0x2676",
        "LoD/1.09b": "0x2676",
        "LoD/1.09d": "0x2676",
        "LoD/1.10": "0x2712",
        "LoD/1.11": "0x5E60",
        "LoD/1.11b": "0x5E60",
        "LoD/1.12a": "0x5EA6",
        "LoD/1.13c": "0x5ED0",
        "LoD/1.13d": "0x5E36"
      },
      "sizes": {
        "LoD/1.07": 6,
        "LoD/1.08": 6,
        "LoD/1.09": 6,
        "LoD/1.09b": 6,
        "LoD/1.09d": 6,
        "LoD/1.10": 6,
        "LoD/1.11": 6,
        "LoD/1.11b": 6,
        "LoD/1.12a": 6,
        "LoD/1.13c": 6,
        "LoD/1.13d": 6
      },
      "name": "NoOpStub",
      "signature": "void NoOpStub(void)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:e3e7225badfcf3c2e051c42d71d7237a",
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1,
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.08": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09d": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.10": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.12a": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13c": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13d": "e3e7225badfcf3c2e051c42d71d7237a"
      }
    },
    "d2net.dll_StubOrdinal10183": {
      "addresses": {
        "LoD/1.07": "0x6FC3267C",
        "LoD/1.08": "0x6FC3267C",
        "LoD/1.09": "0x6FC0267C",
        "LoD/1.09b": "0x6FC0267C",
        "LoD/1.09d": "0x6FC0267C",
        "LoD/1.10": "0x6FC02718",
        "LoD/1.11": "0x6FBF5E42",
        "LoD/1.11b": "0x6FBF5E42",
        "LoD/1.12a": "0x6FBF5E82",
        "LoD/1.13c": "0x6FBF5EB2",
        "LoD/1.13d": "0x6FBF5E12"
      },
      "rvas": {
        "LoD/1.07": "0x267C",
        "LoD/1.08": "0x267C",
        "LoD/1.09": "0x267C",
        "LoD/1.09b": "0x267C",
        "LoD/1.09d": "0x267C",
        "LoD/1.10": "0x2718",
        "LoD/1.11": "0x5E42",
        "LoD/1.11b": "0x5E42",
        "LoD/1.12a": "0x5E82",
        "LoD/1.13c": "0x5EB2",
        "LoD/1.13d": "0x5E12"
      },
      "sizes": {
        "LoD/1.07": 6,
        "LoD/1.08": 6,
        "LoD/1.09": 6,
        "LoD/1.09b": 6,
        "LoD/1.09d": 6,
        "LoD/1.10": 6,
        "LoD/1.11": 6,
        "LoD/1.11b": 6,
        "LoD/1.12a": 6,
        "LoD/1.13c": 6,
        "LoD/1.13d": 6
      },
      "name": "StubOrdinal10183",
      "signature": "void StubOrdinal10183(int nParam1, int nParam2)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:e3e7225badfcf3c2e051c42d71d7237a",
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1,
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.08": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09d": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.10": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.12a": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13c": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13d": "e3e7225badfcf3c2e051c42d71d7237a"
      }
    },
    "d2net.dll_SStrCopy": {
      "addresses": {
        "LoD/1.07": "0x6FC32682",
        "LoD/1.08": "0x6FC32682",
        "LoD/1.09": "0x6FC02682",
        "LoD/1.09b": "0x6FC02682",
        "LoD/1.09d": "0x6FC02682",
        "LoD/1.10": "0x6FC0271E",
        "LoD/1.11": "0x6FBF5DB8",
        "LoD/1.11b": "0x6FBF5DB8",
        "LoD/1.12a": "0x6FBF5EDC",
        "LoD/1.13c": "0x6FBF5E28",
        "LoD/1.13d": "0x6FBF5E6C"
      },
      "rvas": {
        "LoD/1.07": "0x2682",
        "LoD/1.08": "0x2682",
        "LoD/1.09": "0x2682",
        "LoD/1.09b": "0x2682",
        "LoD/1.09d": "0x2682",
        "LoD/1.10": "0x271E",
        "LoD/1.11": "0x5DB8",
        "LoD/1.11b": "0x5DB8",
        "LoD/1.12a": "0x5EDC",
        "LoD/1.13c": "0x5E28",
        "LoD/1.13d": "0x5E6C"
      },
      "sizes": {
        "LoD/1.07": 6,
        "LoD/1.08": 6,
        "LoD/1.09": 6,
        "LoD/1.09b": 6,
        "LoD/1.09d": 6,
        "LoD/1.10": 6,
        "LoD/1.11": 6,
        "LoD/1.11b": 6,
        "LoD/1.12a": 6,
        "LoD/1.13c": 6,
        "LoD/1.13d": 6
      },
      "name": "SStrCopy",
      "signature": "char * SStrCopy(int nDestSize, char * szDest, char * szSrc)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:e3e7225badfcf3c2e051c42d71d7237a",
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1,
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.08": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09d": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.10": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.12a": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13c": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13d": "e3e7225badfcf3c2e051c42d71d7237a"
      }
    },
    "d2net.dll_SStrLen": {
      "addresses": {
        "LoD/1.07": "0x6FC32688",
        "LoD/1.08": "0x6FC32688",
        "LoD/1.09": "0x6FC02688",
        "LoD/1.09b": "0x6FC02688",
        "LoD/1.09d": "0x6FC02688",
        "LoD/1.10": "0x6FC02724",
        "LoD/1.11": "0x6FBF5D64",
        "LoD/1.11b": "0x6FBF5D6A",
        "LoD/1.12a": "0x6FBF5DD4",
        "LoD/1.13c": "0x6FBF5DD4",
        "LoD/1.13d": "0x6FBF5D64"
      },
      "rvas": {
        "LoD/1.07": "0x2688",
        "LoD/1.08": "0x2688",
        "LoD/1.09": "0x2688",
        "LoD/1.09b": "0x2688",
        "LoD/1.09d": "0x2688",
        "LoD/1.10": "0x2724",
        "LoD/1.11": "0x5D64",
        "LoD/1.11b": "0x5D6A",
        "LoD/1.12a": "0x5DD4",
        "LoD/1.13c": "0x5DD4",
        "LoD/1.13d": "0x5D64"
      },
      "sizes": {
        "LoD/1.07": 6,
        "LoD/1.08": 6,
        "LoD/1.09": 6,
        "LoD/1.09b": 6,
        "LoD/1.09d": 6,
        "LoD/1.10": 6,
        "LoD/1.11": 6,
        "LoD/1.11b": 6,
        "LoD/1.12a": 6,
        "LoD/1.13c": 6,
        "LoD/1.13d": 6
      },
      "name": "SStrLen",
      "signature": "int SStrLen(char * szString)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:e3e7225badfcf3c2e051c42d71d7237a",
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1,
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.08": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09d": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.10": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.12a": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13c": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13d": "e3e7225badfcf3c2e051c42d71d7237a"
      }
    },
    "d2net.dll_CRT_RunInitializers": {
      "addresses": {
        "LoD/1.07": "0x6FC3268E",
        "LoD/1.08": "0x6FC3268E",
        "LoD/1.09": "0x6FC0268E",
        "LoD/1.09b": "0x6FC0268E",
        "LoD/1.09d": "0x6FC0268E",
        "LoD/1.10": "0x6FC0272A"
      },
      "rvas": {
        "LoD/1.07": "0x268E",
        "LoD/1.08": "0x268E",
        "LoD/1.09": "0x268E",
        "LoD/1.09b": "0x268E",
        "LoD/1.09d": "0x268E",
        "LoD/1.10": "0x272A"
      },
      "sizes": {
        "LoD/1.07": 45,
        "LoD/1.08": 45,
        "LoD/1.09": 45,
        "LoD/1.09b": 45,
        "LoD/1.09d": 45,
        "LoD/1.10": 45
      },
      "name": "CRT_RunInitializers",
      "signature": "void CRT_RunInitializers(void)",
      "calling_convention": "__stdcall",
      "comment": "Executes C Runtime initialization functions during DLL/process startup.\n\nAlgorithm:\n1. Check if pre-termination callback is registered (g_pfnPreTermCallback != 0)\n2. If callback exists, invoke it via indirect call through EAX\n3. Call CRT_CallFunctionPointerArray for C initializers array (g_apfnCInitializers to g_apfnCInitializersEnd)\n4. Call CRT_CallFunctionPointerArray for C++ initializers array (g_apfnCppInitializers to g_apfnCppInitializersEnd)\n5. Return to caller\n\nParameters:\n  None\n\nReturns:\n  void - No return value\n\nClassification: Initialization function\nCalled from DllMain/CRT entry point (FUN_6fc32af5) during DLL_PROCESS_ATTACH (reason=1).\n\nGlobal References:\n  g_pfnPreTermCallback (0x6fc3b8fc) - Pre-termination callback function pointer\n  g_apfnCppInitializers (0x6fc38000) - Start of C++ initializer function pointer array\n  g_apfnCppInitializersEnd (0x6fc38004) - End of C++ initializer array\n  g_apfnCInitializers (0x6fc38008) - Start of C initializer function pointer array  \n  g_apfnCInitializersEnd (0x6fc38010) - End of C initializer array\n\nNotes:\n  This is part of the C Runtime startup sequence. The initializer arrays contain\n  function pointers to static constructors and initialization routines that must\n  run before main/DllMain returns. The arrays are populated by the linker.",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:91b5192dddb89e963abc2be4471149da",
      "basic_block_counts": {
        "LoD/1.07": 3,
        "LoD/1.08": 3,
        "LoD/1.09": 3,
        "LoD/1.09b": 3,
        "LoD/1.09d": 3,
        "LoD/1.10": 3
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "91b5192dddb89e963abc2be4471149da",
        "LoD/1.08": "91b5192dddb89e963abc2be4471149da",
        "LoD/1.09": "91b5192dddb89e963abc2be4471149da",
        "LoD/1.09b": "91b5192dddb89e963abc2be4471149da",
        "LoD/1.09d": "91b5192dddb89e963abc2be4471149da",
        "LoD/1.10": "91b5192dddb89e963abc2be4471149da"
      }
    },
    "d2net.dll_CRT_ExitProcessWithCleanup": {
      "addresses": {
        "LoD/1.07": "0x6FC326BB",
        "LoD/1.08": "0x6FC326BB",
        "LoD/1.09": "0x6FC026BB",
        "LoD/1.09b": "0x6FC026BB",
        "LoD/1.09d": "0x6FC026BB",
        "LoD/1.10": "0x6FC02757",
        "LoD/1.11": "0x6FBF14C4",
        "LoD/1.11b": "0x6FBF14C4",
        "LoD/1.12a": "0x6FBF1187",
        "LoD/1.13c": "0x6FBF14C4",
        "LoD/1.13d": "0x6FBF1187"
      },
      "rvas": {
        "LoD/1.07": "0x26BB",
        "LoD/1.08": "0x26BB",
        "LoD/1.09": "0x26BB",
        "LoD/1.09b": "0x26BB",
        "LoD/1.09d": "0x26BB",
        "LoD/1.10": "0x2757",
        "LoD/1.11": "0x14C4",
        "LoD/1.11b": "0x14C4",
        "LoD/1.12a": "0x1187",
        "LoD/1.13c": "0x14C4",
        "LoD/1.13d": "0x1187"
      },
      "sizes": {
        "LoD/1.07": 17,
        "LoD/1.08": 17,
        "LoD/1.09": 17,
        "LoD/1.09b": 17,
        "LoD/1.09d": 17,
        "LoD/1.10": 17,
        "LoD/1.11": 17,
        "LoD/1.11b": 17,
        "LoD/1.12a": 17,
        "LoD/1.13c": 17,
        "LoD/1.13d": 17
      },
      "name": "CRT_ExitProcessWithCleanup",
      "signature": "void CRT_ExitProcessWithCleanup(UINT dwExitCode)",
      "calling_convention": "__cdecl",
      "comment": "Terminates the process with full CRT cleanup and atexit handler execution.\n\nWrapper that calls CRT_ExitProcessInternal with default cleanup parameters:\n- Runs all registered atexit handlers (param_2=0)\n- Calls ExitProcess instead of returning (param_3=0)\n\nAlgorithm:\n1. Push default parameters (0, 0) for cleanup and termination modes\n2. Call CRT_ExitProcessInternal(dwExitCode, 0, 0)\n3. Function does not return - process terminates\n\nParameters:\n  dwExitCode (UINT) - Process exit code passed to ExitProcess\n\nReturns:\n  void - Function does not return (calls ExitProcess)\n\nCallers:\n  NET_SendClientData, NET_SendDataPacket, NET_ParseAndQueuePackets,\n  NET_QueuePacketForShutdown, NET_QueueMessageDuringShutdown\n  Used for fatal network error termination scenarios.\n\nSee Also:\n  CRT_ExitProcessInternal (FUN_6fc326ec) - Full exit implementation",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:cd85d17a6b193c95680d3fdca645abba",
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1,
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "cd85d17a6b193c95680d3fdca645abba",
        "LoD/1.08": "cd85d17a6b193c95680d3fdca645abba",
        "LoD/1.09": "cd85d17a6b193c95680d3fdca645abba",
        "LoD/1.09b": "cd85d17a6b193c95680d3fdca645abba",
        "LoD/1.09d": "cd85d17a6b193c95680d3fdca645abba",
        "LoD/1.10": "cd85d17a6b193c95680d3fdca645abba",
        "LoD/1.11": "cd85d17a6b193c95680d3fdca645abba",
        "LoD/1.11b": "cd85d17a6b193c95680d3fdca645abba",
        "LoD/1.12a": "cd85d17a6b193c95680d3fdca645abba",
        "LoD/1.13c": "cd85d17a6b193c95680d3fdca645abba",
        "LoD/1.13d": "cd85d17a6b193c95680d3fdca645abba"
      }
    },
    "d2net.dll___exit": {
      "addresses": {
        "LoD/1.07": "0x6FC326CC",
        "LoD/1.08": "0x6FC326CC",
        "LoD/1.09": "0x6FC026CC",
        "LoD/1.09b": "0x6FC026CC",
        "LoD/1.09d": "0x6FC026CC",
        "LoD/1.10": "0x6FC02768",
        "LoD/1.11": "0x6FBF14D5",
        "LoD/1.11b": "0x6FBF14D5",
        "LoD/1.12a": "0x6FBF1198",
        "LoD/1.13c": "0x6FBF14D5",
        "LoD/1.13d": "0x6FBF1198"
      },
      "rvas": {
        "LoD/1.07": "0x26CC",
        "LoD/1.08": "0x26CC",
        "LoD/1.09": "0x26CC",
        "LoD/1.09b": "0x26CC",
        "LoD/1.09d": "0x26CC",
        "LoD/1.10": "0x2768",
        "LoD/1.11": "0x14D5",
        "LoD/1.11b": "0x14D5",
        "LoD/1.12a": "0x1198",
        "LoD/1.13c": "0x14D5",
        "LoD/1.13d": "0x1198"
      },
      "sizes": {
        "LoD/1.07": 17,
        "LoD/1.08": 17,
        "LoD/1.09": 17,
        "LoD/1.09b": 17,
        "LoD/1.09d": 17,
        "LoD/1.10": 17,
        "LoD/1.11": 17,
        "LoD/1.11b": 17,
        "LoD/1.12a": 17,
        "LoD/1.13c": 17,
        "LoD/1.13d": 17
      },
      "name": "__exit",
      "signature": "void __exit(int _Code)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __exit\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:cd85d17a6b193c95680d3fdca645abba",
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1,
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "cd85d17a6b193c95680d3fdca645abba",
        "LoD/1.08": "cd85d17a6b193c95680d3fdca645abba",
        "LoD/1.09": "cd85d17a6b193c95680d3fdca645abba",
        "LoD/1.09b": "cd85d17a6b193c95680d3fdca645abba",
        "LoD/1.09d": "cd85d17a6b193c95680d3fdca645abba",
        "LoD/1.10": "cd85d17a6b193c95680d3fdca645abba",
        "LoD/1.11": "cd85d17a6b193c95680d3fdca645abba",
        "LoD/1.11b": "cd85d17a6b193c95680d3fdca645abba",
        "LoD/1.12a": "cd85d17a6b193c95680d3fdca645abba",
        "LoD/1.13c": "cd85d17a6b193c95680d3fdca645abba",
        "LoD/1.13d": "cd85d17a6b193c95680d3fdca645abba"
      }
    },
    "d2net.dll_CRT_RunAtexitCleanup": {
      "addresses": {
        "LoD/1.07": "0x6FC326DD",
        "LoD/1.08": "0x6FC326DD",
        "LoD/1.09": "0x6FC026DD",
        "LoD/1.09b": "0x6FC026DD",
        "LoD/1.09d": "0x6FC026DD",
        "LoD/1.10": "0x6FC02779",
        "LoD/1.11": "0x6FBF14E6",
        "LoD/1.11b": "0x6FBF14E6",
        "LoD/1.12a": "0x6FBF11A9",
        "LoD/1.13c": "0x6FBF14E6",
        "LoD/1.13d": "0x6FBF11A9"
      },
      "rvas": {
        "LoD/1.07": "0x26DD",
        "LoD/1.08": "0x26DD",
        "LoD/1.09": "0x26DD",
        "LoD/1.09b": "0x26DD",
        "LoD/1.09d": "0x26DD",
        "LoD/1.10": "0x2779",
        "LoD/1.11": "0x14E6",
        "LoD/1.11b": "0x14E6",
        "LoD/1.12a": "0x11A9",
        "LoD/1.13c": "0x14E6",
        "LoD/1.13d": "0x11A9"
      },
      "sizes": {
        "LoD/1.07": 15,
        "LoD/1.08": 15,
        "LoD/1.09": 15,
        "LoD/1.09b": 15,
        "LoD/1.09d": 15,
        "LoD/1.10": 15,
        "LoD/1.11": 15,
        "LoD/1.11b": 15,
        "LoD/1.12a": 15,
        "LoD/1.13c": 15,
        "LoD/1.13d": 15
      },
      "name": "CRT_RunAtexitCleanup",
      "signature": "void CRT_RunAtexitCleanup(void)",
      "calling_convention": "__stdcall",
      "comment": "Wrapper that invokes CRT atexit cleanup handlers without terminating the process.\n\nAlgorithm:\n1. Call FUN_6fc326ec with exit code 0, trigger atexit handlers (param_2=0), soft exit mode (param_3=1)\n2. The callee runs registered atexit functions, pre-termination handlers, sets g_fCrtInitialized=1\n3. Returns without calling ExitProcess due to soft exit mode\n\nParameters: None\n\nReturns: void\n\nSpecial Cases:\n- Called during DLL_PROCESS_DETACH when g_dwServerState == 0\n- Does NOT terminate the process (soft exit mode)\n- Sets g_fCrtInitialized flag to indicate cleanup completed\n- Runs both atexit() registered functions and CRT pre-termination array\n\nClassification: Thunk/Wrapper - wraps FUN_6fc326ec for soft cleanup scenario",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:7a5e6ed384be31095abb7960c9f1d6d0",
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1,
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "7a5e6ed384be31095abb7960c9f1d6d0",
        "LoD/1.08": "7a5e6ed384be31095abb7960c9f1d6d0",
        "LoD/1.09": "7a5e6ed384be31095abb7960c9f1d6d0",
        "LoD/1.09b": "7a5e6ed384be31095abb7960c9f1d6d0",
        "LoD/1.09d": "7a5e6ed384be31095abb7960c9f1d6d0",
        "LoD/1.10": "7a5e6ed384be31095abb7960c9f1d6d0",
        "LoD/1.11": "7a5e6ed384be31095abb7960c9f1d6d0",
        "LoD/1.11b": "7a5e6ed384be31095abb7960c9f1d6d0",
        "LoD/1.12a": "7a5e6ed384be31095abb7960c9f1d6d0",
        "LoD/1.13c": "7a5e6ed384be31095abb7960c9f1d6d0",
        "LoD/1.13d": "7a5e6ed384be31095abb7960c9f1d6d0"
      }
    },
    "d2net.dll_CRT_DoExit": {
      "addresses": {
        "LoD/1.07": "0x6FC326EC",
        "LoD/1.08": "0x6FC326EC",
        "LoD/1.09": "0x6FC026EC",
        "LoD/1.09b": "0x6FC026EC",
        "LoD/1.09d": "0x6FC026EC",
        "LoD/1.10": "0x6FC02788"
      },
      "rvas": {
        "LoD/1.07": "0x26EC",
        "LoD/1.08": "0x26EC",
        "LoD/1.09": "0x26EC",
        "LoD/1.09b": "0x26EC",
        "LoD/1.09d": "0x26EC",
        "LoD/1.10": "0x2788"
      },
      "sizes": {
        "LoD/1.07": 163,
        "LoD/1.08": 163,
        "LoD/1.09": 163,
        "LoD/1.09b": 163,
        "LoD/1.09d": 163,
        "LoD/1.10": 163
      },
      "name": "CRT_DoExit",
      "signature": "void CRT_DoExit(uint dwExitCode, int nCallAtexitHandlers, int nReturnToCallerFlag)",
      "calling_convention": "__cdecl",
      "comment": "CRT exit handler that performs cleanup and optionally terminates the process.\n\nClassification: Cleanup/Destructor - CRT runtime termination handler\n\nAlgorithm:\n1. Acquire the exit critical section lock (CRT_AcquireExitLock)\n2. If g_dwServerPort == 1, terminate immediately via TerminateProcess\n3. Set g_dwServerState = 1 to indicate exit in progress\n4. Store nReturnToCallerFlag in g_fCrtInitialized\n5. If nCallAtexitHandlers == 0:\n   a. Iterate g_ppfnAtexitTableEnd backwards to g_ppfnAtexitTableStart\n   b. Call each non-null function pointer in the atexit table\n   c. Call CRT_CallFunctionPointerArray on g_apfnAtexitFuncs array\n6. Call CRT_CallFunctionPointerArray on g_apfnPreTermFuncs array\n7. If nReturnToCallerFlag == 0:\n   a. Set g_dwServerPort = 1\n   b. Call ExitProcess(dwExitCode) - does not return\n8. Release exit lock via CRT_LeaveCritSectExit and return\n\nParameters:\n  dwExitCode (uint) - Process exit code passed to ExitProcess/TerminateProcess\n  nCallAtexitHandlers (int) - 0 to call atexit handlers, non-zero to skip them\n  nReturnToCallerFlag (int) - 0 to call ExitProcess, non-zero to return to caller\n\nReturns: void (may not return if nReturnToCallerFlag == 0)\n\nCallers: __exit, FUN_6fc326dd, CRT_ExitProcessWithCleanup\n\nSpecial Cases:\n- If g_dwServerPort already 1, forces immediate termination\n- Atexit handlers called in reverse registration order\n- Pre-termination functions always called regardless of parameters",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:eb17d7abe573793d4b67d9aac794697b",
      "basic_block_counts": {
        "LoD/1.07": 13,
        "LoD/1.08": 13,
        "LoD/1.09": 13,
        "LoD/1.09b": 13,
        "LoD/1.09d": 13,
        "LoD/1.10": 13
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "eb17d7abe573793d4b67d9aac794697b",
        "LoD/1.08": "eb17d7abe573793d4b67d9aac794697b",
        "LoD/1.09": "eb17d7abe573793d4b67d9aac794697b",
        "LoD/1.09b": "eb17d7abe573793d4b67d9aac794697b",
        "LoD/1.09d": "eb17d7abe573793d4b67d9aac794697b",
        "LoD/1.10": "eb17d7abe573793d4b67d9aac794697b"
      }
    },
    "d2net.dll_CRT_AcquireExitLock": {
      "addresses": {
        "LoD/1.07": "0x6FC32791",
        "LoD/1.08": "0x6FC32791",
        "LoD/1.09": "0x6FC02791",
        "LoD/1.09b": "0x6FC02791",
        "LoD/1.09d": "0x6FC02791",
        "LoD/1.10": "0x6FC0282D",
        "LoD/1.11": "0x6FBF1DBD",
        "LoD/1.11b": "0x6FBF1DBD",
        "LoD/1.12a": "0x6FBF1DC5",
        "LoD/1.13c": "0x6FBF1DBD",
        "LoD/1.13d": "0x6FBF1DC5"
      },
      "rvas": {
        "LoD/1.07": "0x2791",
        "LoD/1.08": "0x2791",
        "LoD/1.09": "0x2791",
        "LoD/1.09b": "0x2791",
        "LoD/1.09d": "0x2791",
        "LoD/1.10": "0x282D",
        "LoD/1.11": "0x1DBD",
        "LoD/1.11b": "0x1DBD",
        "LoD/1.12a": "0x1DC5",
        "LoD/1.13c": "0x1DBD",
        "LoD/1.13d": "0x1DC5"
      },
      "sizes": {
        "LoD/1.07": 9,
        "LoD/1.08": 9,
        "LoD/1.09": 9,
        "LoD/1.09b": 9,
        "LoD/1.09d": 9,
        "LoD/1.10": 9,
        "LoD/1.11": 9,
        "LoD/1.11b": 9,
        "LoD/1.12a": 9,
        "LoD/1.13c": 9,
        "LoD/1.13d": 9
      },
      "name": "CRT_AcquireExitLock",
      "signature": "void CRT_AcquireExitLock(void)",
      "calling_convention": "__stdcall",
      "comment": "Acquires the CRT exit lock (critical section index 0xd/13).\n\nClassification: Thunk/Wrapper - wraps CRT_LockCriticalSection with fixed lock index.\n\nAlgorithm:\n1. Push lock index 0xd (exit lock) onto stack\n2. Call CRT_LockCriticalSection to acquire the critical section\n3. Clean up stack and return\n\nParameters: None\n\nReturns: void\n\nSpecial Cases:\n- If critical section not yet initialized, CRT_LockCriticalSection will allocate and initialize it\n- Blocks if another thread holds the exit lock\n\nRelated Functions:\n- CRT_ReleaseExitLock (FUN_6fc3279a): Releases this lock via LeaveCriticalSection\n- CRT_LockCriticalSection (FUN_6fc32d33): Generic lock acquisition by index\n- CRT_UnlockCriticalSection (FUN_6fc32d94): Generic lock release by index\n\nLock Table (DAT_6fc38644):\n- Index 0xd (13): Exit lock - protects process termination sequence\n- Used during atexit handler execution and process exit coordination",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:f23ef2b3a6cfdeb1f35221d5fc7b15e0",
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1,
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.08": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.09": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.09b": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.09d": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.10": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.11": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.11b": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.12a": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.13c": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.13d": "f23ef2b3a6cfdeb1f35221d5fc7b15e0"
      }
    },
    "d2net.dll_CRT_LeaveCritSectExit": {
      "addresses": {
        "LoD/1.07": "0x6FC3279A",
        "LoD/1.08": "0x6FC3279A",
        "LoD/1.09": "0x6FC0279A",
        "LoD/1.09b": "0x6FC0279A",
        "LoD/1.09d": "0x6FC0279A",
        "LoD/1.10": "0x6FC02836",
        "LoD/1.11": "0x6FBF37DD",
        "LoD/1.11b": "0x6FBF37DD",
        "LoD/1.12a": "0x6FBF3815",
        "LoD/1.13c": "0x6FBF3815",
        "LoD/1.13d": "0x6FBF37DD"
      },
      "rvas": {
        "LoD/1.07": "0x279A",
        "LoD/1.08": "0x279A",
        "LoD/1.09": "0x279A",
        "LoD/1.09b": "0x279A",
        "LoD/1.09d": "0x279A",
        "LoD/1.10": "0x2836",
        "LoD/1.11": "0x37DD",
        "LoD/1.11b": "0x37DD",
        "LoD/1.12a": "0x3815",
        "LoD/1.13c": "0x3815",
        "LoD/1.13d": "0x37DD"
      },
      "sizes": {
        "LoD/1.07": 9,
        "LoD/1.08": 9,
        "LoD/1.09": 9,
        "LoD/1.09b": 9,
        "LoD/1.09d": 9,
        "LoD/1.10": 9,
        "LoD/1.11": 9,
        "LoD/1.11b": 9,
        "LoD/1.12a": 9,
        "LoD/1.13c": 9,
        "LoD/1.13d": 9
      },
      "name": "CRT_LeaveCritSectExit",
      "signature": "void CRT_LeaveCritSectExit(void)",
      "calling_convention": "__stdcall",
      "comment": "Releases the CRT exit critical section (index 0xd/13).\n\nAlgorithm:\n1. Call CRT_LeaveCritSectByIndex with index 0xd (13) to release the exit lock\n2. Return to caller\n\nParameters: None\n\nReturns: void\n\nCalled by: CRT_DoExit (FUN_6fc326ec) at the end of process termination\nafter atexit handlers have been called.\n\nThe critical section at index 13 (0xd) in the g_apCrtCriticalSections array\nis used to synchronize CRT exit handling. This ensures thread-safe cleanup\nduring process termination.\n\nMagic Numbers:\n  0xd (13) - Index of the exit critical section in g_apCrtCriticalSections\n\nRelated Functions:\n  CRT_LeaveCritSectByIndex - Releases critical section by index\n  CRT_EnterCritSectByIndex - Acquires critical section by index",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:f23ef2b3a6cfdeb1f35221d5fc7b15e0",
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1,
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.08": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.09": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.09b": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.09d": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.10": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.11": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.11b": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.12a": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.13c": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.13d": "f23ef2b3a6cfdeb1f35221d5fc7b15e0"
      }
    },
    "d2net.dll_CRT_CallFunctionPointerArray": {
      "addresses": {
        "LoD/1.07": "0x6FC327A3",
        "LoD/1.08": "0x6FC327A3",
        "LoD/1.09": "0x6FC027A3",
        "LoD/1.09b": "0x6FC027A3",
        "LoD/1.09d": "0x6FC027A3",
        "LoD/1.10": "0x6FC0283F"
      },
      "rvas": {
        "LoD/1.07": "0x27A3",
        "LoD/1.08": "0x27A3",
        "LoD/1.09": "0x27A3",
        "LoD/1.09b": "0x27A3",
        "LoD/1.09d": "0x27A3",
        "LoD/1.10": "0x283F"
      },
      "sizes": {
        "LoD/1.07": 26,
        "LoD/1.08": 26,
        "LoD/1.09": 26,
        "LoD/1.09b": 26,
        "LoD/1.09d": 26,
        "LoD/1.10": 26
      },
      "name": "CRT_CallFunctionPointerArray",
      "signature": "void CRT_CallFunctionPointerArray(uint * ppfnStart, uint * ppfnEnd)",
      "calling_convention": "__cdecl",
      "comment": "Iterates through an array of function pointers, calling each non-NULL entry.\n\nAlgorithm:\n1. Compare start pointer against end pointer\n2. If start >= end, exit immediately (empty array)\n3. Load function pointer at current position\n4. If pointer is non-NULL, call the function\n5. Advance to next array element (+4 bytes)\n6. Loop back to step 1\n\nParameters:\n  ppfnStart (uint *) - Pointer to start of function pointer array\n  ppfnEnd (uint *) - Pointer to end of function pointer array (exclusive)\n\nReturns:\n  void - No return value\n\nClassification: Internal utility (leaf function)\nCalled by CRT_RunInitializers for C/C++ static initializers and\nCRT_DoExit for atexit/pre-termination handlers.\n\nControl Flow:\n  Entry -> Loop condition check -> If empty, exit\n  Loop body: Load ptr -> If non-NULL call it -> Advance -> Loop\n  Loop exit when start >= end\n\nMemory Model:\n  No allocation. Array is read-only. Called functions may have side effects.\n  Assumes array contains valid function pointers or NULL.\n\nNotes:\n  The array bounds are [ppfnStart, ppfnEnd) - end is exclusive.\n  Each element is a 4-byte function pointer. NULL entries are skipped.\n  This is a standard CRT pattern for executing static initializer tables\n  populated by the linker (.CRT$XCA, .CRT$XCZ sections).",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:f1060dff4c8b86b7cd32c42f8f136fb6",
      "basic_block_counts": {
        "LoD/1.07": 6,
        "LoD/1.08": 6,
        "LoD/1.09": 6,
        "LoD/1.09b": 6,
        "LoD/1.09d": 6,
        "LoD/1.10": 6
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "f1060dff4c8b86b7cd32c42f8f136fb6",
        "LoD/1.08": "f1060dff4c8b86b7cd32c42f8f136fb6",
        "LoD/1.09": "f1060dff4c8b86b7cd32c42f8f136fb6",
        "LoD/1.09b": "f1060dff4c8b86b7cd32c42f8f136fb6",
        "LoD/1.09d": "f1060dff4c8b86b7cd32c42f8f136fb6",
        "LoD/1.10": "f1060dff4c8b86b7cd32c42f8f136fb6"
      }
    },
    "d2net.dll_NET_MemmoveBuffer": {
      "addresses": {
        "LoD/1.07": "0x6FC327C0",
        "LoD/1.08": "0x6FC327C0",
        "LoD/1.09": "0x6FC04250",
        "LoD/1.09b": "0x6FC027C0",
        "LoD/1.09d": "0x6FC04250",
        "LoD/1.10": "0x6FC042F0"
      },
      "rvas": {
        "LoD/1.07": "0x27C0",
        "LoD/1.08": "0x27C0",
        "LoD/1.09": "0x4250",
        "LoD/1.09b": "0x27C0",
        "LoD/1.09d": "0x4250",
        "LoD/1.10": "0x42F0"
      },
      "sizes": {
        "LoD/1.07": 664,
        "LoD/1.08": 664,
        "LoD/1.09": 664,
        "LoD/1.09b": 664,
        "LoD/1.09d": 664,
        "LoD/1.10": 664
      },
      "name": "NET_MemmoveBuffer",
      "signature": "void * NET_MemmoveBuffer(void * pDest, void * pSrc, dword dwByteCount)",
      "calling_convention": "__cdecl",
      "comment": "Optimized memory move implementation for network buffers that safely handles overlapping regions.\n\nClassification: Internal utility function - optimized memmove for network packet handling.\n\nAlgorithm:\n1. Check for overlapping regions: if (pSrc < pDest < pSrc + dwByteCount), must copy backwards\n2. For backwards copy (overlapping, dest > src):\n   a. Start from end of buffers: pCurrSrc = pSrc + dwByteCount - 4, pCurrDest = pDest + dwByteCount - 4\n   b. If destination is DWORD-aligned (pCurrDest & 3 == 0):\n      - Calculate dwDwordCount = dwByteCount >> 2 (number of DWORDs)\n      - Calculate dwRemainderBytes = dwByteCount & 3 (trailing bytes)\n      - If dwDwordCount > 7, use REP MOVSD with STD (backward direction)\n   c. If destination is NOT DWORD-aligned:\n      - Copy 1-3 bytes to align destination to DWORD boundary\n      - Then proceed with DWORD copy as above\n   d. Handle remainder bytes (0-3) via switch table\n3. For forward copy (non-overlapping or src >= dest):\n   a. Start from beginning: pCurrDest = pDest\n   b. If destination is DWORD-aligned:\n      - Use REP MOVSD for bulk DWORD copy when dwDwordCount > 7\n   c. If destination is NOT DWORD-aligned:\n      - Copy 1-3 bytes to align destination\n      - Then proceed with DWORD copy\n   d. Handle remainder bytes (0-3) via switch table\n4. Duff's device optimization for small DWORD counts (1-7): unrolled switch statement\n5. Return original pDest pointer\n\nParameters:\n  pDest (void *) - Destination buffer pointer [EBP+0x8]\n  pSrc (void *) - Source buffer pointer [EBP+0xC]  \n  dwByteCount (uint) - Number of bytes to copy [EBP+0x10]\n\nReturns:\n  void * - Original destination pointer (pDest), enables call chaining\n\nLocals:\n  dwDwordCount (uint) - Number of DWORDs to copy (dwByteCount >> 2)\n  dwRemainderBytes (uint) - Remainder bytes after DWORD copy (dwByteCount & 3)\n  pCurrSrc (byte *) - Current source pointer during copy\n  pCurrDest (byte *) - Current destination pointer during copy\n\nCallers:\n  NET_ParseAndQueuePackets - Network packet parsing\n  FUN_6fc349e2 - Network buffer manipulation\n  FUN_6fc314da - Network operations\n\nSpecial Cases:\n  - Zero-length copy: Returns immediately\n  - Overlapping regions: Uses backward copy to prevent data corruption\n  - Unaligned addresses: Handles 1-3 byte alignment prefix before DWORD copy\n\nMagic Numbers:\n  0x3 - DWORD alignment mask\n  0x4 - DWORD size\n  0x7/8 - Threshold for REP MOVSD vs unrolled loop\n  Jump tables at 0x6fc32908, 0x6fc32918, 0x6fc32820, 0x6fc32aa0 - Switch dispatch",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:bff09423b51fd121ea30afec957819f4",
      "basic_block_counts": {
        "LoD/1.07": 63,
        "LoD/1.08": 63,
        "LoD/1.09": 63,
        "LoD/1.09b": 63,
        "LoD/1.09d": 63,
        "LoD/1.10": 63
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "bff09423b51fd121ea30afec957819f4",
        "LoD/1.08": "bff09423b51fd121ea30afec957819f4",
        "LoD/1.09": "bff09423b51fd121ea30afec957819f4",
        "LoD/1.09b": "bff09423b51fd121ea30afec957819f4",
        "LoD/1.09d": "bff09423b51fd121ea30afec957819f4",
        "LoD/1.10": "bff09423b51fd121ea30afec957819f4"
      }
    },
    "d2net.dll_CRT_DllMainCRTStartup": {
      "addresses": {
        "LoD/1.07": "0x6FC32AF5",
        "LoD/1.08": "0x6FC32AF5",
        "LoD/1.09": "0x6FC02AF5",
        "LoD/1.09b": "0x6FC02AF5",
        "LoD/1.09d": "0x6FC02AF5",
        "LoD/1.10": "0x6FC02B95"
      },
      "rvas": {
        "LoD/1.07": "0x2AF5",
        "LoD/1.08": "0x2AF5",
        "LoD/1.09": "0x2AF5",
        "LoD/1.09b": "0x2AF5",
        "LoD/1.09d": "0x2AF5",
        "LoD/1.10": "0x2B95"
      },
      "sizes": {
        "LoD/1.07": 217,
        "LoD/1.08": 217,
        "LoD/1.09": 217,
        "LoD/1.09b": 217,
        "LoD/1.09d": 217,
        "LoD/1.10": 217
      },
      "name": "CRT_DllMainCRTStartup",
      "signature": "dword CRT_DllMainCRTStartup(void * hDllHandle, dword dwReason)",
      "calling_convention": "__stdcall",
      "comment": "CRT_DllMainCRTStartup - C Runtime DLL initialization/termination handler\n\nCalled by DllMain entry point to perform CRT initialization on DLL_PROCESS_ATTACH\nand cleanup on DLL_PROCESS_DETACH.\n\nAlgorithm:\n1. Check dwReason parameter for operation type\n2. If DLL_PROCESS_ATTACH (1):\n   a. Call GetVersion() to retrieve OS version information\n   b. Store raw version in g_dwOsVersionInfo\n   c. Initialize CRT heap via FUN_6fc336f2\n   d. Parse version: major (low byte), minor (byte 1), build (high word)\n   e. Store parsed values in g_dwOsMajorVersion, g_dwOsMinorVersion, g_dwOsBuildNumber\n   f. Initialize CRT internals via FUN_6fc32da9\n   g. Get command line via GetCommandLineA() -> g_lpszCmdLine\n   h. Get environment block via FUN_6fc3344b -> g_lpszEnvironment\n   i. Run CRT startup functions (FUN_6fc32f35, FUN_6fc331fe, FUN_6fc33145)\n   j. Run C initializers via CRT_RunInitializers\n   k. Increment g_nCrtInitCount reference counter\n3. If DLL_PROCESS_DETACH (0):\n   a. Check g_nCrtInitCount > 0, return 0 if not initialized\n   b. Decrement g_nCrtInitCount\n   c. If g_fCrtExitInProgress == 0, run atexit handlers via CRT_RunAtexitCleanup\n   d. Run CRT cleanup functions (FUN_6fc330f1, FUN_6fc32dfd, FUN_6fc3374f)\n4. If DLL_THREAD_DETACH (3):\n   a. Call FUN_6fc32e95(NULL) for thread-local cleanup\n5. Return 1 on success, 0 on failure\n\nParameters:\n  hDllHandle (void *) - DLL module handle (unused)\n  dwReason (dword) - DLL notification reason code:\n    0 = DLL_PROCESS_DETACH\n    1 = DLL_PROCESS_ATTACH  \n    2 = DLL_THREAD_ATTACH (handled elsewhere)\n    3 = DLL_THREAD_DETACH\n\nReturns:\n  1 - Success\n  0 - Failure (init failed or already detached)\n\nGlobals Modified:\n  g_dwOsVersionInfo (0x6fc3b23c) - Raw GetVersion() result, then shifted build number\n  g_dwOsMajorVersion (0x6fc3b244) - OS major version (low byte)\n  g_dwOsMinorVersion (0x6fc3b248) - OS minor version (byte 1)\n  g_dwOsBuildNumber (0x6fc3b240) - Combined version for build checks\n  g_nCrtInitCount (0x6fc3b27c) - CRT initialization reference count\n  g_lpszCmdLine (0x6fc3b8e4) - Command line string pointer\n  g_lpszEnvironment (0x6fc3b280) - Environment block pointer",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:966ae3d3931d4719f3b38eb61e43e94b",
      "basic_block_counts": {
        "LoD/1.07": 15,
        "LoD/1.08": 15,
        "LoD/1.09": 15,
        "LoD/1.09b": 15,
        "LoD/1.09d": 15,
        "LoD/1.10": 15
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "966ae3d3931d4719f3b38eb61e43e94b",
        "LoD/1.08": "966ae3d3931d4719f3b38eb61e43e94b",
        "LoD/1.09": "966ae3d3931d4719f3b38eb61e43e94b",
        "LoD/1.09b": "966ae3d3931d4719f3b38eb61e43e94b",
        "LoD/1.09d": "966ae3d3931d4719f3b38eb61e43e94b",
        "LoD/1.10": "966ae3d3931d4719f3b38eb61e43e94b"
      }
    },
    "d2net.dll_MNE_bafce56213ce": {
      "addresses": {
        "LoD/1.07": "0x6FC32BCE",
        "LoD/1.08": "0x6FC32BCE",
        "LoD/1.09": "0x6FC02BCE",
        "LoD/1.09b": "0x6FC02BCE",
        "LoD/1.09d": "0x6FC02BCE",
        "LoD/1.10": "0x6FC02C6E"
      },
      "rvas": {
        "LoD/1.07": "0x2BCE",
        "LoD/1.08": "0x2BCE",
        "LoD/1.09": "0x2BCE",
        "LoD/1.09b": "0x2BCE",
        "LoD/1.09d": "0x2BCE",
        "LoD/1.10": "0x2C6E"
      },
      "sizes": {
        "LoD/1.07": 157,
        "LoD/1.08": 157,
        "LoD/1.09": 157,
        "LoD/1.09b": 157,
        "LoD/1.09d": 157,
        "LoD/1.10": 157
      },
      "name": "entry",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:bafce56213ce6cb4a7088c594df572ea",
      "basic_block_counts": {
        "LoD/1.07": 21,
        "LoD/1.08": 21,
        "LoD/1.09": 21,
        "LoD/1.09b": 21,
        "LoD/1.09d": 21,
        "LoD/1.10": 21
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "bafce56213ce6cb4a7088c594df572ea",
        "LoD/1.08": "bafce56213ce6cb4a7088c594df572ea",
        "LoD/1.09": "bafce56213ce6cb4a7088c594df572ea",
        "LoD/1.09b": "bafce56213ce6cb4a7088c594df572ea",
        "LoD/1.09d": "bafce56213ce6cb4a7088c594df572ea",
        "LoD/1.10": "bafce56213ce6cb4a7088c594df572ea"
      }
    },
    "d2net.dll___amsg_exit": {
      "addresses": {
        "LoD/1.07": "0x6FC32C6B",
        "LoD/1.08": "0x6FC32C6B",
        "LoD/1.09": "0x6FC02C6B",
        "LoD/1.09b": "0x6FC02C6B",
        "LoD/1.09d": "0x6FC02C6B",
        "LoD/1.10": "0x6FC02D0B",
        "LoD/1.11": "0x6FBF175A",
        "LoD/1.11b": "0x6FBF175A",
        "LoD/1.12a": "0x6FBF1762",
        "LoD/1.13c": "0x6FBF175A",
        "LoD/1.13d": "0x6FBF1762"
      },
      "rvas": {
        "LoD/1.07": "0x2C6B",
        "LoD/1.08": "0x2C6B",
        "LoD/1.09": "0x2C6B",
        "LoD/1.09b": "0x2C6B",
        "LoD/1.09d": "0x2C6B",
        "LoD/1.10": "0x2D0B",
        "LoD/1.11": "0x175A",
        "LoD/1.11b": "0x175A",
        "LoD/1.12a": "0x1762",
        "LoD/1.13c": "0x175A",
        "LoD/1.13d": "0x1762"
      },
      "sizes": {
        "LoD/1.07": 48,
        "LoD/1.08": 48,
        "LoD/1.09": 48,
        "LoD/1.09b": 48,
        "LoD/1.09d": 48,
        "LoD/1.10": 48,
        "LoD/1.11": 48,
        "LoD/1.11b": 48,
        "LoD/1.12a": 48,
        "LoD/1.13c": 48,
        "LoD/1.13d": 48
      },
      "name": "__amsg_exit",
      "signature": "void __amsg_exit(int param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __amsg_exit\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:bed936c73fe1864937225129603e250c",
      "basic_block_counts": {
        "LoD/1.07": 5,
        "LoD/1.08": 5,
        "LoD/1.09": 5,
        "LoD/1.09b": 5,
        "LoD/1.09d": 5,
        "LoD/1.10": 5,
        "LoD/1.11": 5,
        "LoD/1.11b": 5,
        "LoD/1.12a": 5,
        "LoD/1.13c": 5,
        "LoD/1.13d": 5
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "bed936c73fe1864937225129603e250c",
        "LoD/1.08": "bed936c73fe1864937225129603e250c",
        "LoD/1.09": "bed936c73fe1864937225129603e250c",
        "LoD/1.09b": "bed936c73fe1864937225129603e250c",
        "LoD/1.09d": "bed936c73fe1864937225129603e250c",
        "LoD/1.10": "bed936c73fe1864937225129603e250c",
        "LoD/1.11": "bed936c73fe1864937225129603e250c",
        "LoD/1.11b": "bed936c73fe1864937225129603e250c",
        "LoD/1.12a": "bed936c73fe1864937225129603e250c",
        "LoD/1.13c": "bed936c73fe1864937225129603e250c",
        "LoD/1.13d": "bed936c73fe1864937225129603e250c"
      }
    },
    "d2net.dll_CRT_InitializeStaticLocks": {
      "addresses": {
        "LoD/1.07": "0x6FC32C9E",
        "LoD/1.08": "0x6FC32C9E",
        "LoD/1.09": "0x6FC02C9E",
        "LoD/1.09b": "0x6FC02C9E",
        "LoD/1.09d": "0x6FC02C9E",
        "LoD/1.10": "0x6FC02D3E"
      },
      "rvas": {
        "LoD/1.07": "0x2C9E",
        "LoD/1.08": "0x2C9E",
        "LoD/1.09": "0x2C9E",
        "LoD/1.09b": "0x2C9E",
        "LoD/1.09d": "0x2C9E",
        "LoD/1.10": "0x2D3E"
      },
      "sizes": {
        "LoD/1.07": 41,
        "LoD/1.08": 41,
        "LoD/1.09": 41,
        "LoD/1.09b": 41,
        "LoD/1.09d": 41,
        "LoD/1.10": 41
      },
      "name": "CRT_InitializeStaticLocks",
      "signature": "void CRT_InitializeStaticLocks(void)",
      "calling_convention": "__stdcall",
      "comment": "Initializes four pre-allocated critical sections for CRT (C Runtime Library) static locks.\n\nThese locks are allocated statically (not via the lock table) and initialized at CRT startup\nbefore general heap/threading operations are available. They protect core CRT subsystems.\n\nAlgorithm:\n1. Load InitializeCriticalSection function pointer into ESI for repeated calls\n2. Initialize g_pCrtLock_Console - protects console I/O operations\n3. Initialize g_pCrtLock_IOB - protects I/O buffer management (_iob array)\n4. Initialize g_pCrtLock_Signal - protects signal handler state\n5. Initialize g_pCrtLock_Heap - protects CRT heap operations (malloc/free)\n\nParameters:\nNone - this function takes no parameters.\n\nReturns:\nvoid - no return value.\n\nLock Index Mapping (in g_apCrtLocks array):\n- Index 0 (0x6fc38648): Heap lock - protects malloc/free/realloc\n- Index 2 (0x6fc38668): Signal lock - protects signal() handler registration\n- Index 4 (0x6fc38678): IOB lock - protects _iob file handle array\n- Index 17 (0x6fc38688): Console lock - protects printf/scanf console operations\n\nNote: These four locks are excluded from cleanup in the destructor (FUN_6fc32cc7) to prevent\nrace conditions during CRT shutdown, and are deleted last in a specific order.\n\nCalled By: FUN_6fc32da9 (CRT thread initialization)\nRelated: CRT_EnterCritSectByIndex, FUN_6fc32cc7 (cleanup counterpart)",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:e1bb2af96e763a0793e4aabbeb4bef2b",
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "e1bb2af96e763a0793e4aabbeb4bef2b",
        "LoD/1.08": "e1bb2af96e763a0793e4aabbeb4bef2b",
        "LoD/1.09": "e1bb2af96e763a0793e4aabbeb4bef2b",
        "LoD/1.09b": "e1bb2af96e763a0793e4aabbeb4bef2b",
        "LoD/1.09d": "e1bb2af96e763a0793e4aabbeb4bef2b",
        "LoD/1.10": "e1bb2af96e763a0793e4aabbeb4bef2b"
      }
    },
    "d2net.dll_CRT_DestroyStaticLocks": {
      "addresses": {
        "LoD/1.07": "0x6FC32CC7",
        "LoD/1.08": "0x6FC32CC7",
        "LoD/1.09": "0x6FC02CC7",
        "LoD/1.09b": "0x6FC02CC7",
        "LoD/1.09d": "0x6FC02CC7",
        "LoD/1.10": "0x6FC02D67"
      },
      "rvas": {
        "LoD/1.07": "0x2CC7",
        "LoD/1.08": "0x2CC7",
        "LoD/1.09": "0x2CC7",
        "LoD/1.09b": "0x2CC7",
        "LoD/1.09d": "0x2CC7",
        "LoD/1.10": "0x2D67"
      },
      "sizes": {
        "LoD/1.07": 108,
        "LoD/1.08": 108,
        "LoD/1.09": 108,
        "LoD/1.09b": 108,
        "LoD/1.09d": 108,
        "LoD/1.10": 108
      },
      "name": "CRT_DestroyStaticLocks",
      "signature": "void CRT_DestroyStaticLocks(void)",
      "calling_convention": "__stdcall",
      "comment": "Destroys all CRT critical section locks during runtime cleanup.\n\nAlgorithm:\n1. Load pointer to DeleteCriticalSection API into EDI\n2. Initialize ESI to start of g_apCrtLocks array (0x6fc38644)\n3. Loop through each pointer in the lock array:\n   a. If pointer is NULL, skip to next entry\n   b. If pointer matches one of 4 reserved static locks, skip\n   c. Otherwise call DeleteCriticalSection on the lock\n   d. Call CRT_Free (FUN_6fc33983) to release memory\n   e. Advance ESI by 4 bytes to next pointer\n4. Continue until ESI reaches 0x6fc38704 (array end)\n5. Delete the 4 reserved static locks in order:\n   - g_pCrtLock_Signal (index 9, offset 0x24)\n   - g_pCrtLock_IOB (index 13, offset 0x34)\n   - g_pCrtLock_Console (index 17, offset 0x44)\n   - g_pCrtLock_Heap (index 1, offset 0x04)\n\nParameters: None\n\nReturns: void\n\nSpecial Cases:\n- Reserved locks (Heap, Signal, IOB, Console) are skipped in loop\n  and destroyed separately at end to ensure proper cleanup order\n- NULL pointers in array are safely skipped\n\nGlobal Data:\n- g_apCrtLocks (0x6fc38644): Array of CRITICAL_SECTION pointers\n  - Array spans 0x6fc38644 to 0x6fc38704 (48 entries, 192 bytes)\n- g_pfnDeleteCriticalSection (0x6fc370b4): Cached API pointer\n- g_pCrtLock_Heap (0x6fc38648): Heap allocation lock\n- g_pCrtLock_Signal (0x6fc38668): Signal handling lock  \n- g_pCrtLock_IOB (0x6fc38678): I/O buffer lock\n- g_pCrtLock_Console (0x6fc38688): Console I/O lock\n\nCalled By: FUN_6fc32dfd (CRT cleanup during DLL unload)\nCalls: DeleteCriticalSection (via cached pointer), FUN_6fc33983 (CRT_Free)",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:a0707ad44a579985e4c3b985375d38cb",
      "basic_block_counts": {
        "LoD/1.07": 9,
        "LoD/1.08": 9,
        "LoD/1.09": 9,
        "LoD/1.09b": 9,
        "LoD/1.09d": 9,
        "LoD/1.10": 9
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "a0707ad44a579985e4c3b985375d38cb",
        "LoD/1.08": "a0707ad44a579985e4c3b985375d38cb",
        "LoD/1.09": "a0707ad44a579985e4c3b985375d38cb",
        "LoD/1.09b": "a0707ad44a579985e4c3b985375d38cb",
        "LoD/1.09d": "a0707ad44a579985e4c3b985375d38cb",
        "LoD/1.10": "a0707ad44a579985e4c3b985375d38cb"
      }
    },
    "d2net.dll_CRT_EnterCritSectByIndex": {
      "addresses": {
        "LoD/1.07": "0x6FC32D33",
        "LoD/1.08": "0x6FC32D33",
        "LoD/1.09": "0x6FC02D33",
        "LoD/1.09b": "0x6FC02D33",
        "LoD/1.09d": "0x6FC02D33",
        "LoD/1.10": "0x6FC02DD3"
      },
      "rvas": {
        "LoD/1.07": "0x2D33",
        "LoD/1.08": "0x2D33",
        "LoD/1.09": "0x2D33",
        "LoD/1.09b": "0x2D33",
        "LoD/1.09d": "0x2D33",
        "LoD/1.10": "0x2DD3"
      },
      "sizes": {
        "LoD/1.07": 97,
        "LoD/1.08": 97,
        "LoD/1.09": 97,
        "LoD/1.09b": 97,
        "LoD/1.09d": 97,
        "LoD/1.10": 97
      },
      "name": "CRT_EnterCritSectByIndex",
      "signature": "void CRT_EnterCritSectByIndex(int nLockIndex)",
      "calling_convention": "__cdecl",
      "comment": "Enters a CRT critical section by lock index, creating the lock on first use.\n\nAlgorithm:\n1. Calculate pointer to lock entry: ppCritSect = &g_apCrtLocks[nLockIndex]\n2. If lock pointer is NULL (first use):\n   a. Allocate 0x18 (24) bytes for CRITICAL_SECTION structure via _malloc\n   b. If allocation fails, call __amsg_exit(0x11) - fatal error R6017\n   c. Recursively enter lock index 0x11 (heap lock) to serialize initialization\n   d. Double-check: if lock is still NULL (race condition guard):\n      - Initialize the critical section via InitializeCriticalSection\n      - Store pointer in g_apCrtLocks[nLockIndex]\n   e. If lock was initialized by another thread, free allocated memory\n   f. Leave heap lock (index 0x11)\n3. Enter the critical section at g_apCrtLocks[nLockIndex]\n\nParameters:\n  nLockIndex (int) - Index into g_apCrtLocks array (0-47)\n                     Common indices: 0x11 (17) = heap lock\n\nReturns: void\n\nSpecial Cases:\n- First-time initialization uses double-checked locking pattern\n- Memory allocation failure causes fatal exit (R6017)\n- Index 0x11 is the heap lock used to serialize other lock initializations\n\nGlobal Data:\n- g_apCrtLocks (0x6fc38644): Array of 48 CRITICAL_SECTION pointers\n  Indexed by lock type (0-47), NULL until first use\n\nMagic Numbers:\n- 0x18 = sizeof(CRITICAL_SECTION) = 24 bytes\n- 0x11 = 17 = CRT heap lock index (used for serialization)\n\nCalled By: CRT_AcquireExitLock, FUN_6fc33983, FUN_6fc33aaa, FUN_6fc33ba6,\n           FUN_6fc33e5b, FUN_6fc35f59, FUN_6fc36220, FUN_6fc362f0\n\nCalls: _malloc, __amsg_exit, InitializeCriticalSection, EnterCriticalSection,\n       FUN_6fc33983 (CRT_Free), CRT_LeaveCritSectByIndex (recursive)",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:5ba7875cbad7a3d5fce31ff25fd40455",
      "basic_block_counts": {
        "LoD/1.07": 8,
        "LoD/1.08": 8,
        "LoD/1.09": 8,
        "LoD/1.09b": 8,
        "LoD/1.09d": 8,
        "LoD/1.10": 8
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "5ba7875cbad7a3d5fce31ff25fd40455",
        "LoD/1.08": "5ba7875cbad7a3d5fce31ff25fd40455",
        "LoD/1.09": "5ba7875cbad7a3d5fce31ff25fd40455",
        "LoD/1.09b": "5ba7875cbad7a3d5fce31ff25fd40455",
        "LoD/1.09d": "5ba7875cbad7a3d5fce31ff25fd40455",
        "LoD/1.10": "5ba7875cbad7a3d5fce31ff25fd40455"
      }
    },
    "d2net.dll_CRT_LeaveCritSectByIndex": {
      "addresses": {
        "LoD/1.07": "0x6FC32D94",
        "LoD/1.08": "0x6FC32D94",
        "LoD/1.09": "0x6FC02D94",
        "LoD/1.09b": "0x6FC02D94",
        "LoD/1.09d": "0x6FC02D94",
        "LoD/1.10": "0x6FC02E34",
        "LoD/1.11": "0x6FBF182B",
        "LoD/1.11b": "0x6FBF182B",
        "LoD/1.12a": "0x6FBF1833",
        "LoD/1.13c": "0x6FBF182B",
        "LoD/1.13d": "0x6FBF1833"
      },
      "rvas": {
        "LoD/1.07": "0x2D94",
        "LoD/1.08": "0x2D94",
        "LoD/1.09": "0x2D94",
        "LoD/1.09b": "0x2D94",
        "LoD/1.09d": "0x2D94",
        "LoD/1.10": "0x2E34",
        "LoD/1.11": "0x182B",
        "LoD/1.11b": "0x182B",
        "LoD/1.12a": "0x1833",
        "LoD/1.13c": "0x182B",
        "LoD/1.13d": "0x1833"
      },
      "sizes": {
        "LoD/1.07": 21,
        "LoD/1.08": 21,
        "LoD/1.09": 21,
        "LoD/1.09b": 21,
        "LoD/1.09d": 21,
        "LoD/1.10": 21,
        "LoD/1.11": 21,
        "LoD/1.11b": 21,
        "LoD/1.12a": 21,
        "LoD/1.13c": 21,
        "LoD/1.13d": 21
      },
      "name": "CRT_LeaveCritSectByIndex",
      "signature": "void CRT_LeaveCritSectByIndex(uint dwLockIndex)",
      "calling_convention": "__cdecl",
      "comment": "Releases a CRT critical section lock by its index.\n\nClassification: Leaf function - wrapper around Win32 LeaveCriticalSection.\n\nAlgorithm:\n1. Index into g_apCrtLocks array using dwLockIndex\n2. Call LeaveCriticalSection on the retrieved CRITICAL_SECTION pointer\n\nParameters:\n  dwLockIndex (uint) - Zero-based index into g_apCrtLocks array\n\nReturns:\n  void\n\nSpecial Cases:\n  - No bounds checking on index; caller must ensure valid range\n  - Must be paired with prior CRT_EnterCritSectByIndex call\n\nGlobal Data:\n  g_apCrtLocks (0x6fc38644) - Array of LPCRITICAL_SECTION pointers\n\nCalled By: 12 functions including CRT_EnterCritSectByIndex, CRT_LeaveCritSectExit",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:e83d104051445238b4510431aa98563d",
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1,
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "e83d104051445238b4510431aa98563d",
        "LoD/1.08": "e83d104051445238b4510431aa98563d",
        "LoD/1.09": "e83d104051445238b4510431aa98563d",
        "LoD/1.09b": "e83d104051445238b4510431aa98563d",
        "LoD/1.09d": "e83d104051445238b4510431aa98563d",
        "LoD/1.10": "e83d104051445238b4510431aa98563d",
        "LoD/1.11": "e83d104051445238b4510431aa98563d",
        "LoD/1.11b": "e83d104051445238b4510431aa98563d",
        "LoD/1.12a": "e83d104051445238b4510431aa98563d",
        "LoD/1.13c": "e83d104051445238b4510431aa98563d",
        "LoD/1.13d": "e83d104051445238b4510431aa98563d"
      }
    },
    "d2net.dll_CRT_InitializeThreadLocalStora": {
      "addresses": {
        "LoD/1.07": "0x6FC32DA9",
        "LoD/1.08": "0x6FC32DA9",
        "LoD/1.09": "0x6FC02DA9",
        "LoD/1.09b": "0x6FC02DA9",
        "LoD/1.09d": "0x6FC02DA9",
        "LoD/1.10": "0x6FC02E49"
      },
      "rvas": {
        "LoD/1.07": "0x2DA9",
        "LoD/1.08": "0x2DA9",
        "LoD/1.09": "0x2DA9",
        "LoD/1.09b": "0x2DA9",
        "LoD/1.09d": "0x2DA9",
        "LoD/1.10": "0x2E49"
      },
      "sizes": {
        "LoD/1.07": 84,
        "LoD/1.08": 84,
        "LoD/1.09": 84,
        "LoD/1.09b": 84,
        "LoD/1.09d": 84,
        "LoD/1.10": 84
      },
      "name": "CRT_InitializeThreadLocalStorage",
      "signature": "BOOL CRT_InitializeThreadLocalStorage(void)",
      "calling_convention": "__stdcall",
      "comment": "Initializes Thread Local Storage (TLS) for the C Runtime Library.\n\nCalled during DLL initialization from CRT_DllMainCRTStartup to set up per-thread\ndata storage for the CRT.\n\nAlgorithm:\n1. Initialize static critical sections via CRT_InitializeStaticLocks\n2. Allocate a TLS slot via TlsAlloc, store index in g_dwTlsIndex\n3. If TLS allocation failed (returned 0xFFFFFFFF), return failure\n4. Allocate 0x74 (116) byte TLS data structure via CRT heap allocator\n5. If allocation failed, return failure\n6. Store TLS data pointer in the allocated TLS slot via TlsSetValue\n7. If TlsSetValue failed, return failure\n8. Initialize TLS data structure fields via FUN_6fc32e1b\n9. Get current thread ID via GetCurrentThreadId\n10. Store thread ID at offset +0x00 of TLS data\n11. Set offset +0x04 to 0xFFFFFFFF (invalid/uninitialized marker)\n12. Return TRUE (1) for success\n\nReturns:\n  BOOL - TRUE (1) on success, FALSE (0) on failure\n\nTLS Data Structure Layout (0x74 bytes):\n  Offset  Size  Description\n  +0x00   4     Current thread ID (DWORD)\n  +0x04   4     Status/marker, initialized to 0xFFFFFFFF\n  +0x14   4     Initialized to 1 by FUN_6fc32e1b\n  +0x50   4     Pointer to DAT_6fc387c0 set by FUN_6fc32e1b\n\nGlobal State Modified:\n  g_dwTlsIndex (0x6fc38704) - Stores allocated TLS slot index\n\nError Handling:\n  Returns 0 immediately if any step fails (TlsAlloc, memory allocation, TlsSetValue)",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:1563254ce315644019ac4e0b71caac74",
      "basic_block_counts": {
        "LoD/1.07": 5,
        "LoD/1.08": 5,
        "LoD/1.09": 5,
        "LoD/1.09b": 5,
        "LoD/1.09d": 5,
        "LoD/1.10": 5
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "1563254ce315644019ac4e0b71caac74",
        "LoD/1.08": "1563254ce315644019ac4e0b71caac74",
        "LoD/1.09": "1563254ce315644019ac4e0b71caac74",
        "LoD/1.09b": "1563254ce315644019ac4e0b71caac74",
        "LoD/1.09d": "1563254ce315644019ac4e0b71caac74",
        "LoD/1.10": "1563254ce315644019ac4e0b71caac74"
      }
    },
    "d2net.dll_CRT_CleanupTlsAndLocks": {
      "addresses": {
        "LoD/1.07": "0x6FC32DFD",
        "LoD/1.08": "0x6FC32DFD",
        "LoD/1.09": "0x6FC02DFD",
        "LoD/1.09b": "0x6FC02DFD",
        "LoD/1.09d": "0x6FC02DFD",
        "LoD/1.10": "0x6FC02E9D",
        "LoD/1.11": "0x6FBF37E6",
        "LoD/1.11b": "0x6FBF37E6",
        "LoD/1.12a": "0x6FBF381E",
        "LoD/1.13c": "0x6FBF381E",
        "LoD/1.13d": "0x6FBF37E6"
      },
      "rvas": {
        "LoD/1.07": "0x2DFD",
        "LoD/1.08": "0x2DFD",
        "LoD/1.09": "0x2DFD",
        "LoD/1.09b": "0x2DFD",
        "LoD/1.09d": "0x2DFD",
        "LoD/1.10": "0x2E9D",
        "LoD/1.11": "0x37E6",
        "LoD/1.11b": "0x37E6",
        "LoD/1.12a": "0x381E",
        "LoD/1.13c": "0x381E",
        "LoD/1.13d": "0x37E6"
      },
      "sizes": {
        "LoD/1.07": 30,
        "LoD/1.08": 30,
        "LoD/1.09": 30,
        "LoD/1.09b": 30,
        "LoD/1.09d": 30,
        "LoD/1.10": 30,
        "LoD/1.11": 30,
        "LoD/1.11b": 30,
        "LoD/1.12a": 30,
        "LoD/1.13c": 30,
        "LoD/1.13d": 30
      },
      "name": "CRT_CleanupTlsAndLocks",
      "signature": "void CRT_CleanupTlsAndLocks(void)",
      "calling_convention": "__stdcall",
      "comment": "Performs CRT cleanup during DLL unload by destroying static locks and freeing TLS index.\n\nAlgorithm:\n1. Call CRT_DestroyStaticLocks to release all CRT critical section locks\n2. Load g_dwTlsIndex from 0x6fc38704\n3. Check if TLS index is valid (not 0xFFFFFFFF)\n4. If valid, call TlsFree to release the TLS slot\n5. Set g_dwTlsIndex to 0xFFFFFFFF to mark as invalid\n6. Return\n\nParameters: None\n\nReturns: void\n\nGlobal Data:\n- g_dwTlsIndex (0x6fc38704): TLS slot index allocated by TlsAlloc\n  - 0xFFFFFFFF indicates no TLS slot allocated\n  - Valid index freed via TlsFree during cleanup\n\nCalled By: CRT_DllMainCRTStartup (during DLL_PROCESS_DETACH)\nCalls: CRT_DestroyStaticLocks, TlsFree (via import pointer at 0x6fc370f4)\n\nSpecial Cases:\n- TLS index check prevents double-free if already cleaned up\n- Setting index to 0xFFFFFFFF after free ensures idempotent cleanup",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:83d07e3c014d31c19cf14861bc62b0a0",
      "basic_block_counts": {
        "LoD/1.07": 3,
        "LoD/1.08": 3,
        "LoD/1.09": 3,
        "LoD/1.09b": 3,
        "LoD/1.09d": 3,
        "LoD/1.10": 3,
        "LoD/1.11": 3,
        "LoD/1.11b": 3,
        "LoD/1.12a": 3,
        "LoD/1.13c": 3,
        "LoD/1.13d": 3
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "83d07e3c014d31c19cf14861bc62b0a0",
        "LoD/1.08": "83d07e3c014d31c19cf14861bc62b0a0",
        "LoD/1.09": "83d07e3c014d31c19cf14861bc62b0a0",
        "LoD/1.09b": "83d07e3c014d31c19cf14861bc62b0a0",
        "LoD/1.09d": "83d07e3c014d31c19cf14861bc62b0a0",
        "LoD/1.10": "83d07e3c014d31c19cf14861bc62b0a0",
        "LoD/1.11": "a4ba30fe4414581a89a628d047ff2406",
        "LoD/1.11b": "a4ba30fe4414581a89a628d047ff2406",
        "LoD/1.12a": "a4ba30fe4414581a89a628d047ff2406",
        "LoD/1.13c": "a4ba30fe4414581a89a628d047ff2406",
        "LoD/1.13d": "a4ba30fe4414581a89a628d047ff2406"
      }
    },
    "d2net.dll_CRT_InitializeTlsDataFields": {
      "addresses": {
        "LoD/1.07": "0x6FC32E1B",
        "LoD/1.08": "0x6FC32E1B",
        "LoD/1.09": "0x6FC02E1B",
        "LoD/1.09b": "0x6FC02E1B",
        "LoD/1.09d": "0x6FC02E1B",
        "LoD/1.10": "0x6FC02EBB",
        "LoD/1.11": "0x6FBF1C07",
        "LoD/1.11b": "0x6FBF1C07",
        "LoD/1.12a": "0x6FBF1C0F",
        "LoD/1.13c": "0x6FBF1C07",
        "LoD/1.13d": "0x6FBF1C0F"
      },
      "rvas": {
        "LoD/1.07": "0x2E1B",
        "LoD/1.08": "0x2E1B",
        "LoD/1.09": "0x2E1B",
        "LoD/1.09b": "0x2E1B",
        "LoD/1.09d": "0x2E1B",
        "LoD/1.10": "0x2EBB",
        "LoD/1.11": "0x1C07",
        "LoD/1.11b": "0x1C07",
        "LoD/1.12a": "0x1C0F",
        "LoD/1.13c": "0x1C07",
        "LoD/1.13d": "0x1C0F"
      },
      "sizes": {
        "LoD/1.07": 19,
        "LoD/1.08": 19,
        "LoD/1.09": 19,
        "LoD/1.09b": 19,
        "LoD/1.09d": 19,
        "LoD/1.10": 19,
        "LoD/1.11": 19,
        "LoD/1.11b": 19,
        "LoD/1.12a": 19,
        "LoD/1.13c": 19,
        "LoD/1.13d": 19
      },
      "name": "CRT_InitializeTlsDataFields",
      "signature": "void CRT_InitializeTlsDataFields(CRT_TlsData * pTlsData)",
      "calling_convention": "__cdecl",
      "comment": "Initializes fields in a newly allocated CRT Thread Local Storage data structure.\n\nCalled during TLS initialization (CRT_InitializeThreadLocalStorage) and on-demand\nTLS allocation (FUN_6fc32e2e) to set up required fields for exception handling.\n\nAlgorithm:\n1. Store pointer to exception handler table (g_CrtExceptionHandlerTable) at offset +0x50\n2. Set initialization flag to 1 at offset +0x14\n3. Return (caller completes initialization with thread ID and status fields)\n\nParameters:\n  pTlsData - Pointer to 0x74 (116) byte CRT_TlsData structure being initialized\n\nReturns:\n  void - No return value\n\nTLS Data Structure Fields Set:\n  Offset  Size  Description\n  +0x14   4     dwInitialized flag (set to 1)\n  +0x50   4     pExceptionHandlerTable pointer to g_CrtExceptionHandlerTable\n\nNote: Parent caller sets additional fields:\n  +0x00   4     dwThreadId (via GetCurrentThreadId)\n  +0x04   4     dwStatusMarker (set to 0xFFFFFFFF)\n\nClassification: Leaf initialization helper for CRT TLS subsystem",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:a1900c49d3b847e69ff3bf21a94518de",
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1,
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "a1900c49d3b847e69ff3bf21a94518de",
        "LoD/1.08": "a1900c49d3b847e69ff3bf21a94518de",
        "LoD/1.09": "a1900c49d3b847e69ff3bf21a94518de",
        "LoD/1.09b": "a1900c49d3b847e69ff3bf21a94518de",
        "LoD/1.09d": "a1900c49d3b847e69ff3bf21a94518de",
        "LoD/1.10": "a1900c49d3b847e69ff3bf21a94518de",
        "LoD/1.11": "a1900c49d3b847e69ff3bf21a94518de",
        "LoD/1.11b": "a1900c49d3b847e69ff3bf21a94518de",
        "LoD/1.12a": "a1900c49d3b847e69ff3bf21a94518de",
        "LoD/1.13c": "a1900c49d3b847e69ff3bf21a94518de",
        "LoD/1.13d": "a1900c49d3b847e69ff3bf21a94518de"
      }
    },
    "d2net.dll_CRT_GetOrAllocateTlsData": {
      "addresses": {
        "LoD/1.07": "0x6FC32E2E",
        "LoD/1.08": "0x6FC32E2E",
        "LoD/1.09": "0x6FC02E2E",
        "LoD/1.09b": "0x6FC02E2E",
        "LoD/1.09d": "0x6FC02E2E",
        "LoD/1.10": "0x6FC02ECE",
        "LoD/1.11": "0x6FBF1C1A",
        "LoD/1.11b": "0x6FBF1C1A",
        "LoD/1.12a": "0x6FBF1C22",
        "LoD/1.13c": "0x6FBF1C1A",
        "LoD/1.13d": "0x6FBF1C22"
      },
      "rvas": {
        "LoD/1.07": "0x2E2E",
        "LoD/1.08": "0x2E2E",
        "LoD/1.09": "0x2E2E",
        "LoD/1.09b": "0x2E2E",
        "LoD/1.09d": "0x2E2E",
        "LoD/1.10": "0x2ECE",
        "LoD/1.11": "0x1C1A",
        "LoD/1.11b": "0x1C1A",
        "LoD/1.12a": "0x1C22",
        "LoD/1.13c": "0x1C1A",
        "LoD/1.13d": "0x1C22"
      },
      "sizes": {
        "LoD/1.07": 103,
        "LoD/1.08": 103,
        "LoD/1.09": 103,
        "LoD/1.09b": 103,
        "LoD/1.09d": 103,
        "LoD/1.10": 103,
        "LoD/1.11": 113,
        "LoD/1.11b": 113,
        "LoD/1.12a": 113,
        "LoD/1.13c": 113,
        "LoD/1.13d": 113
      },
      "name": "CRT_GetOrAllocateTlsData",
      "signature": "CRT_TlsData * CRT_GetOrAllocateTlsData(void)",
      "calling_convention": "__stdcall",
      "comment": "Gets or allocates the CRT Thread Local Storage (TLS) data structure for the current thread.\n\nClassification: Worker function - Core CRT TLS initialization called on-demand\n\nAlgorithm:\n1. Save current Windows error code via GetLastError() to preserve caller's error state\n2. Retrieve existing TLS data pointer via TlsGetValue(g_dwTlsIndex)\n3. If TLS data exists, skip to step 9\n4. Allocate new 0x74 (116) byte TLS data structure via FUN_6fc33ba6(1, 0x74)\n5. If allocation fails, call __amsg_exit(0x10) - fatal CRT out-of-memory error\n6. Store allocated TLS pointer via TlsSetValue(g_dwTlsIndex, pTlsData)\n7. If TlsSetValue fails, call __amsg_exit(0x10) - fatal error\n8. Initialize TLS data fields:\n   a. Call CRT_InitializeTlsDataFields() to set exception handler table and init flag\n   b. Store current thread ID at offset +0x00\n   c. Store 0xFFFFFFFF status marker at offset +0x04\n9. Restore caller's Windows error code via SetLastError()\n10. Return TLS data pointer\n\nParameters:\n  None\n\nReturns:\n  DWORD* - Pointer to 116-byte TLS data structure for current thread\n           Never returns NULL (fatal exit on allocation failure)\n\nTLS Data Structure Layout:\n  Offset  Size  Field              Description\n  +0x00   4     dwThreadId         Current thread ID\n  +0x04   4     dwStatus           Status marker (0xFFFFFFFF = active)\n  +0x14   4     fInitialized       Initialization flag (1 = initialized)\n  +0x50   4     pExceptionTable    Pointer to g_CrtExceptionHandlerTable\n\nSpecial Cases:\n  - Fatal exit (code 0x10): Called if allocation or TlsSetValue fails\n  - Error preservation: Windows error code saved/restored to prevent TLS\n    operations from corrupting caller's GetLastError() state\n\nCaller Context:\n  Called by FUN_6fc35f50 - likely CRT exception handling or thread init path",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:6dad5d06763847d66c3aa4a89105e250",
      "basic_block_counts": {
        "LoD/1.07": 6,
        "LoD/1.08": 6,
        "LoD/1.09": 6,
        "LoD/1.09b": 6,
        "LoD/1.09d": 6,
        "LoD/1.10": 6,
        "LoD/1.11": 6,
        "LoD/1.11b": 6,
        "LoD/1.12a": 6,
        "LoD/1.13c": 6,
        "LoD/1.13d": 6
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "6dad5d06763847d66c3aa4a89105e250",
        "LoD/1.08": "6dad5d06763847d66c3aa4a89105e250",
        "LoD/1.09": "6dad5d06763847d66c3aa4a89105e250",
        "LoD/1.09b": "6dad5d06763847d66c3aa4a89105e250",
        "LoD/1.09d": "6dad5d06763847d66c3aa4a89105e250",
        "LoD/1.10": "6dad5d06763847d66c3aa4a89105e250",
        "LoD/1.11": "04f1e6f173a4f00f5247db68bf412e5b",
        "LoD/1.11b": "04f1e6f173a4f00f5247db68bf412e5b",
        "LoD/1.12a": "04f1e6f173a4f00f5247db68bf412e5b",
        "LoD/1.13c": "04f1e6f173a4f00f5247db68bf412e5b",
        "LoD/1.13d": "04f1e6f173a4f00f5247db68bf412e5b"
      }
    },
    "d2net.dll_CRT_FreeThreadLocalData": {
      "addresses": {
        "LoD/1.07": "0x6FC32E95",
        "LoD/1.08": "0x6FC32E95",
        "LoD/1.09": "0x6FC02E95",
        "LoD/1.09b": "0x6FC02E95",
        "LoD/1.09d": "0x6FC02E95",
        "LoD/1.10": "0x6FC02F35"
      },
      "rvas": {
        "LoD/1.07": "0x2E95",
        "LoD/1.08": "0x2E95",
        "LoD/1.09": "0x2E95",
        "LoD/1.09b": "0x2E95",
        "LoD/1.09d": "0x2E95",
        "LoD/1.10": "0x2F35"
      },
      "sizes": {
        "LoD/1.07": 160,
        "LoD/1.08": 160,
        "LoD/1.09": 160,
        "LoD/1.09b": 160,
        "LoD/1.09d": 160,
        "LoD/1.10": 160
      },
      "name": "CRT_FreeThreadLocalData",
      "signature": "void CRT_FreeThreadLocalData(CRT_TlsData * pTlsData)",
      "calling_convention": "__cdecl",
      "comment": "CRT_FreeThreadLocalData - Cleans up thread-local storage data on thread detach\n\nAlgorithm:\n1. Check if TLS index is valid (not -1/0xFFFFFFFF)\n2. If pTlsData is NULL, retrieve it via TlsGetValue(g_dwTlsIndex)\n3. If TLS data exists, free dynamically allocated fields:\n   a. Free pField24 (+0x24) if non-NULL\n   b. Free pField28 (+0x28) if non-NULL\n   c. Free pField30 (+0x30) if non-NULL\n   d. Free pField38 (+0x38) if non-NULL\n   e. Free pField40 (+0x40) if non-NULL\n   f. Free pField44 (+0x44) if non-NULL\n   g. Free pField50 (+0x50) if not pointing to global g_CrtExceptionHandlerTable\n4. Free the TLS data structure itself\n5. Clear TLS slot by calling TlsSetValue(index, NULL)\n\nParameters:\n  pTlsData (CRT_TlsData *) - Thread-local data structure to free, or NULL to\n                             retrieve from current thread's TLS slot\n\nReturns:\n  void\n\nCalled By:\n  CRT_DllMainCRTStartup - On DLL_THREAD_DETACH (reason 3) with NULL parameter\n\nSpecial Cases:\n  - If g_dwTlsIndex == -1 (TLS not initialized), returns immediately\n  - pField50 is only freed if it differs from static g_CrtExceptionHandlerTable\n  - When pTlsData is NULL, function retrieves from TLS slot for current thread\n\nStructure Layout (CRT_TlsData):\n  Offset  Size  Field               Description\n  0x00    36    reserved0           Reserved/internal fields\n  0x24    4     pField24            Dynamically allocated buffer 1\n  0x28    4     pField28            Dynamically allocated buffer 2\n  0x2C    4     reserved2C          Reserved\n  0x30    4     pField30            Dynamically allocated buffer 3\n  0x34    4     reserved34          Reserved\n  0x38    4     pField38            Dynamically allocated buffer 4\n  0x3C    4     reserved3C          Reserved\n  0x40    4     pField40            Dynamically allocated buffer 5\n  0x44    4     pField44            Dynamically allocated buffer 6\n  0x48    8     reserved48          Reserved\n  0x50    4     pExceptionHandler   Exception handler table (may be static)",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:17d5e4a2ea8eca0808e1116fecc65876",
      "basic_block_counts": {
        "LoD/1.07": 20,
        "LoD/1.08": 20,
        "LoD/1.09": 20,
        "LoD/1.09b": 20,
        "LoD/1.09d": 20,
        "LoD/1.10": 20
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "17d5e4a2ea8eca0808e1116fecc65876",
        "LoD/1.08": "17d5e4a2ea8eca0808e1116fecc65876",
        "LoD/1.09": "17d5e4a2ea8eca0808e1116fecc65876",
        "LoD/1.09b": "17d5e4a2ea8eca0808e1116fecc65876",
        "LoD/1.09d": "17d5e4a2ea8eca0808e1116fecc65876",
        "LoD/1.10": "17d5e4a2ea8eca0808e1116fecc65876"
      }
    },
    "d2net.dll_CRT_ioinit": {
      "addresses": {
        "LoD/1.07": "0x6FC32F35",
        "LoD/1.08": "0x6FC32F35",
        "LoD/1.09": "0x6FC02F35",
        "LoD/1.09b": "0x6FC02F35",
        "LoD/1.09d": "0x6FC02F35",
        "LoD/1.10": "0x6FC02FD5"
      },
      "rvas": {
        "LoD/1.07": "0x2F35",
        "LoD/1.08": "0x2F35",
        "LoD/1.09": "0x2F35",
        "LoD/1.09b": "0x2F35",
        "LoD/1.09d": "0x2F35",
        "LoD/1.10": "0x2FD5"
      },
      "sizes": {
        "LoD/1.07": 444,
        "LoD/1.08": 444,
        "LoD/1.09": 444,
        "LoD/1.09b": 444,
        "LoD/1.09d": 444,
        "LoD/1.10": 444
      },
      "name": "CRT_ioinit",
      "signature": "void CRT_ioinit(void)",
      "calling_convention": "__stdcall",
      "comment": "CRT_ioinit - Initialize C Runtime I/O Subsystem\n\nInitializes the file handle table used by the C runtime library for stdin, stdout, \nstderr and other file descriptors. Allocates and initializes ioinfo structures in \nblocks of 32 entries (0x480 bytes each), inherits handles from parent process via \nSTARTUPINFO, and sets up standard handles.\n\nAlgorithm:\n1. Allocate initial ioinfo table (0x480 bytes for 32 entries of 0x24 bytes each)\n2. Call __amsg_exit(0x1b) on allocation failure (error 27: not enough memory for lowio)\n3. Set g_dwNHandle to 0x20 (32 initial handles), store table base in g_apIoInfo\n4. Initialize each ioinfo entry: osfhnd = -1, osfile = 0, pipech = 10 (LF), lock = 0\n5. Call GetStartupInfoA to get inherited handle info from parent process\n6. If cbReserved2 > 0 and lpReserved2 != NULL, process inherited handles:\n   - Read handle count from lpReserved2[0], clamp to 0x800 (2048) max\n   - Expand ioinfo table with additional blocks if needed\n   - For each inherited handle with FOPEN flag (0x01) set:\n     - Skip invalid handles (-1) and non-file handles (GetFileType == 0)\n     - Allow FDEV flag (0x08) handles without GetFileType check\n     - Copy OS handle and flags to ioinfo entry using bucket indexing\n7. Initialize stdin (0), stdout (1), stderr (2) if not inherited:\n   - Set osfile = 0x81 (FOPEN | FTEXT)\n   - Get Windows handle via GetStdHandle (STD_INPUT=-10, STD_OUTPUT=-11, STD_ERROR=-12)\n   - Call GetFileType to determine handle type\n   - Set FDEV flag (0x08) for pipe handles (type 3)\n   - Set FEOF flag (0x40) for invalid or char device handles (type 2)\n   - Set FINHERIT flag (0x80) for already-initialized entries\n8. Call SetHandleCount to inform Windows of handle table size\n\nParameters: None\n\nReturns: void\n\nSpecial Cases:\n- Max inherited handles capped at 2048 (0x800)\n- Allocation failure exits via __amsg_exit with code 0x1b\n- Standard handles skipped if already inherited from parent\n\nStructure Layout (ioinfo - 36 bytes per entry):\nOffset  Size  Field       Type    Description\n0x00    4     osfhnd      int     Windows OS file handle (-1 = invalid)\n0x04    1     osfile      byte    File flags (FOPEN, FTEXT, FDEV, etc.)\n0x05    1     pipech      byte    Pipe lookahead char (default 10 = LF)\n0x06    2     reserved    ushort  Padding\n0x08    4     lock        uint    Critical section lock for thread safety\n0x0C    24    padding     byte[]  Alignment padding to 36 byte stride\n\nFlag Bits (osfile field):\n0x01 - FOPEN: File is open\n0x02 - FEOFLAG: End of file reached\n0x08 - FDEV: Device (pipe/console)\n0x10 - FTEXT: Text mode (vs binary)\n0x40 - FEOF: EOF/error condition\n0x80 - FINHERIT: Handle inherited from parent\n\nGlobal Variables:\ng_apIoInfo (0x6fc3b7e0): Array of pointers to ioinfo table blocks\ng_dwNHandle (0x6fc3b8e0): Total number of handle slots allocated\n\nBucket Indexing: entry = g_apIoInfo[index >> 5] + (index & 0x1f) * 0x24\n- index >> 5: Block number (32 entries per block)\n- index & 0x1f: Entry within block (0-31)\n- * 0x24: Multiply by entry size (36 bytes)",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:1352fc0555ea3629db2c9325fd0e6c42",
      "basic_block_counts": {
        "LoD/1.07": 39,
        "LoD/1.08": 39,
        "LoD/1.09": 39,
        "LoD/1.09b": 39,
        "LoD/1.09d": 39,
        "LoD/1.10": 39
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "1352fc0555ea3629db2c9325fd0e6c42",
        "LoD/1.08": "1352fc0555ea3629db2c9325fd0e6c42",
        "LoD/1.09": "1352fc0555ea3629db2c9325fd0e6c42",
        "LoD/1.09b": "1352fc0555ea3629db2c9325fd0e6c42",
        "LoD/1.09d": "1352fc0555ea3629db2c9325fd0e6c42",
        "LoD/1.10": "1352fc0555ea3629db2c9325fd0e6c42"
      }
    },
    "d2net.dll_CRT_CleanupIoInfo": {
      "addresses": {
        "LoD/1.07": "0x6FC330F1",
        "LoD/1.08": "0x6FC330F1",
        "LoD/1.09": "0x6FC030F1",
        "LoD/1.09b": "0x6FC030F1",
        "LoD/1.09d": "0x6FC030F1",
        "LoD/1.10": "0x6FC03191"
      },
      "rvas": {
        "LoD/1.07": "0x30F1",
        "LoD/1.08": "0x30F1",
        "LoD/1.09": "0x30F1",
        "LoD/1.09b": "0x30F1",
        "LoD/1.09d": "0x30F1",
        "LoD/1.10": "0x3191"
      },
      "sizes": {
        "LoD/1.07": 84,
        "LoD/1.08": 84,
        "LoD/1.09": 84,
        "LoD/1.09b": 84,
        "LoD/1.09d": 84,
        "LoD/1.10": 84
      },
      "name": "CRT_CleanupIoInfo",
      "signature": "void CRT_CleanupIoInfo(void)",
      "calling_convention": "__stdcall",
      "comment": "CRT_CleanupIoInfo - Releases CRT I/O information blocks during DLL detach\n\nAlgorithm:\n1. Initialize pointer to first element of g_apIoInfo array (at 0x6fc3b7e0)\n2. Loop through array elements until reaching 0x6fc3b8e0 (64 pointers, 0x100 bytes)\n3. For each non-null pointer:\n   a. Iterate through 32 I/O info entries (stride 0x24 bytes, total 0x480 bytes)\n   b. For each entry with initialized critical section (SpinCount != 0 at offset +8):\n      - Call DeleteCriticalSection on CRITICAL_SECTION at offset +0xC\n   c. Free the I/O info block via CRT_HeapFree\n   d. Set the pointer to NULL\n\nParameters:\n  None\n\nReturns:\n  void\n\nStructure Layout (I/O Info Entry - 0x24 bytes):\n  Offset  Size  Field            Type              Description\n  0x00    4     hFile            HANDLE            File handle (-1 if unused)\n  0x04    1     fFlags           byte              File flags\n  0x05    1     bPipeMode        byte              Pipe mode (10 = default)\n  0x06    2     wPadding         word              Alignment padding\n  0x08    4     dwSpinCount      dword             Critical section spin count (0 = not init)\n  0x0C    24    CriticalSection  CRITICAL_SECTION  Per-file lock structure\n  0x24    -     (next entry)\n\nArray Layout:\n  g_apIoInfo[0..63] at 0x6fc3b7e0-0x6fc3b8DC\n  Each non-null pointer references a 0x480 byte block (32 entries x 0x24)\n  g_dwNHandle tracks total allocated handle count (0x20 per block)\n\nCalled By:\n  CRT_DllMainCRTStartup (DLL_PROCESS_DETACH cleanup)",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:b7026c232ba5b32b3521a3c7482af720",
      "basic_block_counts": {
        "LoD/1.07": 10,
        "LoD/1.08": 10,
        "LoD/1.09": 10,
        "LoD/1.09b": 10,
        "LoD/1.09d": 10,
        "LoD/1.10": 10
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "b7026c232ba5b32b3521a3c7482af720",
        "LoD/1.08": "b7026c232ba5b32b3521a3c7482af720",
        "LoD/1.09": "b7026c232ba5b32b3521a3c7482af720",
        "LoD/1.09b": "b7026c232ba5b32b3521a3c7482af720",
        "LoD/1.09d": "b7026c232ba5b32b3521a3c7482af720",
        "LoD/1.10": "b7026c232ba5b32b3521a3c7482af720"
      }
    },
    "d2net.dll_CRT_SetEnvironmentStrings": {
      "addresses": {
        "LoD/1.07": "0x6FC33145",
        "LoD/1.08": "0x6FC33145",
        "LoD/1.09": "0x6FC03145",
        "LoD/1.09b": "0x6FC03145",
        "LoD/1.09d": "0x6FC03145",
        "LoD/1.10": "0x6FC031E5"
      },
      "rvas": {
        "LoD/1.07": "0x3145",
        "LoD/1.08": "0x3145",
        "LoD/1.09": "0x3145",
        "LoD/1.09b": "0x3145",
        "LoD/1.09d": "0x3145",
        "LoD/1.10": "0x31E5"
      },
      "sizes": {
        "LoD/1.07": 185,
        "LoD/1.08": 185,
        "LoD/1.09": 185,
        "LoD/1.09b": 185,
        "LoD/1.09d": 185,
        "LoD/1.10": 185
      },
      "name": "CRT_SetEnvironmentStrings",
      "signature": "void CRT_SetEnvironmentStrings(void)",
      "calling_convention": "__stdcall",
      "comment": "CRT_SetEnvironmentStrings - Initializes the CRT environment string table\n\nConverts the raw environment block (g_lpszEnvironment) into an array of\nindividually allocated string pointers (g_ppszEnvironmentTable). This is\npart of the C runtime startup sequence called from DllMainCRTStartup.\n\nALGORITHM:\n1. If environment not initialized (g_fEnvironmentInitialized == 0), call FUN_6fc34233 to initialize\n2. Count environment variables in g_lpszEnvironment:\n   - Skip entries starting with '=' (hidden system variables)\n   - Increment count for each valid variable\n   - Advance past null-terminated string\n3. Allocate pointer array: malloc((count + 1) * 4) for count pointers + NULL terminator\n4. Store array pointer in g_ppszEnvironmentTable\n5. If allocation fails, call __amsg_exit(9) - out of memory\n6. For each environment string:\n   a. Get string length with _strlen\n   b. Skip entries starting with '=' \n   c. Allocate (length + 1) bytes for string copy\n   d. If allocation fails, call __amsg_exit(9)\n   e. Copy string using FUN_6fc33cf0 (strcpy-like)\n   f. Store pointer in table and advance\n7. Free original environment block via CRT_HeapFree\n8. Set g_lpszEnvironment to 0 (NULL)\n9. NULL-terminate the pointer array\n10. Set g_fEnvironmentTableReady to 1\n\nPARAMETERS: None (void)\n\nRETURNS: void\n\nSPECIAL CASES:\n- Entries starting with '=' are system variables (like =C:=C:\\) and are skipped\n- Two allocations can fail triggering __amsg_exit(9):\n  1. Pointer array allocation\n  2. Individual string allocation\n\nGLOBALS ACCESSED:\n- g_fEnvironmentInitialized (0x6fc3b8f0) - Read: check if env initialized\n- g_lpszEnvironment (0x6fc3b280) - Read/Write: raw env block, set to 0 after copy\n- g_ppszEnvironmentTable (0x6fc3b258) - Write: stores allocated pointer array\n- g_fEnvironmentTableReady (0x6fc3b8ec) - Write: set to 1 when complete\n\nCALLEES:\n- FUN_6fc34233: Environment initialization\n- _strlen: Get string length\n- _malloc: Allocate memory\n- __amsg_exit(9): Fatal error - out of memory\n- FUN_6fc33cf0: String copy (strcpy variant)\n- CRT_HeapFree: Free memory",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:6e538b3bbbeec8f94bef058bdad701fe",
      "basic_block_counts": {
        "LoD/1.07": 18,
        "LoD/1.08": 18,
        "LoD/1.09": 18,
        "LoD/1.09b": 18,
        "LoD/1.09d": 18,
        "LoD/1.10": 18
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "6e538b3bbbeec8f94bef058bdad701fe",
        "LoD/1.08": "6e538b3bbbeec8f94bef058bdad701fe",
        "LoD/1.09": "6e538b3bbbeec8f94bef058bdad701fe",
        "LoD/1.09b": "6e538b3bbbeec8f94bef058bdad701fe",
        "LoD/1.09d": "6e538b3bbbeec8f94bef058bdad701fe",
        "LoD/1.10": "6e538b3bbbeec8f94bef058bdad701fe"
      }
    },
    "d2net.dll_CRT_InitCommandLineArgs": {
      "addresses": {
        "LoD/1.07": "0x6FC331FE",
        "LoD/1.08": "0x6FC331FE",
        "LoD/1.09": "0x6FC031FE",
        "LoD/1.09b": "0x6FC031FE",
        "LoD/1.09d": "0x6FC031FE",
        "LoD/1.10": "0x6FC0329E"
      },
      "rvas": {
        "LoD/1.07": "0x31FE",
        "LoD/1.08": "0x31FE",
        "LoD/1.09": "0x31FE",
        "LoD/1.09b": "0x31FE",
        "LoD/1.09d": "0x31FE",
        "LoD/1.10": "0x329E"
      },
      "sizes": {
        "LoD/1.07": 153,
        "LoD/1.08": 153,
        "LoD/1.09": 153,
        "LoD/1.09b": 153,
        "LoD/1.09d": 153,
        "LoD/1.10": 153
      },
      "name": "CRT_InitCommandLineArgs",
      "signature": "void CRT_InitCommandLineArgs(void)",
      "calling_convention": "__stdcall",
      "comment": "CRT_InitCommandLineArgs - Initialize command line argument parsing for CRT startup\n\nClassification: Initialization function - sets up argc/argv globals for the runtime\n\nAlgorithm:\n1. Check if environment is initialized (g_fEnvironmentInitialized), call FUN_6fc34233 if not\n2. Get module filename via GetModuleFileNameA into g_szModuleFileName buffer (MAX_PATH=260 bytes)\n3. Store module filename pointer in g_pszModulePath\n4. Select source string: use g_lpszCmdLine if non-empty, else use module filename\n5. First pass: call FUN_6fc33297 with NULL buffers to calculate required sizes (nArgCount, nCharCount)\n6. Allocate memory: malloc(nCharCount + nArgCount * 4) for argv array + string storage\n7. If allocation fails, call __amsg_exit(8) for out-of-memory abort\n8. Second pass: call FUN_6fc33297 to populate argv array and copy argument strings\n9. Store argv pointer array base in g_ppszArgv\n10. Store argument count minus 1 in g_nArgc (excludes program name for shell convention)\n\nReturns: void\n\nSpecial Cases:\n- Empty command line: uses module filename as program name only\n- Memory allocation failure: terminates via __amsg_exit(8)\n\nMemory Model:\n- g_szModuleFileName: 260-byte static buffer at 0x6fc3b2f0\n- g_ppszArgv: heap-allocated pointer array, each element points into contiguous string storage\n- String storage follows argv array in same allocation block\n\nGlobals Modified:\n- g_pszModulePath (0x6fc3b268): pointer to module filename buffer\n- g_ppszArgv (0x6fc3b250): pointer to argv array\n- g_nArgc (0x6fc3b24c): argument count minus 1\n\nCalled By: CRT_DllMainCRTStartup during DLL initialization",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:78c0be793b204c577b78460711bf70fb",
      "basic_block_counts": {
        "LoD/1.07": 7,
        "LoD/1.08": 7,
        "LoD/1.09": 7,
        "LoD/1.09b": 7,
        "LoD/1.09d": 7,
        "LoD/1.10": 7
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "78c0be793b204c577b78460711bf70fb",
        "LoD/1.08": "78c0be793b204c577b78460711bf70fb",
        "LoD/1.09": "78c0be793b204c577b78460711bf70fb",
        "LoD/1.09b": "78c0be793b204c577b78460711bf70fb",
        "LoD/1.09d": "78c0be793b204c577b78460711bf70fb",
        "LoD/1.10": "78c0be793b204c577b78460711bf70fb"
      }
    },
    "d2net.dll_CRT_ParseCommandLine": {
      "addresses": {
        "LoD/1.07": "0x6FC33297",
        "LoD/1.08": "0x6FC33297",
        "LoD/1.09": "0x6FC03297",
        "LoD/1.09b": "0x6FC03297",
        "LoD/1.09d": "0x6FC03297",
        "LoD/1.10": "0x6FC03337"
      },
      "rvas": {
        "LoD/1.07": "0x3297",
        "LoD/1.08": "0x3297",
        "LoD/1.09": "0x3297",
        "LoD/1.09b": "0x3297",
        "LoD/1.09d": "0x3297",
        "LoD/1.10": "0x3337"
      },
      "sizes": {
        "LoD/1.07": 436,
        "LoD/1.08": 436,
        "LoD/1.09": 436,
        "LoD/1.09b": 436,
        "LoD/1.09d": 436,
        "LoD/1.10": 436
      },
      "name": "CRT_ParseCommandLine",
      "signature": "void CRT_ParseCommandLine(byte * pbCmdLine, char * * ppszArgv, byte * pbArgBuffer, int * pnArgCount, int * pnCharCount)",
      "calling_convention": "__cdecl",
      "comment": "CRT_ParseCommandLine - Parses command line string into argc/argv format\n\nCLASSIFICATION: Worker function - CRT command-line argument parser\n\nALGORITHM:\n1. Initialize pnCharCount=0, pnArgCount=1 (program name counts as arg 0)\n2. Store first argv pointer (pbArgBuffer) if ppszArgv provided\n3. Parse program name (argv[0]):\n   a. If starts with quote (0x22): copy until closing quote or NUL, skip MBCS lead bytes\n   b. Else: copy until space (0x20), tab (0x09), or NUL, handling MBCS lead bytes\n4. Null-terminate argv[0] in buffer\n5. Parse remaining arguments in outer while loop:\n   a. Skip whitespace (space, tab)\n   b. If at NUL, exit loop\n   c. Store argv[n] pointer, increment pnArgCount\n   d. Inner while loop processes argument characters:\n      - Count consecutive backslashes\n      - If quote found: backslash pairs become single backslash (count >> 1)\n        - Odd backslashes + quote = literal quote\n        - Even backslashes + quote = toggle fInQuotedArg mode\n      - Copy backslash characters to output\n      - Copy regular characters (with MBCS lead byte handling)\n      - Exit on NUL or unquoted whitespace\n   e. Null-terminate argument in buffer\n6. Null-terminate argv array if ppszArgv provided\n7. Increment pnArgCount for final NULL entry\n\nPARAMETERS:\n  pbCmdLine    - Input command line string to parse\n  ppszArgv     - Output argv array (NULL on first pass to count only)\n  pbArgBuffer  - Output buffer for argument strings (NULL on first pass)\n  pnArgCount   - Output: number of arguments (argc + 1 for NULL terminator)\n  pnCharCount  - Output: total characters needed including NUL terminators\n\nRETURNS: void (results via output pointers)\n\nSPECIAL CASES:\n  - First call with ppszArgv=NULL, pbArgBuffer=NULL counts space needed\n  - Second call with allocated buffers fills argv array\n  - MBCS support: lead byte check via g_abCharTypeTable[char+1] & 0x04\n  - Backslash escape rules follow Windows command line parsing conventions\n  - Empty command line uses module filename as argv[0]\n\nMAGIC NUMBERS:\n  0x22 - Double quote character\n  0x5c - Backslash character\n  0x20 - Space character\n  0x09 - Tab character\n  0x04 - MBCS lead byte flag in character type table",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:50cd6b6fd69b78c0380659763fce7ea0",
      "basic_block_counts": {
        "LoD/1.07": 71,
        "LoD/1.08": 71,
        "LoD/1.09": 71,
        "LoD/1.09b": 71,
        "LoD/1.09d": 71,
        "LoD/1.10": 71
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "50cd6b6fd69b78c0380659763fce7ea0",
        "LoD/1.08": "50cd6b6fd69b78c0380659763fce7ea0",
        "LoD/1.09": "50cd6b6fd69b78c0380659763fce7ea0",
        "LoD/1.09b": "50cd6b6fd69b78c0380659763fce7ea0",
        "LoD/1.09d": "50cd6b6fd69b78c0380659763fce7ea0",
        "LoD/1.10": "50cd6b6fd69b78c0380659763fce7ea0"
      }
    },
    "d2net.dll_CRT_GetEnvironmentStringsA": {
      "addresses": {
        "LoD/1.07": "0x6FC3344B",
        "LoD/1.08": "0x6FC3344B",
        "LoD/1.09": "0x6FC0344B",
        "LoD/1.09b": "0x6FC0344B",
        "LoD/1.09d": "0x6FC0344B",
        "LoD/1.10": "0x6FC034EB"
      },
      "rvas": {
        "LoD/1.07": "0x344B",
        "LoD/1.08": "0x344B",
        "LoD/1.09": "0x344B",
        "LoD/1.09b": "0x344B",
        "LoD/1.09d": "0x344B",
        "LoD/1.10": "0x34EB"
      },
      "sizes": {
        "LoD/1.07": 306,
        "LoD/1.08": 306,
        "LoD/1.09": 306,
        "LoD/1.09b": 306,
        "LoD/1.09d": 306,
        "LoD/1.10": 306
      },
      "name": "CRT_GetEnvironmentStringsA",
      "signature": "char * CRT_GetEnvironmentStringsA(void)",
      "calling_convention": "__stdcall",
      "comment": "CRT helper to retrieve environment strings as ANSI (char *).\n\nParameters:\n  None - This function takes no parameters.\n\nAlgorithm:\n1. Read g_dwEnvStringsMode to determine retrieval strategy (0=auto, 1=wide, 2=ANSI)\n2. Mode 0 (auto-detect): Try GetEnvironmentStringsW first, set mode=1 if success\n   If wide fails, try GetEnvironmentStrings (ANSI), set mode=2 if success\n3. Mode 1 (wide path):\n   a. Call GetEnvironmentStringsW to get wide environment block\n   b. Scan block for double-null terminator (each string null-terminated, block ends with extra null)\n   c. Calculate character count = (end - start) / 2 + 1\n   d. Call WideCharToMultiByte with NULL output to get required buffer size\n   e. Allocate buffer via _malloc\n   f. Call WideCharToMultiByte to convert wide strings to ANSI\n   g. Free wide environment block via FreeEnvironmentStringsW\n   h. On conversion failure, free allocated buffer and return NULL\n4. Mode 2 (ANSI path):\n   a. Call GetEnvironmentStrings to get ANSI environment block\n   b. Scan block for double-null terminator\n   c. Calculate byte count = (end - start) + 1\n   d. Allocate buffer via _malloc\n   e. Copy environment block via FUN_6fc34250 (memcpy wrapper)\n   f. Free original environment block via FreeEnvironmentStringsA\n5. Return allocated ANSI environment block or NULL on failure\n\nReturns:\n  char * - Newly allocated ANSI environment block (caller must free)\n           NULL on failure (allocation failed or no environment strings)\n\nSpecial Cases:\n  - Environment block format: VAR1=VALUE1\\0VAR2=VALUE2\\0\\0 (double-null terminated)\n  - Mode flag persists across calls to optimize subsequent retrieval\n  - Wide-to-ANSI conversion uses system default code page (CP_ACP)\n\nGlobals Referenced:\n  g_dwEnvStringsMode (0x6fc3b3f4) - Environment retrieval mode (0=auto, 1=wide, 2=ANSI)\n  g_pfnGetEnvironmentStringsW (0x6fc37124) - GetEnvironmentStringsW function pointer\n  g_pfnGetEnvironmentStrings (0x6fc370cc) - GetEnvironmentStrings function pointer  \n  g_pfnWideCharToMultiByte (0x6fc37120) - WideCharToMultiByte function pointer\n  g_pfnFreeEnvironmentStringsW (0x6fc3711c) - FreeEnvironmentStringsW function pointer\n  g_pfnFreeEnvironmentStringsA (0x6fc37118) - FreeEnvironmentStringsA function pointer",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:ee22dcb18299b51eb994a57f32a5df1d",
      "basic_block_counts": {
        "LoD/1.07": 29,
        "LoD/1.08": 29,
        "LoD/1.09": 29,
        "LoD/1.09b": 29,
        "LoD/1.09d": 29,
        "LoD/1.10": 29
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "ee22dcb18299b51eb994a57f32a5df1d",
        "LoD/1.08": "ee22dcb18299b51eb994a57f32a5df1d",
        "LoD/1.09": "ee22dcb18299b51eb994a57f32a5df1d",
        "LoD/1.09b": "ee22dcb18299b51eb994a57f32a5df1d",
        "LoD/1.09d": "ee22dcb18299b51eb994a57f32a5df1d",
        "LoD/1.10": "ee22dcb18299b51eb994a57f32a5df1d"
      }
    },
    "d2net.dll_GetCurrentModuleLinkerVersion": {
      "addresses": {
        "LoD/1.07": "0x6FC3357D",
        "LoD/1.08": "0x6FC3357D",
        "LoD/1.09": "0x6FC0357D",
        "LoD/1.09b": "0x6FC0357D",
        "LoD/1.09d": "0x6FC0357D",
        "LoD/1.10": "0x6FC0361D"
      },
      "rvas": {
        "LoD/1.07": "0x357D",
        "LoD/1.08": "0x357D",
        "LoD/1.09": "0x357D",
        "LoD/1.09b": "0x357D",
        "LoD/1.09d": "0x357D",
        "LoD/1.10": "0x361D"
      },
      "sizes": {
        "LoD/1.07": 45,
        "LoD/1.08": 45,
        "LoD/1.09": 45,
        "LoD/1.09b": 45,
        "LoD/1.09d": 45,
        "LoD/1.10": 45
      },
      "name": "GetCurrentModuleLinkerVersion",
      "signature": "void GetCurrentModuleLinkerVersion(ushort * pwLinkerVersion)",
      "calling_convention": "__cdecl",
      "comment": "Retrieves the linker version from the current module's PE header.\n\nAlgorithm:\n1. Initialize output to 0\n2. Call GetModuleHandleA(NULL) to get current module base address\n3. Verify MZ signature (0x5A4D) at DOS header offset 0\n4. Get PE header offset from e_lfanew field (DOS header offset 0x3C)\n5. If PE header offset is valid (non-zero):\n   a. Read major linker version from PE Optional Header offset 0x1A\n   b. Read minor linker version from PE Optional Header offset 0x1B\n   c. Store as little-endian ushort (major in low byte, minor in high byte)\n\nParameters:\n  pwLinkerVersion - OUT: Pointer to receive linker version as ushort\n                    Format: Low byte = major version, High byte = minor version\n\nReturns:\n  void - Result stored in pwLinkerVersion (0 if PE header invalid)\n\nSpecial Cases:\n  - Returns 0 if MZ signature missing (not a valid PE/DOS executable)\n  - Returns 0 if e_lfanew is NULL (no PE header)\n\nStructure Layout (PE Header offsets from module base):\n  Offset   Field                  Description\n  0x00     e_magic                DOS signature \"MZ\" (0x5A4D)\n  0x3C     e_lfanew               Offset to PE header\n  PE+0x1A  MajorLinkerVersion     Linker major version (byte)\n  PE+0x1B  MinorLinkerVersion     Linker minor version (byte)\n\nMagic Numbers:\n  0x5A4D - \"MZ\" DOS executable signature\n  0x3C   - Offset to e_lfanew in DOS header\n  0x1A   - Offset to MajorLinkerVersion in PE Optional Header\n  0x1B   - Offset to MinorLinkerVersion in PE Optional Header",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:d8be7433da8984a6d08ceacc3367b90b",
      "basic_block_counts": {
        "LoD/1.07": 4,
        "LoD/1.08": 4,
        "LoD/1.09": 4,
        "LoD/1.09b": 4,
        "LoD/1.09d": 4,
        "LoD/1.10": 4
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "d8be7433da8984a6d08ceacc3367b90b",
        "LoD/1.08": "d8be7433da8984a6d08ceacc3367b90b",
        "LoD/1.09": "d8be7433da8984a6d08ceacc3367b90b",
        "LoD/1.09b": "d8be7433da8984a6d08ceacc3367b90b",
        "LoD/1.09d": "d8be7433da8984a6d08ceacc3367b90b",
        "LoD/1.10": "d8be7433da8984a6d08ceacc3367b90b"
      }
    },
    "d2net.dll_SelectHeapType": {
      "addresses": {
        "LoD/1.07": "0x6FC335AA",
        "LoD/1.08": "0x6FC335AA",
        "LoD/1.09": "0x6FC035AA",
        "LoD/1.09b": "0x6FC035AA",
        "LoD/1.09d": "0x6FC035AA",
        "LoD/1.10": "0x6FC0364A"
      },
      "rvas": {
        "LoD/1.07": "0x35AA",
        "LoD/1.08": "0x35AA",
        "LoD/1.09": "0x35AA",
        "LoD/1.09b": "0x35AA",
        "LoD/1.09d": "0x35AA",
        "LoD/1.10": "0x364A"
      },
      "sizes": {
        "LoD/1.07": 328,
        "LoD/1.08": 328,
        "LoD/1.09": 328,
        "LoD/1.09b": 328,
        "LoD/1.09d": 328,
        "LoD/1.10": 328
      },
      "name": "SelectHeapType",
      "signature": "int SelectHeapType(void)",
      "calling_convention": "__stdcall",
      "comment": "Selects the CRT heap implementation type based on OS version and environment.\n\nAlgorithm:\n1. Reserve stack space and call FUN_6fc34940 for stack initialization\n2. Initialize OSVERSIONINFOEXA structure (dwOsVersionInfoSize = 0x94)\n3. Call GetVersionExA to retrieve Windows version information\n4. Check if Windows Server 2003+ (VER_PLATFORM_WIN32_NT == 2, dwMajorVersion >= 5)\n   - If true, return 1 (use system default heap)\n5. Otherwise, read __MSVCRT_HEAP_SELECT environment variable\n6. Convert environment value to uppercase (chars 'a'-'z' to 'A'-'Z')\n7. Check if value starts with \"__GLOBAL_HEAP_SELECTED\"\n   - If match, use the env value buffer as heap selection string\n8. Otherwise, get module filename and convert to uppercase\n9. Search for module name within the env variable value\n10. If found, find comma separator after module name\n11. Parse numeric value after comma (semicolon terminates)\n12. Call FUN_6fc34585 to convert string to heap type (1, 2, or 3)\n13. If environment parsing fails, get PE linker version\n14. Return 3 if linker major version >= 6, else return 2\n\nParameters:\n  None\n\nReturns:\n  int - Heap type selector:\n    1 = System heap (Windows Server 2003+)\n    2 = Old MSVCRT small-block heap (linker < 6)\n    3 = New MSVCRT heap (linker >= 6 or env override)\n\nSpecial Cases:\n  - GetVersionExA failure: falls through to env var check\n  - Empty env variable: uses linker version fallback\n  - No module match in env: uses linker version fallback\n\nStructure Layout (OSVERSIONINFOEXA at EBP-0x9C):\n  Offset   Size   Field               Description\n  0x00     4      dwOsVersionInfoSize Size of structure (0x94)\n  0x04     4      dwMajorVersion      Major OS version\n  0x08     4      dwMinorVersion      Minor OS version\n  0x0C     4      dwBuildNumber       Build number\n  0x10     4      dwPlatformId        Platform type (2=NT)\n\nMagic Numbers:\n  0x94   - sizeof(OSVERSIONINFOEXA)\n  0x1090 - Max env variable buffer size (4240 bytes)\n  0x104  - MAX_PATH (260 characters)\n  0x16   - Length of \"__GLOBAL_HEAP_SELECTED\" string\n  0x2C   - ASCII comma delimiter\n  0x3B   - ASCII semicolon terminator\n  0x0A   - Radix 10 for strtol parsing",
      "name_source": "LoD/1.07",
      "method": "STR",
      "index": "STR:8315eedfd35b963ffd4ae4799f93ce60",
      "strings": {
        "LoD/1.07": [
          "\"__MSVCRT_HEAP_SELECT\""
        ],
        "LoD/1.08": [
          "\"__MSVCRT_HEAP_SELECT\""
        ],
        "LoD/1.09": [
          "\"__MSVCRT_HEAP_SELECT\""
        ],
        "LoD/1.09b": [
          "\"__MSVCRT_HEAP_SELECT\""
        ],
        "LoD/1.09d": [
          "\"__MSVCRT_HEAP_SELECT\""
        ],
        "LoD/1.10": [
          "\"__MSVCRT_HEAP_SELECT\""
        ]
      },
      "basic_block_counts": {
        "LoD/1.07": 30,
        "LoD/1.08": 30,
        "LoD/1.09": 30,
        "LoD/1.09b": 30,
        "LoD/1.09d": 30,
        "LoD/1.10": 30
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "454368f80bb3f288f15a4980f2c2bd46",
        "LoD/1.08": "454368f80bb3f288f15a4980f2c2bd46",
        "LoD/1.09": "454368f80bb3f288f15a4980f2c2bd46",
        "LoD/1.09b": "454368f80bb3f288f15a4980f2c2bd46",
        "LoD/1.09d": "454368f80bb3f288f15a4980f2c2bd46",
        "LoD/1.10": "454368f80bb3f288f15a4980f2c2bd46"
      }
    },
    "d2net.dll_CRT_InitializeHeap": {
      "addresses": {
        "LoD/1.07": "0x6FC336F2",
        "LoD/1.08": "0x6FC336F2",
        "LoD/1.09": "0x6FC036F2",
        "LoD/1.09b": "0x6FC036F2",
        "LoD/1.09d": "0x6FC036F2",
        "LoD/1.10": "0x6FC03792"
      },
      "rvas": {
        "LoD/1.07": "0x36F2",
        "LoD/1.08": "0x36F2",
        "LoD/1.09": "0x36F2",
        "LoD/1.09b": "0x36F2",
        "LoD/1.09d": "0x36F2",
        "LoD/1.10": "0x3792"
      },
      "sizes": {
        "LoD/1.07": 93,
        "LoD/1.08": 93,
        "LoD/1.09": 93,
        "LoD/1.09b": 93,
        "LoD/1.09d": 93,
        "LoD/1.10": 93
      },
      "name": "CRT_InitializeHeap",
      "signature": "int CRT_InitializeHeap(int nReason)",
      "calling_convention": "__cdecl",
      "comment": "CRT_InitializeHeap - Initialize CRT heap for DLL\n\nInitializes the C runtime heap during DLL startup. Creates a Windows heap\nand selects an appropriate heap management strategy based on OS version\nand environment configuration.\n\nAlgorithm:\n1. Create Windows heap via HeapCreate with serialization based on nReason\n   - If nReason==0 (DLL_PROCESS_ATTACH), enable heap serialization\n   - Otherwise disable serialization for single-threaded operation\n2. Store heap handle in g_hCrtHeap global\n3. If heap creation fails, return 0 (failure)\n4. Call FUN_6fc335aa to determine heap type based on OS version/env vars\n   - Returns 1: Use system heap (Windows 2000+ with platform version 5+)\n   - Returns 2: Use virtual memory heap (FUN_6fc351c0)\n   - Returns 3: Use small block heap (FUN_6fc3496f)\n5. Store heap type in g_dwHeapType global\n6. If type==3, initialize small block heap with 0x3f8 (1016) byte threshold\n7. If type==2, initialize virtual memory based heap\n8. If type==1, skip custom heap initialization (use system heap)\n9. If custom heap init succeeds, return 1\n10. If custom heap init fails, destroy the created heap and return 0\n\nParameters:\n  nReason (int) - DLL attach reason from DllMain\n    - 0 (DLL_PROCESS_ATTACH): Create serialized heap for multi-threaded use\n    - Non-zero: Create non-serialized heap\n\nReturns:\n  1 - Success: Heap initialized\n  0 - Failure: Heap creation or initialization failed\n\nGlobals Modified:\n  g_hCrtHeap (0x6fc3b7c8) - Windows heap handle for CRT allocations\n  g_dwHeapType (0x6fc3b7cc) - Heap type selector (1=system, 2=virtual, 3=small block)\n\nHeap Type Selection:\n  Type 1: System heap - Used on Windows 2000+ (platform version 5.x+)\n  Type 2: Virtual memory heap - Custom allocator using VirtualAlloc\n  Type 3: Small block heap - Optimized for small allocations up to 1016 bytes\n\nCalled By: CRT_DllMainCRTStartup during DLL initialization",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:15aa81e73603ef0f9aff675af9b3ec8c",
      "basic_block_counts": {
        "LoD/1.07": 9,
        "LoD/1.08": 9,
        "LoD/1.09": 9,
        "LoD/1.09b": 9,
        "LoD/1.09d": 9,
        "LoD/1.10": 9
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "15aa81e73603ef0f9aff675af9b3ec8c",
        "LoD/1.08": "15aa81e73603ef0f9aff675af9b3ec8c",
        "LoD/1.09": "15aa81e73603ef0f9aff675af9b3ec8c",
        "LoD/1.09b": "15aa81e73603ef0f9aff675af9b3ec8c",
        "LoD/1.09d": "15aa81e73603ef0f9aff675af9b3ec8c",
        "LoD/1.10": "15aa81e73603ef0f9aff675af9b3ec8c"
      }
    },
    "d2net.dll_CRT_DestroyHeap": {
      "addresses": {
        "LoD/1.07": "0x6FC3374F",
        "LoD/1.08": "0x6FC3374F",
        "LoD/1.09": "0x6FC0374F",
        "LoD/1.09b": "0x6FC0374F",
        "LoD/1.09d": "0x6FC0374F",
        "LoD/1.10": "0x6FC037EF"
      },
      "rvas": {
        "LoD/1.07": "0x374F",
        "LoD/1.08": "0x374F",
        "LoD/1.09": "0x374F",
        "LoD/1.09b": "0x374F",
        "LoD/1.09d": "0x374F",
        "LoD/1.10": "0x37EF"
      },
      "sizes": {
        "LoD/1.07": 168,
        "LoD/1.08": 168,
        "LoD/1.09": 168,
        "LoD/1.09b": 168,
        "LoD/1.09d": 168,
        "LoD/1.10": 168
      },
      "name": "CRT_DestroyHeap",
      "signature": "void CRT_DestroyHeap(void)",
      "calling_convention": "__stdcall",
      "comment": "CRT_DestroyHeap - Destroy CRT heap and free all allocated memory regions\n\nCalled during DLL_PROCESS_DETACH to tear down all heap resources allocated\nby CRT_InitializeHeap. Handles two heap allocation modes:\n  Mode 2 (Linked List): Circular linked list of heap nodes at g_HeapNodeListHead\n  Mode 3 (Region Array): Array of memory regions stored at g_pRegionArray\n\nAlgorithm:\n1. Check g_dwHeapType for heap allocation mode\n2. If mode 3 (region array):\n   a. Initialize loop counter to 0\n   b. If g_nRegionCount > 0, iterate through region array\n   c. For each region entry (stride 0x14 = 20 bytes):\n      - VirtualFree with MEM_DECOMMIT (0x4000) to decommit 0x100000 bytes\n      - VirtualFree with MEM_RELEASE (0x8000) to release virtual memory\n      - HeapFree the associated heap allocation at entry[1]\n   d. HeapFree the region array itself\n3. If mode 2 (linked list):\n   a. Start at g_HeapNodeListHead (circular doubly-linked list)\n   b. For each node, if node[4] (virtual memory ptr) is non-NULL:\n      - VirtualFree with MEM_RELEASE (0x8000) to release\n   c. Traverse via node[0] (next pointer) until back at list head\n4. Call HeapDestroy to destroy the primary CRT heap\n\nParameters:\n  None (void)\n\nReturns:\n  void\n\nGlobals Read:\n  g_dwHeapType (0x6fc3b7cc) - Heap allocation mode (2=list, 3=array)\n  g_nRegionCount (0x6fc3b5a0) - Number of allocated regions\n  g_pRegionArray (0x6fc3b5a4) - Pointer to region descriptor array\n  g_hCrtHeap (0x6fc3b7c8) - Handle to primary CRT heap\n  g_HeapNodeListHead (0x6fc38950) - Head of circular heap node list\n\nMagic Numbers:\n  0x100000 - 1MB region size to decommit\n  0x4000 - MEM_DECOMMIT flag for VirtualFree\n  0x8000 - MEM_RELEASE flag for VirtualFree\n  0x14 (20) - Stride of region array entries\n  0xc (12) - Offset to virtual memory pointer in region entry\n\nStructure Layout (Region Array Entry, 20 bytes):\n  Offset  Size  Field        Type       Description\n  0x00    4     pNext        void*      Next region or reserved\n  0x04    4     pPrev        void*      Previous region or reserved\n  0x08    4     dwFlags      uint       Region flags\n  0x0c    4     pVirtualMem  void*      Virtual memory base address\n  0x10    4     pHeapAlloc   void*      Associated heap allocation\n\nLinked List Node (g_HeapNodeListHead):\n  Offset  Size  Field        Type       Description\n  0x00    4     pNext        void**     Next node pointer\n  0x04    4     pPrev        void**     Previous node pointer\n  0x08    4     field_08     uint       Reserved\n  0x0c    4     field_0c     uint       Reserved\n  0x10    4     pVirtualMem  void*      Virtual memory to release",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:c2ccec13492440089beaf10a53536424",
      "basic_block_counts": {
        "LoD/1.07": 11,
        "LoD/1.08": 11,
        "LoD/1.09": 11,
        "LoD/1.09b": 11,
        "LoD/1.09d": 11,
        "LoD/1.10": 11
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "c2ccec13492440089beaf10a53536424",
        "LoD/1.08": "c2ccec13492440089beaf10a53536424",
        "LoD/1.09": "c2ccec13492440089beaf10a53536424",
        "LoD/1.09b": "c2ccec13492440089beaf10a53536424",
        "LoD/1.09d": "c2ccec13492440089beaf10a53536424",
        "LoD/1.10": "c2ccec13492440089beaf10a53536424"
      }
    },
    "d2net.dll_CrtExitCallbackAndTerminate": {
      "addresses": {
        "LoD/1.07": "0x6FC337F7",
        "LoD/1.08": "0x6FC337F7",
        "LoD/1.09": "0x6FC037F7",
        "LoD/1.09b": "0x6FC037F7",
        "LoD/1.09d": "0x6FC037F7",
        "LoD/1.10": "0x6FC03897",
        "LoD/1.11": "0x6FBF2A83",
        "LoD/1.11b": "0x6FBF2A83",
        "LoD/1.12a": "0x6FBF2AA4",
        "LoD/1.13c": "0x6FBF2AA4",
        "LoD/1.13d": "0x6FBF2A83"
      },
      "rvas": {
        "LoD/1.07": "0x37F7",
        "LoD/1.08": "0x37F7",
        "LoD/1.09": "0x37F7",
        "LoD/1.09b": "0x37F7",
        "LoD/1.09d": "0x37F7",
        "LoD/1.10": "0x3897",
        "LoD/1.11": "0x2A83",
        "LoD/1.11b": "0x2A83",
        "LoD/1.12a": "0x2AA4",
        "LoD/1.13c": "0x2AA4",
        "LoD/1.13d": "0x2A83"
      },
      "sizes": {
        "LoD/1.07": 57,
        "LoD/1.08": 57,
        "LoD/1.09": 57,
        "LoD/1.09b": 57,
        "LoD/1.09d": 57,
        "LoD/1.10": 57,
        "LoD/1.11": 57,
        "LoD/1.11b": 57,
        "LoD/1.12a": 57,
        "LoD/1.13c": 57,
        "LoD/1.13d": 57
      },
      "name": "CrtExitCallbackAndTerminate",
      "signature": "void CrtExitCallbackAndTerminate(void)",
      "calling_convention": "__stdcall",
      "comment": "CRT exit callback and termination handler.\n\nCalled from __amsg_exit to perform cleanup before program termination.\nOnly executes in console/server mode (g_dwServerTimeout == 1 or\ng_dwServerTimeout == 0 with g_dwServerFlags == 1).\n\nAlgorithm:\n1. Check if server timeout flag is 1 (server mode) - proceed to step 4\n2. If server timeout is 0, check server flags == 1 (console mode)\n3. If neither condition met, return without action\n4. Call FUN_6fc33830(0xfc) to write pre-termination marker\n5. Check if exit callback function pointer is registered\n6. If callback exists, invoke g_pfnCrtExitCallback()\n7. Call FUN_6fc33830(0xff) to write termination marker\n\nParameters:\n  None\n\nReturns:\n  void\n\nGlobals:\n  g_dwServerTimeout (0x6fc3b288) - Server/console mode flag (1=server, 0=check flags)\n  g_dwServerFlags (0x6fc3b28c) - Console output flag (1=console mode)\n  g_pfnCrtExitCallback (0x6fc3b3f8) - Optional exit callback function pointer\n\nMagic Numbers:\n  0xfc - Pre-termination message code for FUN_6fc33830\n  0xff - Final termination message code for FUN_6fc33830\n\nClassification: Cleanup/Destructor - called during program exit sequence\nCallers: __amsg_exit (1 caller)",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:9765460a30498931557fab10cfc0be00",
      "basic_block_counts": {
        "LoD/1.07": 7,
        "LoD/1.08": 7,
        "LoD/1.09": 7,
        "LoD/1.09b": 7,
        "LoD/1.09d": 7,
        "LoD/1.10": 7,
        "LoD/1.11": 7,
        "LoD/1.11b": 7,
        "LoD/1.12a": 7,
        "LoD/1.13c": 7,
        "LoD/1.13d": 7
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "9765460a30498931557fab10cfc0be00",
        "LoD/1.08": "9765460a30498931557fab10cfc0be00",
        "LoD/1.09": "9765460a30498931557fab10cfc0be00",
        "LoD/1.09b": "9765460a30498931557fab10cfc0be00",
        "LoD/1.09d": "9765460a30498931557fab10cfc0be00",
        "LoD/1.10": "9765460a30498931557fab10cfc0be00",
        "LoD/1.11": "e0686acda8daa87f807e8c4bf4d7ccee",
        "LoD/1.11b": "e0686acda8daa87f807e8c4bf4d7ccee",
        "LoD/1.12a": "e0686acda8daa87f807e8c4bf4d7ccee",
        "LoD/1.13c": "e0686acda8daa87f807e8c4bf4d7ccee",
        "LoD/1.13d": "e0686acda8daa87f807e8c4bf4d7ccee"
      }
    },
    "d2net.dll_CrtDisplayRuntimeError": {
      "addresses": {
        "LoD/1.07": "0x6FC33830",
        "LoD/1.08": "0x6FC33830",
        "LoD/1.09": "0x6FC03830",
        "LoD/1.09b": "0x6FC03830",
        "LoD/1.09d": "0x6FC03830",
        "LoD/1.10": "0x6FC038D0",
        "LoD/1.11": "0x6FBF290C",
        "LoD/1.11b": "0x6FBF290C",
        "LoD/1.12a": "0x6FBF292C",
        "LoD/1.13c": "0x6FBF292C",
        "LoD/1.13d": "0x6FBF290C"
      },
      "rvas": {
        "LoD/1.07": "0x3830",
        "LoD/1.08": "0x3830",
        "LoD/1.09": "0x3830",
        "LoD/1.09b": "0x3830",
        "LoD/1.09d": "0x3830",
        "LoD/1.10": "0x38D0",
        "LoD/1.11": "0x290C",
        "LoD/1.11b": "0x290C",
        "LoD/1.12a": "0x292C",
        "LoD/1.13c": "0x292C",
        "LoD/1.13d": "0x290C"
      },
      "sizes": {
        "LoD/1.07": 339,
        "LoD/1.08": 339,
        "LoD/1.09": 339,
        "LoD/1.09b": 339,
        "LoD/1.09d": 339,
        "LoD/1.10": 339,
        "LoD/1.11": 375,
        "LoD/1.11b": 375,
        "LoD/1.12a": 376,
        "LoD/1.13c": 376,
        "LoD/1.13d": 375
      },
      "name": "CrtDisplayRuntimeError",
      "signature": "void CrtDisplayRuntimeError(dword dwErrorCode)",
      "calling_convention": "__cdecl",
      "comment": "CRT Runtime Error Message Display Handler\n\nDisplays CRT runtime error messages to the user based on error code.\nCalled by __amsg_exit and CrtExitCallbackAndTerminate when runtime errors occur.\n\nAlgorithm:\n1. Search g_adwCrtErrorCodeTable for matching error code (8-byte entries: code, message ptr)\n2. If error code not found in table, exit without display\n3. Check g_dwCrtAppType for console vs GUI mode:\n   - If console app (g_dwCrtAppType == 1), write error string to stderr via WriteFile\n   - If GUI app or g_dwCrtMsgBoxMode == 1, display message box\n4. For message box path (non-console):\n   - Skip display if error code is 0xFC (internal marker)\n   - Get module filename via GetModuleFileNameA\n   - If module name unavailable, use \"<program name unknown>\"\n   - Truncate path to 60 chars max with \"...\" suffix if needed\n   - Build formatted message: \"Runtime Error!\n\nProgram: [path]\n\n[error text]\"\n   - Display via FUN_6fc357e4 (MessageBox wrapper) with title \"Microsoft Visual C++ Runtime Library\"\n\nParameters:\n  dwErrorCode - CRT runtime error code (e.g., 0x02=R6002, 0x08=R6008, etc.)\n\nReturns:\n  void\n\nError Code Table (g_adwCrtErrorCodeTable at 0x6fc38730):\n  0x02 - R6002: floating point not loaded\n  0x08 - R6008: not enough space for arguments\n  0x09 - R6009: not enough space for environment\n  0x0A - R6010: abort() has been called\n  0x10 - R6016: not enough space for thread data\n  0x11 - R6017: unexpected multithread lock error\n  0x12 - R6018: unexpected heap error\n  0x13 - R6019: unable to open console device\n  0x18 - R6024: not enough space for lowio initialization\n  0x19 - R6025: pure virtual function call\n  0x1A - R6026: not enough space for stdio initialization\n  0x1B - R6027: not enough space for lowio initialization\n  0x1C - R6028: unable to initialize heap\n  0x78 - R6030: CRT not initialized\n  0x79 - R6031: Attempt to initialize CRT more than once\n  0x7A - R6032: not enough space for locale information\n  0xFC - Internal marker (skips messagebox display)\n  0xFF - R6033: XOSD error\n\nSpecial Cases:\n  - Error code 0xFC bypasses message box display (internal use)\n  - Path truncation preserves last 60 chars with \"...\" prefix\n  - Console apps use stderr (handle -12/0xFFFFFFF4)",
      "name_source": "LoD/1.07",
      "method": "STR",
      "index": "STR:ff7880d11813b11bf7ac9bc241be5c60",
      "strings": {
        "LoD/1.07": [
          "\"Runtime Error!\\n\\nProgram: \"",
          "\"Microsoft Visual C++ Runtime Library\"",
          "\"R6009\\r\\n- not enough space for environment\\r\\n\"",
          "\"<program name unknown>\""
        ],
        "LoD/1.08": [
          "\"Runtime Error!\\n\\nProgram: \"",
          "\"Microsoft Visual C++ Runtime Library\"",
          "\"R6009\\r\\n- not enough space for environment\\r\\n\"",
          "\"<program name unknown>\""
        ],
        "LoD/1.09": [
          "\"Runtime Error!\\n\\nProgram: \"",
          "\"Microsoft Visual C++ Runtime Library\"",
          "\"R6009\\r\\n- not enough space for environment\\r\\n\"",
          "\"<program name unknown>\""
        ],
        "LoD/1.09b": [
          "\"Runtime Error!\\n\\nProgram: \"",
          "\"Microsoft Visual C++ Runtime Library\"",
          "\"R6009\\r\\n- not enough space for environment\\r\\n\"",
          "\"<program name unknown>\""
        ],
        "LoD/1.09d": [
          "\"Runtime Error!\\n\\nProgram: \"",
          "\"Microsoft Visual C++ Runtime Library\"",
          "\"R6009\\r\\n- not enough space for environment\\r\\n\"",
          "\"<program name unknown>\""
        ],
        "LoD/1.10": [
          "\"Runtime Error!\\n\\nProgram: \"",
          "\"Microsoft Visual C++ Runtime Library\"",
          "\"R6009\\r\\n- not enough space for environment\\r\\n\"",
          "\"<program name unknown>\""
        ],
        "LoD/1.11": [
          "\"Runtime Error!\\n\\nProgram: \"",
          "\"Microsoft Visual C++ Runtime Library\"",
          "\"R6009\\r\\n- not enough space for environment\\r\\n\"",
          "\"<program name unknown>\""
        ],
        "LoD/1.11b": [
          "\"Runtime Error!\\n\\nProgram: \"",
          "\"Microsoft Visual C++ Runtime Library\"",
          "\"R6009\\r\\n- not enough space for environment\\r\\n\"",
          "\"<program name unknown>\""
        ],
        "LoD/1.12a": [
          "\"Runtime Error!\\n\\nProgram: \"",
          "\"Microsoft Visual C++ Runtime Library\"",
          "\"R6009\\r\\n- not enough space for environment\\r\\n\"",
          "\"<program name unknown>\""
        ],
        "LoD/1.13c": [
          "\"Runtime Error!\\n\\nProgram: \"",
          "\"Microsoft Visual C++ Runtime Library\"",
          "\"R6009\\r\\n- not enough space for environment\\r\\n\"",
          "\"<program name unknown>\""
        ],
        "LoD/1.13d": [
          "\"Runtime Error!\\n\\nProgram: \"",
          "\"Microsoft Visual C++ Runtime Library\"",
          "\"R6009\\r\\n- not enough space for environment\\r\\n\"",
          "\"<program name unknown>\""
        ]
      },
      "basic_block_counts": {
        "LoD/1.07": 15,
        "LoD/1.08": 15,
        "LoD/1.09": 15,
        "LoD/1.09b": 15,
        "LoD/1.09d": 15,
        "LoD/1.10": 15,
        "LoD/1.11": 15,
        "LoD/1.11b": 15,
        "LoD/1.12a": 15,
        "LoD/1.13c": 15,
        "LoD/1.13d": 15
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "da32166b3f0e7e0948a175245c62ec51",
        "LoD/1.08": "da32166b3f0e7e0948a175245c62ec51",
        "LoD/1.09": "da32166b3f0e7e0948a175245c62ec51",
        "LoD/1.09b": "da32166b3f0e7e0948a175245c62ec51",
        "LoD/1.09d": "6bfb7faf8650903f50cd7e2ef7eba7fe",
        "LoD/1.10": "6bfb7faf8650903f50cd7e2ef7eba7fe",
        "LoD/1.11": "df12c88834995835564ff6c039540618",
        "LoD/1.11b": "df12c88834995835564ff6c039540618",
        "LoD/1.12a": "907ddf19e9b559942986798c3a61049f",
        "LoD/1.13c": "907ddf19e9b559942986798c3a61049f",
        "LoD/1.13d": "df12c88834995835564ff6c039540618"
      }
    },
    "d2net.dll_CRT_HeapFree": {
      "addresses": {
        "LoD/1.07": "0x6FC33983",
        "LoD/1.08": "0x6FC33983",
        "LoD/1.09": "0x6FC03983",
        "LoD/1.09b": "0x6FC03983",
        "LoD/1.09d": "0x6FC03983",
        "LoD/1.10": "0x6FC03A23"
      },
      "rvas": {
        "LoD/1.07": "0x3983",
        "LoD/1.08": "0x3983",
        "LoD/1.09": "0x3983",
        "LoD/1.09b": "0x3983",
        "LoD/1.09d": "0x3983",
        "LoD/1.10": "0x3A23"
      },
      "sizes": {
        "LoD/1.07": 215,
        "LoD/1.08": 215,
        "LoD/1.09": 215,
        "LoD/1.09b": 215,
        "LoD/1.09d": 215,
        "LoD/1.10": 215
      },
      "name": "CRT_HeapFree",
      "signature": "void CRT_HeapFree(void * pBlock)",
      "calling_convention": "__cdecl",
      "comment": "CRT heap memory deallocation wrapper with SEH protection.\n\nFrees memory allocated by CRT heap allocation functions. Routes deallocation\nthrough the appropriate subsystem based on g_dwHeapType: region-based allocator\n(type 3), small block heap (type 2), or direct Windows heap (default).\n\nAlgorithm:\n1. Set up SEH frame with scope table and exception handler\n2. Return immediately if pBlock is NULL\n3. Check g_dwHeapType for allocation strategy:\n   - If type 3 (region allocator):\n     a. Enter critical section 9\n     b. Find region record via FUN_6fc349b7\n     c. If found, mark block free via FUN_6fc349e2\n     d. Leave critical section\n     e. If region found, return (skip HeapFree)\n   - If type 2 (small block heap):\n     a. Enter critical section 9\n     b. Lookup heap node via FUN_6fc3541c\n     c. If found, free via FUN_6fc35473\n     d. Leave critical section\n     e. If node found, return (skip HeapFree)\n4. Call HeapFree(g_hCrtHeap, 0, pBlock) for unmanaged blocks\n5. Restore SEH chain and return\n\nParameters:\n  pBlock - Pointer to memory block to free. May be NULL (safe no-op).\n           Generic void* since this handles any CRT-allocated memory.\n\nReturns:\n  void\n\nSpecial Cases:\n  - NULL pointer: Returns immediately without any action\n  - Region-managed block (type 3): Freed via region subsystem\n  - Small block heap (type 2): Freed via small block subsystem\n  - Direct heap allocation: Falls through to HeapFree\n\nGlobals Used:\n  g_dwHeapType - Heap allocation strategy (2=small block, 3=region, other=direct)\n  g_hCrtHeap - Handle to CRT private heap\n\nSEH Frame:\n  Uses __try/__except with scope table at g_SehScopeTable.\n  Handler at LAB_6fc35a68. State variable tracks active scope.\n\nPhantom Variables (decompiler SSA temporaries):\n  puStack_c (pSehScopeTable): SEH scope table pointer\n  puStack_10 (pSehHandler): SEH exception handler address\n  puVar1 (pdwResult): Result from region/node lookup, determines HeapFree fallback",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:38a52ad8d9123a0ed65e4de10b1cf943",
      "basic_block_counts": {
        "LoD/1.07": 14,
        "LoD/1.08": 14,
        "LoD/1.09": 14,
        "LoD/1.09b": 14,
        "LoD/1.09d": 14,
        "LoD/1.10": 14
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "38a52ad8d9123a0ed65e4de10b1cf943",
        "LoD/1.08": "38a52ad8d9123a0ed65e4de10b1cf943",
        "LoD/1.09": "38a52ad8d9123a0ed65e4de10b1cf943",
        "LoD/1.09b": "38a52ad8d9123a0ed65e4de10b1cf943",
        "LoD/1.09d": "38a52ad8d9123a0ed65e4de10b1cf943",
        "LoD/1.10": "38a52ad8d9123a0ed65e4de10b1cf943"
      }
    },
    "d2net.dll_CRT_LeaveHeapLock": {
      "addresses": {
        "LoD/1.07": "0x6FC339ED",
        "LoD/1.08": "0x6FC339ED",
        "LoD/1.09": "0x6FC039ED",
        "LoD/1.09b": "0x6FC039ED",
        "LoD/1.09d": "0x6FC039ED",
        "LoD/1.10": "0x6FC03A8D",
        "LoD/1.11": "0x6FBF2BD2",
        "LoD/1.11b": "0x6FBF2BD2",
        "LoD/1.12a": "0x6FBF2BF3",
        "LoD/1.13c": "0x6FBF2F49",
        "LoD/1.13d": "0x6FBF2013"
      },
      "rvas": {
        "LoD/1.07": "0x39ED",
        "LoD/1.08": "0x39ED",
        "LoD/1.09": "0x39ED",
        "LoD/1.09b": "0x39ED",
        "LoD/1.09d": "0x39ED",
        "LoD/1.10": "0x3A8D",
        "LoD/1.11": "0x2BD2",
        "LoD/1.11b": "0x2BD2",
        "LoD/1.12a": "0x2BF3",
        "LoD/1.13c": "0x2F49",
        "LoD/1.13d": "0x2013"
      },
      "sizes": {
        "LoD/1.07": 9,
        "LoD/1.08": 9,
        "LoD/1.09": 9,
        "LoD/1.09b": 9,
        "LoD/1.09d": 9,
        "LoD/1.10": 9,
        "LoD/1.11": 9,
        "LoD/1.11b": 9,
        "LoD/1.12a": 9,
        "LoD/1.13c": 9,
        "LoD/1.13d": 9
      },
      "name": "CRT_LeaveHeapLock",
      "signature": "void CRT_LeaveHeapLock(void)",
      "calling_convention": "__stdcall",
      "comment": "Releases the CRT heap critical section lock (index 9).\n\nClassification: Thunk - wraps CRT_LeaveCritSectByIndex with hardcoded index.\n\nAlgorithm:\n1. Push critical section index 9 (heap lock)\n2. Call CRT_LeaveCritSectByIndex to release the lock\n3. Pop parameter and return\n\nParameters:\n  None - all parameters are hardcoded constants\n\nReturns:\n  void\n\nSpecial Cases:\n  - Must be paired with prior CRT_EnterCritSectByIndex(9) call\n  - Part of SEH-protected heap free path in CRT_HeapFree\n\nCalled By: CRT_HeapFree (0x6fc33983)\n\nMagic Numbers:\n  0x9 - Critical section index for heap lock (g_apCrtLocks[9])",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:f23ef2b3a6cfdeb1f35221d5fc7b15e0",
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1,
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.08": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.09": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.09b": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.09d": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.10": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.11": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.11b": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.12a": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.13c": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.13d": "f23ef2b3a6cfdeb1f35221d5fc7b15e0"
      }
    },
    "d2net.dll_CRT_LeaveHeapLockSmallBlock": {
      "addresses": {
        "LoD/1.07": "0x6FC33A45",
        "LoD/1.08": "0x6FC33A45",
        "LoD/1.09": "0x6FC03A45",
        "LoD/1.09b": "0x6FC03A45",
        "LoD/1.09d": "0x6FC03A45",
        "LoD/1.10": "0x6FC03AE5",
        "LoD/1.11": "0x6FBF136D",
        "LoD/1.11b": "0x6FBF136D",
        "LoD/1.12a": "0x6FBF1030",
        "LoD/1.13c": "0x6FBF136D",
        "LoD/1.13d": "0x6FBF1030"
      },
      "rvas": {
        "LoD/1.07": "0x3A45",
        "LoD/1.08": "0x3A45",
        "LoD/1.09": "0x3A45",
        "LoD/1.09b": "0x3A45",
        "LoD/1.09d": "0x3A45",
        "LoD/1.10": "0x3AE5",
        "LoD/1.11": "0x136D",
        "LoD/1.11b": "0x136D",
        "LoD/1.12a": "0x1030",
        "LoD/1.13c": "0x136D",
        "LoD/1.13d": "0x1030"
      },
      "sizes": {
        "LoD/1.07": 9,
        "LoD/1.08": 9,
        "LoD/1.09": 9,
        "LoD/1.09b": 9,
        "LoD/1.09d": 9,
        "LoD/1.10": 9,
        "LoD/1.11": 9,
        "LoD/1.11b": 9,
        "LoD/1.12a": 9,
        "LoD/1.13c": 9,
        "LoD/1.13d": 9
      },
      "name": "CRT_LeaveHeapLockSmallBlock",
      "signature": "void CRT_LeaveHeapLockSmallBlock(void)",
      "calling_convention": "__stdcall",
      "comment": "Leaves the small-block heap critical section (index 9).\n\nThunk function that wraps CRT_LeaveCritSectByIndex with hardcoded\ncritical section index 9 (heap lock). Called by CRT_HeapFree after\ncompleting small-block heap operations (g_dwHeapType == 2).\n\nAlgorithm:\n1. Push critical section index 9 onto stack\n2. Call CRT_LeaveCritSectByIndex to release heap lock\n3. Return to caller\n\nParameters: None\n\nReturns: void\n\nCallers:\n- CRT_HeapFree: After small-block heap free operations\n\nRelated Functions:\n- CRT_LeaveHeapLock: Leaves heap lock for type 3 heap\n- CRT_EnterCritSectByIndex: Enters critical section by index\n- CRT_LeaveCritSectByIndex: Generic critical section leave\n\nMagic Numbers:\n- 9: Critical section index for CRT small-block heap lock",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:f23ef2b3a6cfdeb1f35221d5fc7b15e0",
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1,
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.08": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.09": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.09b": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.09d": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.10": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.11": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.11b": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.12a": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.13c": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.13d": "f23ef2b3a6cfdeb1f35221d5fc7b15e0"
      }
    },
    "d2net.dll__malloc": {
      "addresses": {
        "LoD/1.07": "0x6FC33A6C",
        "LoD/1.08": "0x6FC33A6C",
        "LoD/1.09": "0x6FC03A6C",
        "LoD/1.09b": "0x6FC03A6C",
        "LoD/1.09d": "0x6FC03A6C",
        "LoD/1.10": "0x6FC03B0C",
        "LoD/1.11": "0x6FBF2C07",
        "LoD/1.11b": "0x6FBF2C07",
        "LoD/1.12a": "0x6FBF2C28",
        "LoD/1.13c": "0x6FBF2C28",
        "LoD/1.13d": "0x6FBF2C07"
      },
      "rvas": {
        "LoD/1.07": "0x3A6C",
        "LoD/1.08": "0x3A6C",
        "LoD/1.09": "0x3A6C",
        "LoD/1.09b": "0x3A6C",
        "LoD/1.09d": "0x3A6C",
        "LoD/1.10": "0x3B0C",
        "LoD/1.11": "0x2C07",
        "LoD/1.11b": "0x2C07",
        "LoD/1.12a": "0x2C28",
        "LoD/1.13c": "0x2C28",
        "LoD/1.13d": "0x2C07"
      },
      "sizes": {
        "LoD/1.07": 18,
        "LoD/1.08": 18,
        "LoD/1.09": 18,
        "LoD/1.09b": 18,
        "LoD/1.09d": 18,
        "LoD/1.10": 18,
        "LoD/1.11": 18,
        "LoD/1.11b": 18,
        "LoD/1.12a": 18,
        "LoD/1.13c": 18,
        "LoD/1.13d": 18
      },
      "name": "_malloc",
      "signature": "void * _malloc(size_t _Size)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n _malloc\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:301bd5440f60703ca7a24a8fb30f1e56",
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1,
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "301bd5440f60703ca7a24a8fb30f1e56",
        "LoD/1.08": "301bd5440f60703ca7a24a8fb30f1e56",
        "LoD/1.09": "301bd5440f60703ca7a24a8fb30f1e56",
        "LoD/1.09b": "301bd5440f60703ca7a24a8fb30f1e56",
        "LoD/1.09d": "301bd5440f60703ca7a24a8fb30f1e56",
        "LoD/1.10": "301bd5440f60703ca7a24a8fb30f1e56",
        "LoD/1.11": "301bd5440f60703ca7a24a8fb30f1e56",
        "LoD/1.11b": "301bd5440f60703ca7a24a8fb30f1e56",
        "LoD/1.12a": "301bd5440f60703ca7a24a8fb30f1e56",
        "LoD/1.13c": "301bd5440f60703ca7a24a8fb30f1e56",
        "LoD/1.13d": "301bd5440f60703ca7a24a8fb30f1e56"
      }
    },
    "d2net.dll___nh_malloc": {
      "addresses": {
        "LoD/1.07": "0x6FC33A7E",
        "LoD/1.08": "0x6FC33A7E",
        "LoD/1.09": "0x6FC03A7E",
        "LoD/1.09b": "0x6FC03A7E",
        "LoD/1.09d": "0x6FC03A7E",
        "LoD/1.10": "0x6FC03B1E",
        "LoD/1.11": "0x6FBF2BDB",
        "LoD/1.11b": "0x6FBF2BDB",
        "LoD/1.12a": "0x6FBF2BFC",
        "LoD/1.13c": "0x6FBF2BFC",
        "LoD/1.13d": "0x6FBF2BDB"
      },
      "rvas": {
        "LoD/1.07": "0x3A7E",
        "LoD/1.08": "0x3A7E",
        "LoD/1.09": "0x3A7E",
        "LoD/1.09b": "0x3A7E",
        "LoD/1.09d": "0x3A7E",
        "LoD/1.10": "0x3B1E",
        "LoD/1.11": "0x2BDB",
        "LoD/1.11b": "0x2BDB",
        "LoD/1.12a": "0x2BFC",
        "LoD/1.13c": "0x2BFC",
        "LoD/1.13d": "0x2BDB"
      },
      "sizes": {
        "LoD/1.07": 44,
        "LoD/1.08": 44,
        "LoD/1.09": 44,
        "LoD/1.09b": 44,
        "LoD/1.09d": 44,
        "LoD/1.10": 44,
        "LoD/1.11": 44,
        "LoD/1.11b": 44,
        "LoD/1.12a": 44,
        "LoD/1.13c": 44,
        "LoD/1.13d": 44
      },
      "name": "__nh_malloc",
      "signature": "void * __nh_malloc(size_t _Size, int _NhFlag)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __nh_malloc\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:be05c38d951a724b98e30bc46956a8c1",
      "basic_block_counts": {
        "LoD/1.07": 6,
        "LoD/1.08": 6,
        "LoD/1.09": 6,
        "LoD/1.09b": 6,
        "LoD/1.09d": 6,
        "LoD/1.10": 6,
        "LoD/1.11": 6,
        "LoD/1.11b": 6,
        "LoD/1.12a": 6,
        "LoD/1.13c": 6,
        "LoD/1.13d": 6
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "be05c38d951a724b98e30bc46956a8c1",
        "LoD/1.08": "be05c38d951a724b98e30bc46956a8c1",
        "LoD/1.09": "be05c38d951a724b98e30bc46956a8c1",
        "LoD/1.09b": "be05c38d951a724b98e30bc46956a8c1",
        "LoD/1.09d": "be05c38d951a724b98e30bc46956a8c1",
        "LoD/1.10": "be05c38d951a724b98e30bc46956a8c1",
        "LoD/1.11": "be05c38d951a724b98e30bc46956a8c1",
        "LoD/1.11b": "be05c38d951a724b98e30bc46956a8c1",
        "LoD/1.12a": "be05c38d951a724b98e30bc46956a8c1",
        "LoD/1.13c": "be05c38d951a724b98e30bc46956a8c1",
        "LoD/1.13d": "be05c38d951a724b98e30bc46956a8c1"
      }
    },
    "d2net.dll_CRT_HeapAlloc": {
      "addresses": {
        "LoD/1.07": "0x6FC33AAA",
        "LoD/1.08": "0x6FC33AAA",
        "LoD/1.09": "0x6FC03AAA",
        "LoD/1.09b": "0x6FC03AAA",
        "LoD/1.09d": "0x6FC03AAA",
        "LoD/1.10": "0x6FC03B4A"
      },
      "rvas": {
        "LoD/1.07": "0x3AAA",
        "LoD/1.08": "0x3AAA",
        "LoD/1.09": "0x3AAA",
        "LoD/1.09b": "0x3AAA",
        "LoD/1.09d": "0x3AAA",
        "LoD/1.10": "0x3B4A"
      },
      "sizes": {
        "LoD/1.07": 231,
        "LoD/1.08": 231,
        "LoD/1.09": 231,
        "LoD/1.09b": 231,
        "LoD/1.09d": 231,
        "LoD/1.10": 231
      },
      "name": "CRT_HeapAlloc",
      "signature": "void * CRT_HeapAlloc(uint dwRequestedSize)",
      "calling_convention": "__cdecl",
      "comment": "CRT Heap Allocation - Allocates memory using appropriate CRT heap strategy.\n\nWorker function that dispatches allocation requests to different backends based on\ng_dwHeapType configuration. Called by __nh_malloc for all CRT memory allocations.\n\nAlgorithm:\n1. Setup SEH frame for exception safety during critical section operations\n2. Check g_dwHeapType to determine allocation strategy:\n   a. Type 3 (Small Block Heap): If size <= g_dwSmallBlockMaxSize, enter critical\n      section 9, call FUN_6fc34d0b for small block allocation, return if successful\n   b. Type 2 (Aligned Block Heap): Align size to 16 bytes (minimum 16), if aligned\n      size <= g_dwAlignedBlockMaxSize, enter critical section 9, call FUN_6fc354b8\n      with size/16 as bucket index, return if successful\n3. Fallback path: Align size to 16-byte boundary (minimum 1 byte request), call\n   HeapAlloc directly on g_hCrtHeap with aligned size\n4. Restore exception list and return allocation result\n\nParameters:\n  dwRequestedSize - Requested allocation size in bytes. Zero is valid (allocates minimum).\n\nReturns:\n  void * - Pointer to allocated memory block, or NULL on failure.\n\nSpecial Cases:\n  - Zero-size requests: Allocates minimum block (1 byte before alignment, 16 after)\n  - Large allocations: Sizes exceeding threshold fall through to direct HeapAlloc\n  - Thread safety: Uses critical section 9 for small/aligned block heap operations\n\nHeap Types:\n  Type 2 - Aligned block heap with 16-byte alignment, uses bucket allocator\n  Type 3 - Small block heap for smaller allocations\n  Default - Direct HeapAlloc fallback for large or unsupported allocations\n\nSEH State Values:\n  0xFFFFFFFF - Outside critical section (safe to unwind)\n  0 - Inside critical section for small block heap (type 3)\n  1 - Inside critical section for aligned block heap (type 2)\n\nGlobals Referenced:\n  g_dwHeapType (0x6fc3b7cc) - Heap strategy selector (2, 3, or other)\n  g_dwSmallBlockMaxSize (0x6fc3b5a8) - Maximum size for small block heap\n  g_dwAlignedBlockMaxSize (0x6fc3a974) - Maximum size for aligned block heap\n  g_hCrtHeap (0x6fc3b7c8) - CRT process heap handle",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:2427cd9c654afc2c511ea083018810d8",
      "basic_block_counts": {
        "LoD/1.07": 16,
        "LoD/1.08": 16,
        "LoD/1.09": 16,
        "LoD/1.09b": 16,
        "LoD/1.09d": 16,
        "LoD/1.10": 16
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "2427cd9c654afc2c511ea083018810d8",
        "LoD/1.08": "2427cd9c654afc2c511ea083018810d8",
        "LoD/1.09": "2427cd9c654afc2c511ea083018810d8",
        "LoD/1.09b": "2427cd9c654afc2c511ea083018810d8",
        "LoD/1.09d": "2427cd9c654afc2c511ea083018810d8",
        "LoD/1.10": "2427cd9c654afc2c511ea083018810d8"
      }
    },
    "d2net.dll_CRT_LeaveSmallBlockCritSect": {
      "addresses": {
        "LoD/1.07": "0x6FC33B11",
        "LoD/1.08": "0x6FC33B11",
        "LoD/1.09": "0x6FC03B11",
        "LoD/1.09b": "0x6FC03B11",
        "LoD/1.09d": "0x6FC03B11",
        "LoD/1.10": "0x6FC03BB1",
        "LoD/1.11": "0x6FBF2E72",
        "LoD/1.11b": "0x6FBF2E72",
        "LoD/1.12a": "0x6FBF202F",
        "LoD/1.13c": "0x6FBF2027",
        "LoD/1.13d": "0x6FBF2E72"
      },
      "rvas": {
        "LoD/1.07": "0x3B11",
        "LoD/1.08": "0x3B11",
        "LoD/1.09": "0x3B11",
        "LoD/1.09b": "0x3B11",
        "LoD/1.09d": "0x3B11",
        "LoD/1.10": "0x3BB1",
        "LoD/1.11": "0x2E72",
        "LoD/1.11b": "0x2E72",
        "LoD/1.12a": "0x202F",
        "LoD/1.13c": "0x2027",
        "LoD/1.13d": "0x2E72"
      },
      "sizes": {
        "LoD/1.07": 9,
        "LoD/1.08": 9,
        "LoD/1.09": 9,
        "LoD/1.09b": 9,
        "LoD/1.09d": 9,
        "LoD/1.10": 9,
        "LoD/1.11": 9,
        "LoD/1.11b": 9,
        "LoD/1.12a": 9,
        "LoD/1.13c": 9,
        "LoD/1.13d": 9
      },
      "name": "CRT_LeaveSmallBlockCritSect",
      "signature": "void CRT_LeaveSmallBlockCritSect(void)",
      "calling_convention": "__stdcall",
      "comment": "Releases the small block heap critical section (index 9).\n\nClassification: Thunk - wrapper for CRT_LeaveCritSectByIndex(9).\n\nAlgorithm:\n1. Push constant 9 (small block lock index) onto stack\n2. Call CRT_LeaveCritSectByIndex to release the lock\n3. Clean up stack and return\n\nParameters:\n  None\n\nReturns:\n  void\n\nSpecial Cases:\n  - Must be paired with prior CRT_EnterCritSectByIndex(9) call\n  - Called after FUN_6fc34d0b completes small block allocation\n\nGlobal Data:\n  - Uses g_apCrtLocks[9] indirectly via CRT_LeaveCritSectByIndex\n\nCalled By: CRT_HeapAlloc (small block allocation path)",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:f23ef2b3a6cfdeb1f35221d5fc7b15e0",
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1,
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.08": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.09": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.09b": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.09d": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.10": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.11": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.11b": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.12a": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.13c": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.13d": "f23ef2b3a6cfdeb1f35221d5fc7b15e0"
      }
    },
    "d2net.dll_CRT_LeaveAlignedBlockCritSect": {
      "addresses": {
        "LoD/1.07": "0x6FC33B70",
        "LoD/1.08": "0x6FC33B70",
        "LoD/1.09": "0x6FC03B70",
        "LoD/1.09b": "0x6FC03B70",
        "LoD/1.09d": "0x6FC03B70",
        "LoD/1.10": "0x6FC03C10",
        "LoD/1.11": "0x6FBF3319",
        "LoD/1.11b": "0x6FBF3319",
        "LoD/1.12a": "0x6FBF333E",
        "LoD/1.13c": "0x6FBF333E",
        "LoD/1.13d": "0x6FBF3319"
      },
      "rvas": {
        "LoD/1.07": "0x3B70",
        "LoD/1.08": "0x3B70",
        "LoD/1.09": "0x3B70",
        "LoD/1.09b": "0x3B70",
        "LoD/1.09d": "0x3B70",
        "LoD/1.10": "0x3C10",
        "LoD/1.11": "0x3319",
        "LoD/1.11b": "0x3319",
        "LoD/1.12a": "0x333E",
        "LoD/1.13c": "0x333E",
        "LoD/1.13d": "0x3319"
      },
      "sizes": {
        "LoD/1.07": 9,
        "LoD/1.08": 9,
        "LoD/1.09": 9,
        "LoD/1.09b": 9,
        "LoD/1.09d": 9,
        "LoD/1.10": 9,
        "LoD/1.11": 9,
        "LoD/1.11b": 9,
        "LoD/1.12a": 9,
        "LoD/1.13c": 9,
        "LoD/1.13d": 9
      },
      "name": "CRT_LeaveAlignedBlockCritSect",
      "signature": "void CRT_LeaveAlignedBlockCritSect(void)",
      "calling_convention": "__stdcall",
      "comment": "Releases the aligned block heap critical section (index 9).\n\nClassification: Thunk - wrapper for CRT_LeaveCritSectByIndex(9).\n\nAlgorithm:\n1. Push constant 9 (heap lock index) onto stack\n2. Call CRT_LeaveCritSectByIndex to release the lock\n3. Clean up stack (POP ECX) and return\n\nParameters:\n  None\n\nReturns:\n  void\n\nSpecial Cases:\n  - Must be paired with prior CRT_EnterCritSectByIndex(9) call\n  - Called after FUN_6fc354b8 completes aligned block allocation\n\nGlobal Data:\n  - Uses g_apCrtLocks[9] indirectly via CRT_LeaveCritSectByIndex\n\nCalled By: CRT_HeapAlloc (aligned block allocation path, heap type 2)\n\nRelated Functions:\n  - CRT_LeaveSmallBlockCritSect: Equivalent for small block heap (type 3)\n  - CRT_EnterCritSectByIndex: Paired entry function",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:f23ef2b3a6cfdeb1f35221d5fc7b15e0",
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1,
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.08": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.09": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.09b": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.09d": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.10": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.11": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.11b": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.12a": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.13c": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.13d": "f23ef2b3a6cfdeb1f35221d5fc7b15e0"
      }
    },
    "d2net.dll_CRT_Calloc": {
      "addresses": {
        "LoD/1.07": "0x6FC33BA6",
        "LoD/1.08": "0x6FC33BA6",
        "LoD/1.09": "0x6FC03BA6",
        "LoD/1.09b": "0x6FC03BA6",
        "LoD/1.09d": "0x6FC03BA6",
        "LoD/1.10": "0x6FC03C46"
      },
      "rvas": {
        "LoD/1.07": "0x3BA6",
        "LoD/1.08": "0x3BA6",
        "LoD/1.09": "0x3BA6",
        "LoD/1.09b": "0x3BA6",
        "LoD/1.09d": "0x3BA6",
        "LoD/1.10": "0x3C46"
      },
      "sizes": {
        "LoD/1.07": 289,
        "LoD/1.08": 289,
        "LoD/1.09": 289,
        "LoD/1.09b": 289,
        "LoD/1.09d": 289,
        "LoD/1.10": 289
      },
      "name": "CRT_Calloc",
      "signature": "void * CRT_Calloc(uint nElementCount, uint nElementSize)",
      "calling_convention": "__cdecl",
      "comment": "CRT_Calloc - Allocate and zero-initialize memory block (calloc implementation)\n\nAllocates memory for an array of nElementCount elements, each nElementSize bytes,\nand initializes all bytes to zero. Supports three allocation strategies based on\nconfigured heap type.\n\nAlgorithm:\n1. Calculate total allocation size: nElementCount * nElementSize\n2. Validate against overflow limit (0xFFFFFFE0)\n3. If size is 0, set minimum allocation to 1 byte\n4. Align size to 16-byte boundary: (size + 0xF) & 0xFFFFFFF0\n5. Check g_dwHeapType for allocation strategy:\n   - Type 3 (Small Block Heap): If size <= g_dwSmallBlockMaxSize, use FUN_6fc34d0b\n   - Type 2 (Aligned Block Heap): If aligned size <= g_dwAlignedBlockMaxSize, use FUN_6fc354b8\n   - Fallback: Use HeapAlloc with HEAP_ZERO_MEMORY flag (0x8)\n6. If allocation succeeds, zero memory with _memset and return pointer\n7. If allocation fails and g_pfnNewHandler is set, call FUN_6fc35b40 (new handler)\n8. Retry allocation if new handler returns non-zero\n9. Return NULL if all allocation attempts fail\n\nParameters:\n  nElementCount (uint) - Number of elements to allocate\n  nElementSize (uint) - Size in bytes of each element\n\nReturns:\n  void * - Pointer to allocated zero-initialized memory, or NULL on failure\n\nSpecial Cases:\n  - Zero-size allocation returns 1-byte block (aligned to 16)\n  - Overflow check: size >= 0xFFFFFFE1 returns NULL\n  - New handler callback enables retry loop for out-of-memory recovery\n\nGlobals Referenced:\n  g_dwHeapType (0x6fc3b7cc) - Heap allocation strategy (2=aligned, 3=small block)\n  g_dwSmallBlockMaxSize (0x6fc3b5a8) - Max size for small block allocator\n  g_dwAlignedBlockMaxSize (0x6fc3a974) - Max size for aligned block allocator (0x1E0)\n  g_hCrtHeap (0x6fc3b7c8) - CRT heap handle for HeapAlloc fallback\n  g_pfnNewHandler (0x6fc3b410) - New handler callback for OOM recovery\n\nSEH Frame:\n  Uses structured exception handling with state machine (dwSehState):\n  0xFFFFFFFF = Default/cleanup state\n  0 = Inside small block critical section\n  1 = Inside aligned block critical section",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:371cf2604575a233020cd5d20fe5277c",
      "basic_block_counts": {
        "LoD/1.07": 23,
        "LoD/1.08": 23,
        "LoD/1.09": 23,
        "LoD/1.09b": 23,
        "LoD/1.09d": 23,
        "LoD/1.10": 23
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "371cf2604575a233020cd5d20fe5277c",
        "LoD/1.08": "371cf2604575a233020cd5d20fe5277c",
        "LoD/1.09": "371cf2604575a233020cd5d20fe5277c",
        "LoD/1.09b": "371cf2604575a233020cd5d20fe5277c",
        "LoD/1.09d": "371cf2604575a233020cd5d20fe5277c",
        "LoD/1.10": "371cf2604575a233020cd5d20fe5277c"
      }
    },
    "d2net.dll_CRT_LeaveSmallBlockHeapLock": {
      "addresses": {
        "LoD/1.07": "0x6FC33C3F",
        "LoD/1.08": "0x6FC33C3F",
        "LoD/1.09": "0x6FC03C3F",
        "LoD/1.09b": "0x6FC03C3F",
        "LoD/1.09d": "0x6FC03C3F",
        "LoD/1.10": "0x6FC03CDF",
        "LoD/1.11": "0x6FBF18D7",
        "LoD/1.11b": "0x6FBF18D7",
        "LoD/1.12a": "0x6FBF18DF",
        "LoD/1.13c": "0x6FBF18D7",
        "LoD/1.13d": "0x6FBF18DF"
      },
      "rvas": {
        "LoD/1.07": "0x3C3F",
        "LoD/1.08": "0x3C3F",
        "LoD/1.09": "0x3C3F",
        "LoD/1.09b": "0x3C3F",
        "LoD/1.09d": "0x3C3F",
        "LoD/1.10": "0x3CDF",
        "LoD/1.11": "0x18D7",
        "LoD/1.11b": "0x18D7",
        "LoD/1.12a": "0x18DF",
        "LoD/1.13c": "0x18D7",
        "LoD/1.13d": "0x18DF"
      },
      "sizes": {
        "LoD/1.07": 9,
        "LoD/1.08": 9,
        "LoD/1.09": 9,
        "LoD/1.09b": 9,
        "LoD/1.09d": 9,
        "LoD/1.10": 9,
        "LoD/1.11": 9,
        "LoD/1.11b": 9,
        "LoD/1.12a": 9,
        "LoD/1.13c": 9,
        "LoD/1.13d": 9
      },
      "name": "CRT_LeaveSmallBlockHeapLock",
      "signature": "void CRT_LeaveSmallBlockHeapLock(void)",
      "calling_convention": "__stdcall",
      "comment": "Releases the small block heap critical section lock (index 9).\n\nClassification: Thunk/Wrapper function - SEH cleanup handler for heap operations.\n\nAlgorithm:\n1. Push critical section index 9 onto stack\n2. Call CRT_LeaveCritSectByIndex to release lock\n3. Clean up stack and return\n\nParameters:\n  None (void)\n\nReturns:\n  void\n\nSpecial Cases:\n  - Used as SEH __finally handler in FUN_6fc33ba6 (calloc-style allocator)\n  - Must be called after CRT_EnterCritSectByIndex(9) was invoked\n  - Critical section 9 protects small block heap allocation structures\n\nGlobal Data:\n  g_apCrtLocks[9] - CRITICAL_SECTION for small block heap (via callee)\n\nCalled By:\n  FUN_6fc33ba6 - Heap allocation with small block optimization",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:f23ef2b3a6cfdeb1f35221d5fc7b15e0",
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1,
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.08": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.09": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.09b": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.09d": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.10": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.11": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.11b": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.12a": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.13c": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.13d": "f23ef2b3a6cfdeb1f35221d5fc7b15e0"
      }
    },
    "d2net.dll_CRT_LeaveAlignedBlockHeapLock": {
      "addresses": {
        "LoD/1.07": "0x6FC33CC8",
        "LoD/1.08": "0x6FC33CC8",
        "LoD/1.09": "0x6FC03CC8",
        "LoD/1.09b": "0x6FC03CC8",
        "LoD/1.09d": "0x6FC03CC8",
        "LoD/1.10": "0x6FC03D68",
        "LoD/1.11": "0x6FBF1DC9",
        "LoD/1.11b": "0x6FBF1DC9",
        "LoD/1.12a": "0x6FBF1DD1",
        "LoD/1.13c": "0x6FBF1DC9",
        "LoD/1.13d": "0x6FBF1DD1"
      },
      "rvas": {
        "LoD/1.07": "0x3CC8",
        "LoD/1.08": "0x3CC8",
        "LoD/1.09": "0x3CC8",
        "LoD/1.09b": "0x3CC8",
        "LoD/1.09d": "0x3CC8",
        "LoD/1.10": "0x3D68",
        "LoD/1.11": "0x1DC9",
        "LoD/1.11b": "0x1DC9",
        "LoD/1.12a": "0x1DD1",
        "LoD/1.13c": "0x1DC9",
        "LoD/1.13d": "0x1DD1"
      },
      "sizes": {
        "LoD/1.07": 9,
        "LoD/1.08": 9,
        "LoD/1.09": 9,
        "LoD/1.09b": 9,
        "LoD/1.09d": 9,
        "LoD/1.10": 9,
        "LoD/1.11": 9,
        "LoD/1.11b": 9,
        "LoD/1.12a": 9,
        "LoD/1.13c": 9,
        "LoD/1.13d": 9
      },
      "name": "CRT_LeaveAlignedBlockHeapLock",
      "signature": "void CRT_LeaveAlignedBlockHeapLock(void)",
      "calling_convention": "__stdcall",
      "comment": "Releases the aligned block heap critical section lock (index 9).\n\nClassification: Thunk - wrapper calling CRT_LeaveCritSectByIndex with hardcoded index 9.\n\nAlgorithm:\n1. Push lock index 9 onto stack\n2. Call CRT_LeaveCritSectByIndex to release critical section\n3. Clean up stack and return\n\nParameters:\n  None\n\nReturns:\n  void\n\nSpecial Cases:\n  - Must be paired with prior CRT_EnterCritSectByIndex(9) call\n  - Index 9 corresponds to the aligned block heap lock in g_apCrtLocks array\n  - Used specifically by heap type 2 (aligned block allocator) in CRT_Calloc\n\nCalled By:\n  CRT_Calloc - releases lock after aligned block allocation attempt\n\nSee Also:\n  CRT_LeaveSmallBlockHeapLock - equivalent function for heap type 3\n  CRT_EnterCritSectByIndex - acquires the critical section lock\n  CRT_LeaveCritSectByIndex - generic lock release function",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:f23ef2b3a6cfdeb1f35221d5fc7b15e0",
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1,
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.08": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.09": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.09b": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.09d": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.10": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.11": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.11b": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.12a": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.13c": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.13d": "f23ef2b3a6cfdeb1f35221d5fc7b15e0"
      }
    },
    "d2net.dll_CRT_strcpy": {
      "addresses": {
        "LoD/1.07": "0x6FC33CF0",
        "LoD/1.08": "0x6FC33CF0",
        "LoD/1.09": "0x6FC03CF0",
        "LoD/1.09b": "0x6FC03CF0",
        "LoD/1.09d": "0x6FC03CF0",
        "LoD/1.10": "0x6FC03D90",
        "LoD/1.11": "0x6FBF43B0",
        "LoD/1.11b": "0x6FBF43B0",
        "LoD/1.12a": "0x6FBF43E0",
        "LoD/1.13c": "0x6FBF43E0",
        "LoD/1.13d": "0x6FBF43B0"
      },
      "rvas": {
        "LoD/1.07": "0x3CF0",
        "LoD/1.08": "0x3CF0",
        "LoD/1.09": "0x3CF0",
        "LoD/1.09b": "0x3CF0",
        "LoD/1.09d": "0x3CF0",
        "LoD/1.10": "0x3D90",
        "LoD/1.11": "0x43B0",
        "LoD/1.11b": "0x43B0",
        "LoD/1.12a": "0x43E0",
        "LoD/1.13c": "0x43E0",
        "LoD/1.13d": "0x43B0"
      },
      "sizes": {
        "LoD/1.07": 7,
        "LoD/1.08": 7,
        "LoD/1.09": 7,
        "LoD/1.09b": 7,
        "LoD/1.09d": 7,
        "LoD/1.10": 7,
        "LoD/1.11": 7,
        "LoD/1.11b": 7,
        "LoD/1.12a": 7,
        "LoD/1.13c": 7,
        "LoD/1.13d": 7
      },
      "name": "CRT_strcpy",
      "signature": "char * CRT_strcpy(char * lpszDest, char * lpszSrc)",
      "calling_convention": "__cdecl",
      "comment": "CRT_strcpy - Copy string to destination buffer\n\nClassification: Thunk/Wrapper\nThis is a strcpy entry point that reuses the string copy loop from CRT_strcat\n(FUN_6fc33d00). It jumps directly to the copy portion at 0x6fc33d61, bypassing\nthe strlen scan that strcat uses to find the destination end.\n\nAlgorithm:\n1. Push EDI and load destination pointer into EDI\n2. Jump to strcat's copy loop at 0x6fc33d61\n3. The shared copy loop handles DWORD-aligned fast copy with null termination\n\nParameters:\n  lpszDest  - char *        Destination buffer (must be large enough for source)\n  lpcszSrc  - const char *  Null-terminated source string to copy\n\nReturns:\n  char * - Returns lpszDest (original destination pointer)\n\nMemory Model:\n  Caller must ensure lpszDest has sufficient space for source string + null\n  No bounds checking is performed\n\nCallers:\n  CRT_SetEnvironmentStrings, CrtDisplayRuntimeError\n\nImplementation Note:\n  Uses DWORD-aligned fast copy with magic constant 0x7efefeff for null byte\n  detection. Processes 4 bytes at a time when aligned, byte-by-byte otherwise.",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:70593f43ea0b0d7692df2cd60ddf29e8",
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1,
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "70593f43ea0b0d7692df2cd60ddf29e8",
        "LoD/1.08": "70593f43ea0b0d7692df2cd60ddf29e8",
        "LoD/1.09": "70593f43ea0b0d7692df2cd60ddf29e8",
        "LoD/1.09b": "70593f43ea0b0d7692df2cd60ddf29e8",
        "LoD/1.09d": "70593f43ea0b0d7692df2cd60ddf29e8",
        "LoD/1.10": "70593f43ea0b0d7692df2cd60ddf29e8",
        "LoD/1.11": "70593f43ea0b0d7692df2cd60ddf29e8",
        "LoD/1.11b": "70593f43ea0b0d7692df2cd60ddf29e8",
        "LoD/1.12a": "70593f43ea0b0d7692df2cd60ddf29e8",
        "LoD/1.13c": "70593f43ea0b0d7692df2cd60ddf29e8",
        "LoD/1.13d": "70593f43ea0b0d7692df2cd60ddf29e8"
      }
    },
    "d2net.dll_CrtStrCat": {
      "addresses": {
        "LoD/1.07": "0x6FC33D00",
        "LoD/1.08": "0x6FC33D00",
        "LoD/1.09": "0x6FC03D00",
        "LoD/1.09b": "0x6FC03D00",
        "LoD/1.09d": "0x6FC03D00",
        "LoD/1.10": "0x6FC03DA0"
      },
      "rvas": {
        "LoD/1.07": "0x3D00",
        "LoD/1.08": "0x3D00",
        "LoD/1.09": "0x3D00",
        "LoD/1.09b": "0x3D00",
        "LoD/1.09d": "0x3D00",
        "LoD/1.10": "0x3DA0"
      },
      "sizes": {
        "LoD/1.07": 224,
        "LoD/1.08": 224,
        "LoD/1.09": 224,
        "LoD/1.09b": 224,
        "LoD/1.09d": 224,
        "LoD/1.10": 224
      },
      "name": "CrtStrCat",
      "signature": "void * CrtStrCat(void * pDest, void * pSrc)",
      "calling_convention": "__cdecl",
      "comment": "CRT strcat implementation with DWORD-aligned optimization.\n\nAppends source string to destination string, returning pointer to destination.\n\nAlgorithm:\n1. Align destination pointer scan to DWORD boundary (handle unaligned bytes individually)\n2. Scan destination 4 bytes at a time using null-detection magic constant\n3. When null found, determine exact position (byte 0, 1, 2, or 3)\n4. Align source pointer to DWORD boundary (copy unaligned bytes individually)\n5. Copy source 4 bytes at a time until null detected\n6. Write final partial DWORD including null terminator\n\nParameters:\n  pDest (void *) - Destination string buffer (must have space for concatenation)\n  pSrc (void *) - Source null-terminated string to append\n\nReturns:\n  void * - Original pDest pointer\n\nMagic Numbers:\n  0x7efefeff - Null byte detection constant (causes carry into high bit if any byte is 0)\n  0x81010100 - Mask to check for null byte presence in DWORD\n  0x3 - Alignment mask for DWORD boundary check\n\nSpecial Cases:\n  - Empty source string: Single null byte written at dest end\n  - Unaligned pointers: Handled byte-by-byte until aligned\n\nNote: This is the CRT strcat function used by CrtDisplayRuntimeError for string operations.",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:845fc5044ff181fe96e2ae868d3aa1f6",
      "basic_block_counts": {
        "LoD/1.07": 28,
        "LoD/1.08": 28,
        "LoD/1.09": 28,
        "LoD/1.09b": 28,
        "LoD/1.09d": 28,
        "LoD/1.10": 28
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "845fc5044ff181fe96e2ae868d3aa1f6",
        "LoD/1.08": "845fc5044ff181fe96e2ae868d3aa1f6",
        "LoD/1.09": "845fc5044ff181fe96e2ae868d3aa1f6",
        "LoD/1.09b": "845fc5044ff181fe96e2ae868d3aa1f6",
        "LoD/1.09d": "845fc5044ff181fe96e2ae868d3aa1f6",
        "LoD/1.10": "845fc5044ff181fe96e2ae868d3aa1f6"
      }
    },
    "d2net.dll__strlen": {
      "addresses": {
        "LoD/1.07": "0x6FC33DE0",
        "LoD/1.08": "0x6FC33DE0",
        "LoD/1.09": "0x6FC03DE0",
        "LoD/1.09b": "0x6FC03DE0",
        "LoD/1.09d": "0x6FC03DE0",
        "LoD/1.10": "0x6FC03E80",
        "LoD/1.11": "0x6FBF44B0",
        "LoD/1.11b": "0x6FBF44B0",
        "LoD/1.12a": "0x6FBF44E0",
        "LoD/1.13c": "0x6FBF44E0",
        "LoD/1.13d": "0x6FBF44B0"
      },
      "rvas": {
        "LoD/1.07": "0x3DE0",
        "LoD/1.08": "0x3DE0",
        "LoD/1.09": "0x3DE0",
        "LoD/1.09b": "0x3DE0",
        "LoD/1.09d": "0x3DE0",
        "LoD/1.10": "0x3E80",
        "LoD/1.11": "0x44B0",
        "LoD/1.11b": "0x44B0",
        "LoD/1.12a": "0x44E0",
        "LoD/1.13c": "0x44E0",
        "LoD/1.13d": "0x44B0"
      },
      "sizes": {
        "LoD/1.07": 123,
        "LoD/1.08": 123,
        "LoD/1.09": 123,
        "LoD/1.09b": 123,
        "LoD/1.09d": 123,
        "LoD/1.10": 123,
        "LoD/1.11": 139,
        "LoD/1.11b": 139,
        "LoD/1.12a": 139,
        "LoD/1.13c": 139,
        "LoD/1.13d": 139
      },
      "name": "_strlen",
      "signature": "size_t _strlen(char * _Str)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n _strlen\n\nLibraries: Visual Studio 1998 Debug, Visual Studio 1998 Release",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:2e762c1c6c457f4a0349d0f895009434",
      "basic_block_counts": {
        "LoD/1.07": 14,
        "LoD/1.08": 14,
        "LoD/1.09": 14,
        "LoD/1.09b": 14,
        "LoD/1.09d": 14,
        "LoD/1.10": 14,
        "LoD/1.11": 14,
        "LoD/1.11b": 14,
        "LoD/1.12a": 14,
        "LoD/1.13c": 14,
        "LoD/1.13d": 14
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "2e762c1c6c457f4a0349d0f895009434",
        "LoD/1.08": "2e762c1c6c457f4a0349d0f895009434",
        "LoD/1.09": "2e762c1c6c457f4a0349d0f895009434",
        "LoD/1.09b": "2e762c1c6c457f4a0349d0f895009434",
        "LoD/1.09d": "2e762c1c6c457f4a0349d0f895009434",
        "LoD/1.10": "2e762c1c6c457f4a0349d0f895009434",
        "LoD/1.11": "2b72785c7d09e5484d16dae5407e64ce",
        "LoD/1.11b": "2b72785c7d09e5484d16dae5407e64ce",
        "LoD/1.12a": "2b72785c7d09e5484d16dae5407e64ce",
        "LoD/1.13c": "2b72785c7d09e5484d16dae5407e64ce",
        "LoD/1.13d": "2b72785c7d09e5484d16dae5407e64ce"
      }
    },
    "d2net.dll_CRT_InitializeCodePageCharType": {
      "addresses": {
        "LoD/1.07": "0x6FC33E5B",
        "LoD/1.08": "0x6FC33E5B",
        "LoD/1.09": "0x6FC03E5B",
        "LoD/1.09b": "0x6FC03E5B",
        "LoD/1.09d": "0x6FC03E5B",
        "LoD/1.10": "0x6FC03EFB"
      },
      "rvas": {
        "LoD/1.07": "0x3E5B",
        "LoD/1.08": "0x3E5B",
        "LoD/1.09": "0x3E5B",
        "LoD/1.09b": "0x3E5B",
        "LoD/1.09d": "0x3E5B",
        "LoD/1.10": "0x3EFB"
      },
      "sizes": {
        "LoD/1.07": 429,
        "LoD/1.08": 429,
        "LoD/1.09": 429,
        "LoD/1.09b": 429,
        "LoD/1.09d": 429,
        "LoD/1.10": 429
      },
      "name": "CRT_InitializeCodePageCharTypeTable",
      "signature": "int CRT_InitializeCodePageCharTypeTable(int nLocaleCategory)",
      "calling_convention": "__cdecl",
      "comment": "CRT_InitializeCodePageCharTypeTable - Initialize multibyte character type table for code page\n\nInitializes the global character type classification table (g_abCharTypeTable) based on\nthe specified locale category. This function is the CRT implementation similar to _setmbcp().\n\nAlgorithm:\n1. Enter critical section 0x19 (code page lock)\n2. Convert locale category to code page via FUN_6fc34008 (-3=GetACP, -2=GetOEMCP)\n3. If code page matches current (g_dwCurrentCodePage), return 0 (already initialized)\n4. If code page is 0, call FUN_6fc34085 error handler\n5. Search predefined code page table (g_aCodePageCharTypeEntries) for match:\n   - Table contains entries for: 932 (Japanese), 936 (Chinese Simplified),\n     949 (Korean), 950 (Chinese Traditional) at stride 0x30 bytes each\n6. If found in predefined table:\n   a. Clear 257-byte g_abCharTypeTable with zeros\n   b. For each of 4 character categories, iterate range pairs from entry\n   c. OR flag mask (g_abCharTypeFlagMasks[category]) into table for each byte in range\n   d. Set g_fMultiByteCodePage=1, store code page and LCID\n   e. Copy 3 DWORDs from entry to g_dwCodePageInfo0/1/2\n7. If not in predefined table, call GetCPInfo():\n   a. If MaxCharSize < 2: single-byte codepage, set g_fMultiByteCodePage=0\n   b. If MaxCharSize >= 2: multibyte codepage:\n      - Mark lead byte ranges with flag 0x04 in table\n      - Mark all bytes 1-254 with flag 0x08 (potential trail bytes)\n      - Get LCID via FUN_6fc34052, set g_fMultiByteCodePage=1\n   c. Clear g_dwCodePageInfo0/1/2 to 0\n8. If GetCPInfo fails and g_fCodePageRequired=0, return -1\n9. Call FUN_6fc340ae to finalize\n10. Leave critical section and return 0\n\nParameters:\n  nLocaleCategory - Locale category specifier:\n    -3: LC_ALL (uses GetACP for ANSI code page)\n    -2: Uses GetOEMCP for OEM code page  \n    -4: Uses stored code page from DWORD_6fc3b430\n    Other: Direct code page number\n\nReturns:\n  0  - Success (code page initialized or already current)\n  -1 - Failure (GetCPInfo failed and code page required)\n\nCharacter Type Flags (g_abCharTypeFlagMasks):\n  0x01 - Category 0 flag\n  0x02 - Category 1 flag  \n  0x04 - Lead byte (multibyte first byte)\n  0x08 - Potential trail byte (bytes 1-254 in MBCS)\n\nPredefined Code Pages:\n  932 (0x3A4)  - Japanese Shift-JIS, LCID 0x411\n  936 (0x3A8)  - Chinese Simplified GB2312, LCID 0x804\n  949 (0x3B5)  - Korean, LCID 0x412\n  950 (0x3B6)  - Chinese Traditional Big5, LCID 0x404\n\nGlobal State Modified:\n  g_abCharTypeTable    - 257-byte character classification table\n  g_dwCurrentCodePage  - Currently active code page\n  g_fMultiByteCodePage - Flag: 1=multibyte, 0=single-byte\n  g_dwCodePageLCID     - Locale ID for code page\n  g_dwCodePageInfo0/1/2 - Additional code page info from predefined table",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:b7003782678f33a2ea4e8b0cc2bae15e",
      "basic_block_counts": {
        "LoD/1.07": 34,
        "LoD/1.08": 34,
        "LoD/1.09": 34,
        "LoD/1.09b": 34,
        "LoD/1.09d": 34,
        "LoD/1.10": 34
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "b7003782678f33a2ea4e8b0cc2bae15e",
        "LoD/1.08": "b7003782678f33a2ea4e8b0cc2bae15e",
        "LoD/1.09": "b7003782678f33a2ea4e8b0cc2bae15e",
        "LoD/1.09b": "b7003782678f33a2ea4e8b0cc2bae15e",
        "LoD/1.09d": "ba616fb6ea4f166e16123a36ca0958b1",
        "LoD/1.10": "ba616fb6ea4f166e16123a36ca0958b1"
      }
    },
    "d2net.dll_CRT_ResolveSpecialCodePageId": {
      "addresses": {
        "LoD/1.07": "0x6FC34008",
        "LoD/1.08": "0x6FC34008",
        "LoD/1.09": "0x6FC04008",
        "LoD/1.09b": "0x6FC04008",
        "LoD/1.09d": "0x6FC04008",
        "LoD/1.10": "0x6FC040A8"
      },
      "rvas": {
        "LoD/1.07": "0x4008",
        "LoD/1.08": "0x4008",
        "LoD/1.09": "0x4008",
        "LoD/1.09b": "0x4008",
        "LoD/1.09d": "0x4008",
        "LoD/1.10": "0x40A8"
      },
      "sizes": {
        "LoD/1.07": 74,
        "LoD/1.08": 74,
        "LoD/1.09": 74,
        "LoD/1.09b": 74,
        "LoD/1.09d": 74,
        "LoD/1.10": 74
      },
      "name": "CRT_ResolveSpecialCodePageId",
      "signature": "int CRT_ResolveSpecialCodePageId(int nCodePageOrSpecial)",
      "calling_convention": "__cdecl",
      "comment": "Resolves special code page identifiers to actual Windows code page IDs.\n\nConverts CRT special code page constants to real code page values by calling\nthe appropriate Windows API or returning a cached thread locale code page.\n\nAlgorithm:\n1. Clear g_fCodePageIsSpecial flag (AND with 0)\n2. If nCodePageOrSpecial == -2 (CP_OEMCP): Set flag=1, tail-call GetOEMCP()\n3. If nCodePageOrSpecial == -3 (CP_ACP): Set flag=1, tail-call GetACP()\n4. If nCodePageOrSpecial == -4 (CP_THREAD_ACP): Set flag=1, return g_dwThreadLocaleCodePage\n5. Otherwise: Return nCodePageOrSpecial unchanged (flag remains 0)\n\nParameters:\n  nCodePageOrSpecial (int) - Code page ID or special constant:\n    -2 = CP_OEMCP (OEM code page)\n    -3 = CP_ACP (ANSI code page)\n    -4 = CP_THREAD_ACP (thread locale code page)\n    Other = Literal code page ID (returned unchanged)\n\nReturns:\n  int - Resolved Windows code page identifier (e.g., 437, 1252)\n\nSide Effects:\n  Sets g_fCodePageIsSpecial to 1 if special constant resolved, 0 otherwise\n\nCalled By:\n  CRT_InitializeCodePageCharTypeTable - To resolve locale category to code page",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:8f2a733057dd5a290f0e17d077c53986",
      "basic_block_counts": {
        "LoD/1.07": 7,
        "LoD/1.08": 7,
        "LoD/1.09": 7,
        "LoD/1.09b": 7,
        "LoD/1.09d": 7,
        "LoD/1.10": 7
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "8f2a733057dd5a290f0e17d077c53986",
        "LoD/1.08": "8f2a733057dd5a290f0e17d077c53986",
        "LoD/1.09": "8f2a733057dd5a290f0e17d077c53986",
        "LoD/1.09b": "8f2a733057dd5a290f0e17d077c53986",
        "LoD/1.09d": "8f2a733057dd5a290f0e17d077c53986",
        "LoD/1.10": "8f2a733057dd5a290f0e17d077c53986"
      }
    },
    "d2net.dll_CRT_ConvertCodePageToLocaleId": {
      "addresses": {
        "LoD/1.07": "0x6FC34052",
        "LoD/1.08": "0x6FC34052",
        "LoD/1.09": "0x6FC04052",
        "LoD/1.09b": "0x6FC04052",
        "LoD/1.09d": "0x6FC04052",
        "LoD/1.10": "0x6FC040F2"
      },
      "rvas": {
        "LoD/1.07": "0x4052",
        "LoD/1.08": "0x4052",
        "LoD/1.09": "0x4052",
        "LoD/1.09b": "0x4052",
        "LoD/1.09d": "0x4052",
        "LoD/1.10": "0x40F2"
      },
      "sizes": {
        "LoD/1.07": 51,
        "LoD/1.08": 51,
        "LoD/1.09": 51,
        "LoD/1.09b": 51,
        "LoD/1.09d": 51,
        "LoD/1.10": 51
      },
      "name": "CRT_ConvertCodePageToLocaleId",
      "signature": "uint CRT_ConvertCodePageToLocaleId(uint nCodePage)",
      "calling_convention": "__cdecl",
      "comment": "Converts a Windows code page ID to a locale ID (LCID) for MBCS code pages.\n\nThis is a CRT helper function that maps specific multi-byte character set \ncode pages to their corresponding Windows locale identifiers. Only four \nEast Asian code pages are handled; all others return 0.\n\nAlgorithm:\n1. Check if code page is 932 (Japanese Shift-JIS)\n2. Check if code page is 936 (Simplified Chinese GBK)\n3. Check if code page is 949 (Korean)\n4. Check if code page is 950 (Traditional Chinese Big5)\n5. Return 0 for any unrecognized code page\n\nParameters:\n  nCodePage (uint): Windows code page identifier to convert\n    - 932 (0x3a4): Japanese Shift-JIS\n    - 936 (0x3a8): Simplified Chinese GBK\n    - 949 (0x3b5): Korean\n    - 950 (0x3b6): Traditional Chinese Big5\n\nReturns:\n  uint: Locale ID (LCID) corresponding to the code page\n    - 0x411 (1041): Japanese\n    - 0x804 (2052): Chinese (Simplified)\n    - 0x412 (1042): Korean\n    - 0x404 (1028): Chinese (Traditional)\n    - 0: Unsupported code page\n\nSpecial Cases:\n  - Only handles MBCS (multi-byte) East Asian code pages\n  - Single-byte code pages return 0 as they don't need LCID mapping\n\nCalled By:\n  CRT_InitializeCodePageCharTypeTable - sets DWORD_6fc3b7c4 with result",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:f31c6439952ca9c3e10694cce3d833df",
      "basic_block_counts": {
        "LoD/1.07": 9,
        "LoD/1.08": 9,
        "LoD/1.09": 9,
        "LoD/1.09b": 9,
        "LoD/1.09d": 9,
        "LoD/1.10": 9
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "f31c6439952ca9c3e10694cce3d833df",
        "LoD/1.08": "f31c6439952ca9c3e10694cce3d833df",
        "LoD/1.09": "f31c6439952ca9c3e10694cce3d833df",
        "LoD/1.09b": "f31c6439952ca9c3e10694cce3d833df",
        "LoD/1.09d": "f31c6439952ca9c3e10694cce3d833df",
        "LoD/1.10": "f31c6439952ca9c3e10694cce3d833df"
      }
    },
    "d2net.dll_CRT_ResetCharTypeTableToDefaul": {
      "addresses": {
        "LoD/1.07": "0x6FC34085",
        "LoD/1.08": "0x6FC34085",
        "LoD/1.09": "0x6FC04085",
        "LoD/1.09b": "0x6FC04085",
        "LoD/1.09d": "0x6FC04085",
        "LoD/1.10": "0x6FC04125"
      },
      "rvas": {
        "LoD/1.07": "0x4085",
        "LoD/1.08": "0x4085",
        "LoD/1.09": "0x4085",
        "LoD/1.09b": "0x4085",
        "LoD/1.09d": "0x4085",
        "LoD/1.10": "0x4125"
      },
      "sizes": {
        "LoD/1.07": 41,
        "LoD/1.08": 41,
        "LoD/1.09": 41,
        "LoD/1.09b": 41,
        "LoD/1.09d": 41,
        "LoD/1.10": 41
      },
      "name": "CRT_ResetCharTypeTableToDefault",
      "signature": "void CRT_ResetCharTypeTableToDefault(void)",
      "calling_convention": "__stdcall",
      "comment": "CRT_ResetCharTypeTableToDefault - Reset character type table to default empty state\n\nResets the multibyte character type classification table and all related code page\nglobals to their default (zero) state. Called as an error/reset handler when \nCRT_InitializeCodePageCharTypeTable encounters code page 0 or initialization failure.\n\nClassification: Leaf function (no calls), Cleanup/Reset operation\n\nAlgorithm:\n1. Clear g_abCharTypeTable (257 bytes) to zeros using REP STOSD (0x40 DWORDs) + STOSB (1 byte)\n2. Clear g_dwCurrentCodePage to 0 (no code page active)\n3. Clear g_fMultiByteCodePage to 0 (single-byte mode)\n4. Clear g_dwCodePageLCID to 0 (no locale ID)\n5. Clear g_dwCodePageInfo0/1/2 to 0 (clear predefined table info)\n\nParameters:\n  None\n\nReturns:\n  void\n\nDecompiler Variables (phantom - synthesized from REP STOSD):\n  iVar1  - Loop counter for REP STOSD (ECX register, counts down from 0x40)\n  pdVar2 - Destination pointer for STOSD (EDI register, advances through table)\n\nGlobal State Modified:\n  g_abCharTypeTable    @ 0x6fc3b6c0 - 257-byte character classification table, cleared to 0\n  g_dwCurrentCodePage  @ 0x6fc3b5ac - Code page number, set to 0\n  g_fMultiByteCodePage @ 0x6fc3b5b0 - Multibyte flag, set to 0\n  g_dwCodePageLCID     @ 0x6fc3b5b4 - Locale ID, set to 0\n  g_dwCodePageInfo0    @ 0x6fc3b5b8 - Info field 0, set to 0\n  g_dwCodePageInfo1    @ 0x6fc3b5bc - Info field 1, set to 0\n  g_dwCodePageInfo2    @ 0x6fc3b7c4 - Info field 2, set to 0\n\nCalled By:\n  CRT_InitializeCodePageCharTypeTable - When nCodePage is 0 or GetCPInfo fails\n\nImplementation Notes:\n  Uses efficient REP STOSD for bulk memory clear (0x40 iterations = 256 bytes)\n  followed by single STOSB for the 257th byte. Then uses 3 consecutive STOSD\n  instructions at 0x6fc3b5b0 to clear g_fMultiByteCodePage, g_dwCodePageLCID,\n  and g_dwCodePageInfo0 in sequence.",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:05d3556ba26e52c51954a1255d97c525",
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "05d3556ba26e52c51954a1255d97c525",
        "LoD/1.08": "05d3556ba26e52c51954a1255d97c525",
        "LoD/1.09": "05d3556ba26e52c51954a1255d97c525",
        "LoD/1.09b": "05d3556ba26e52c51954a1255d97c525",
        "LoD/1.09d": "05d3556ba26e52c51954a1255d97c525",
        "LoD/1.10": "05d3556ba26e52c51954a1255d97c525"
      }
    },
    "d2net.dll_CRT_BuildCodePageCaseTables": {
      "addresses": {
        "LoD/1.07": "0x6FC340AE",
        "LoD/1.08": "0x6FC340AE",
        "LoD/1.09": "0x6FC040AE",
        "LoD/1.09b": "0x6FC040AE",
        "LoD/1.09d": "0x6FC040AE",
        "LoD/1.10": "0x6FC0414E"
      },
      "rvas": {
        "LoD/1.07": "0x40AE",
        "LoD/1.08": "0x40AE",
        "LoD/1.09": "0x40AE",
        "LoD/1.09b": "0x40AE",
        "LoD/1.09d": "0x40AE",
        "LoD/1.10": "0x414E"
      },
      "sizes": {
        "LoD/1.07": 389,
        "LoD/1.08": 389,
        "LoD/1.09": 389,
        "LoD/1.09b": 389,
        "LoD/1.09d": 389,
        "LoD/1.10": 389
      },
      "name": "CRT_BuildCodePageCaseTables",
      "signature": "void CRT_BuildCodePageCaseTables(void)",
      "calling_convention": "__stdcall",
      "comment": "Builds case conversion and character type tables for the current code page.\n\nThis CRT initialization function populates g_abCaseConversionTable (uppercase/lowercase\nmapping) and g_abCharTypeTable (character classification flags) based on the current\ncode page or falls back to ASCII defaults if GetCPInfo fails.\n\nAlgorithm:\n1. Call GetCPInfo to get code page information (MaxCharSize, LeadByte ranges)\n2. If GetCPInfo succeeds (multi-byte code page path):\n   a. Initialize szCharTable[0..255] with identity mapping (each byte = its index)\n   b. Set szCharTable[0] = ' ' (space) as special null handling\n   c. For each lead byte range in cpInfo.LeadByte pairs:\n      - Fill range with spaces (lead bytes shouldn't be used standalone)\n      - Uses STOSD/STOSB optimization (4 bytes at a time, then remainder)\n   d. Call FUN_6fc35e07 to get character types into awCharTypes (CT_CTYPE1 flags)\n   e. Call FUN_6fc35bb8 with flag 0x100 to get uppercase conversion -> wszUpperCase\n   f. Call FUN_6fc35bb8 with flag 0x200 to get lowercase conversion -> wszLowerCase\n   g. For each character 0..255:\n      - If CT_UPPER (bit 0): set 0x10 flag in g_abCharTypeTable, store lowercase\n      - If CT_LOWER (bit 1): set 0x20 flag in g_abCharTypeTable, store uppercase\n      - Otherwise: store 0 in g_abCaseConversionTable\n3. If GetCPInfo fails (ASCII fallback path):\n   a. For each character 0..255:\n      - 'A'-'Z' (0x41-0x5A): set 0x10 flag, store lowercase (char + 0x20)\n      - 'a'-'z' (0x61-0x7A): set 0x20 flag, store uppercase (char - 0x20)\n      - Otherwise: store 0 in g_abCaseConversionTable\n\nParameters: None (uses globals g_dwCurrentCodePage, g_dwCodePageLCID)\n\nReturns: void\n\nGlobal State Modified:\n  g_abCharTypeTable[0..255]+1: Character type flags (0x10=upper, 0x20=lower)\n  g_abCaseConversionTable[0..255]: Case conversion lookup (lowercase for upper, \n                                    uppercase for lower, 0 otherwise)\n\nMagic Numbers:\n  0x100 - Character table size (256 entries)\n  0x10  - Flag for uppercase character in g_abCharTypeTable\n  0x20  - Flag for lowercase character in g_abCharTypeTable\n  0x41  - ASCII 'A'\n  0x5A  - ASCII 'Z'\n  0x61  - ASCII 'a'\n  0x7A  - ASCII 'z'\n  0x100 - LCMapString flag for uppercase conversion\n  0x200 - LCMapString flag for lowercase conversion\n\nCalled By: CRT_InitializeCodePageCharTypeTable",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:63906d1f35f7842042066a6643d2050c",
      "basic_block_counts": {
        "LoD/1.07": 29,
        "LoD/1.08": 29,
        "LoD/1.09": 29,
        "LoD/1.09b": 29,
        "LoD/1.09d": 29,
        "LoD/1.10": 29
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "63906d1f35f7842042066a6643d2050c",
        "LoD/1.08": "63906d1f35f7842042066a6643d2050c",
        "LoD/1.09": "63906d1f35f7842042066a6643d2050c",
        "LoD/1.09b": "63906d1f35f7842042066a6643d2050c",
        "LoD/1.09d": "63906d1f35f7842042066a6643d2050c",
        "LoD/1.10": "63906d1f35f7842042066a6643d2050c"
      }
    },
    "d2net.dll_CRT_InitializeCharTypeTableOnc": {
      "addresses": {
        "LoD/1.07": "0x6FC34233",
        "LoD/1.08": "0x6FC34233",
        "LoD/1.09": "0x6FC04233",
        "LoD/1.09b": "0x6FC04233",
        "LoD/1.09d": "0x6FC04233",
        "LoD/1.10": "0x6FC042D3"
      },
      "rvas": {
        "LoD/1.07": "0x4233",
        "LoD/1.08": "0x4233",
        "LoD/1.09": "0x4233",
        "LoD/1.09b": "0x4233",
        "LoD/1.09d": "0x4233",
        "LoD/1.10": "0x42D3"
      },
      "sizes": {
        "LoD/1.07": 28,
        "LoD/1.08": 28,
        "LoD/1.09": 28,
        "LoD/1.09b": 28,
        "LoD/1.09d": 28,
        "LoD/1.10": 28
      },
      "name": "CRT_InitializeCharTypeTableOnce",
      "signature": "void CRT_InitializeCharTypeTableOnce(void)",
      "calling_convention": "__stdcall",
      "comment": "CRT_InitializeCharTypeTableOnce - Guard function for one-time character type table initialization\n\nClassification: Initialization guard (ensures single execution)\n\nAlgorithm:\n1. Check g_fEnvironmentInitialized flag at 0x6fc3b8f0\n2. If flag is 0 (not initialized):\n   a. Call CRT_InitializeCodePageCharTypeTable(-3) to init ANSI code page tables\n   b. Set g_fEnvironmentInitialized = 1\n3. Return (no explicit return value, void function)\n\nParameters: None (void)\n\nReturns: void\n\nSpecial Cases:\n- Idempotent: safe to call multiple times, only executes initialization once\n- The -3 parameter to CRT_InitializeCodePageCharTypeTable specifies LC_ALL\n  which uses GetACP() to get the system ANSI code page\n\nGlobals Accessed:\n- g_fEnvironmentInitialized (0x6fc3b8f0): Read/Write - initialization guard flag\n\nCalled By:\n- CRT_SetEnvironmentStrings: Environment string table setup\n- CRT_InitCommandLineArgs: Command line argument parsing setup\n\nCallees:\n- CRT_InitializeCodePageCharTypeTable(-3): Initialize multibyte char type table for ANSI code page",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:750c71b47c1aaa7e04385ca0c70f7831",
      "basic_block_counts": {
        "LoD/1.07": 3,
        "LoD/1.08": 3,
        "LoD/1.09": 3,
        "LoD/1.09b": 3,
        "LoD/1.09d": 3,
        "LoD/1.10": 3
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "750c71b47c1aaa7e04385ca0c70f7831",
        "LoD/1.08": "750c71b47c1aaa7e04385ca0c70f7831",
        "LoD/1.09": "750c71b47c1aaa7e04385ca0c70f7831",
        "LoD/1.09b": "750c71b47c1aaa7e04385ca0c70f7831",
        "LoD/1.09d": "750c71b47c1aaa7e04385ca0c70f7831",
        "LoD/1.10": "750c71b47c1aaa7e04385ca0c70f7831"
      }
    },
    "d2net.dll_CRT_memmove": {
      "addresses": {
        "LoD/1.07": "0x6FC34250",
        "LoD/1.08": "0x6FC34250",
        "LoD/1.09": "0x6FC027C0",
        "LoD/1.09b": "0x6FC04250",
        "LoD/1.09d": "0x6FC027C0",
        "LoD/1.10": "0x6FC02860"
      },
      "rvas": {
        "LoD/1.07": "0x4250",
        "LoD/1.08": "0x4250",
        "LoD/1.09": "0x27C0",
        "LoD/1.09b": "0x4250",
        "LoD/1.09d": "0x27C0",
        "LoD/1.10": "0x2860"
      },
      "sizes": {
        "LoD/1.07": 664,
        "LoD/1.08": 664,
        "LoD/1.09": 664,
        "LoD/1.09b": 664,
        "LoD/1.09d": 664,
        "LoD/1.10": 664
      },
      "name": "CRT_memmove",
      "signature": "void * CRT_memmove(void * pDest, void * pSrc, uint cbBytes)",
      "calling_convention": "__cdecl",
      "comment": "CRT_memmove - Copy memory with overlap handling\n\nCRT runtime implementation of memmove(). Safely copies cbBytes from pSrc to pDest,\nhandling overlapping memory regions by copying backward when necessary.\n\nAlgorithm:\n1. Check for overlap: if (pSrc < pDest < pSrc + cbBytes), use backward copy\n2. For backward copy: start from end of buffers, copy toward beginning\n3. For forward copy: start from beginning, copy toward end\n4. Optimize for alignment: if destination is 4-byte aligned, use DWORD copies\n5. For unaligned destinations: copy leading bytes to reach alignment, then DWORD copy\n6. DWORD copy uses MOVSD.REP for 8+ DWORDs, unrolled loop for 1-7 DWORDs\n7. Handle trailing bytes (0-3) with byte-by-byte copy\n\nParameters:\n  pDest (void *) - Destination buffer pointer\n  pSrc (void *) - Source buffer pointer\n  cbBytes (uint) - Number of bytes to copy\n\nReturns:\n  void * - Returns pDest (original destination pointer)\n\nAlignment Optimization:\n  dest & 3 == 0: Direct DWORD copy\n  dest & 3 == 1: Copy 3 leading bytes, then DWORD copy\n  dest & 3 == 2: Copy 2 leading bytes, then DWORD copy\n  dest & 3 == 3: Copy 1 leading byte, then DWORD copy\n\nOverlap Detection:\n  Forward: pDest <= pSrc OR pDest >= pSrc + cbBytes (no overlap or dest before src)\n  Backward: pSrc < pDest < pSrc + cbBytes (dest within src region)\n\nMagic Numbers:\n  0x3 - Alignment mask for 4-byte boundary\n  0x8 - Threshold for MOVSD.REP vs unrolled loop\n  0x4 - DWORD size for pointer arithmetic",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:bff09423b51fd121ea30afec957819f4",
      "basic_block_counts": {
        "LoD/1.07": 63,
        "LoD/1.08": 63,
        "LoD/1.09": 63,
        "LoD/1.09b": 63,
        "LoD/1.09d": 63,
        "LoD/1.10": 63
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "bff09423b51fd121ea30afec957819f4",
        "LoD/1.08": "bff09423b51fd121ea30afec957819f4",
        "LoD/1.09": "bff09423b51fd121ea30afec957819f4",
        "LoD/1.09b": "bff09423b51fd121ea30afec957819f4",
        "LoD/1.09d": "bff09423b51fd121ea30afec957819f4",
        "LoD/1.10": "bff09423b51fd121ea30afec957819f4"
      }
    },
    "d2net.dll_StringToLongAutoRadix": {
      "addresses": {
        "LoD/1.07": "0x6FC34585",
        "LoD/1.08": "0x6FC34585",
        "LoD/1.09": "0x6FC04585",
        "LoD/1.09b": "0x6FC04585",
        "LoD/1.09d": "0x6FC04585",
        "LoD/1.10": "0x6FC04625"
      },
      "rvas": {
        "LoD/1.07": "0x4585",
        "LoD/1.08": "0x4585",
        "LoD/1.09": "0x4585",
        "LoD/1.09b": "0x4585",
        "LoD/1.09d": "0x4585",
        "LoD/1.10": "0x4625"
      },
      "sizes": {
        "LoD/1.07": 23,
        "LoD/1.08": 23,
        "LoD/1.09": 23,
        "LoD/1.09b": 23,
        "LoD/1.09d": 23,
        "LoD/1.10": 23
      },
      "name": "StringToLongAutoRadix",
      "signature": "long StringToLongAutoRadix(char * lpszString, char * * ppszEndPtr, int * pnError, int nRadix)",
      "calling_convention": "__cdecl",
      "comment": "Setting prototype: long StringToLongAutoRadix(char *lpszString, char **ppszEndPtr, int *pnError, int nRadix)",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:e4c337356f231e5baad169a03bc50c48",
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "e4c337356f231e5baad169a03bc50c48",
        "LoD/1.08": "e4c337356f231e5baad169a03bc50c48",
        "LoD/1.09": "e4c337356f231e5baad169a03bc50c48",
        "LoD/1.09b": "e4c337356f231e5baad169a03bc50c48",
        "LoD/1.09d": "e4c337356f231e5baad169a03bc50c48",
        "LoD/1.10": "e4c337356f231e5baad169a03bc50c48"
      }
    },
    "d2net.dll_StringToULongInternal": {
      "addresses": {
        "LoD/1.07": "0x6FC3459C",
        "LoD/1.08": "0x6FC3459C",
        "LoD/1.09": "0x6FC0459C",
        "LoD/1.09b": "0x6FC0459C",
        "LoD/1.09d": "0x6FC0459C",
        "LoD/1.10": "0x6FC0463C"
      },
      "rvas": {
        "LoD/1.07": "0x459C",
        "LoD/1.08": "0x459C",
        "LoD/1.09": "0x459C",
        "LoD/1.09b": "0x459C",
        "LoD/1.09d": "0x459C",
        "LoD/1.10": "0x463C"
      },
      "sizes": {
        "LoD/1.07": 517,
        "LoD/1.08": 517,
        "LoD/1.09": 517,
        "LoD/1.09b": 517,
        "LoD/1.09d": 517,
        "LoD/1.10": 517
      },
      "name": "StringToULongInternal",
      "signature": "ulong StringToULongInternal(byte * lpszString, byte * * ppszEndPtr, int nRadix, uint dwFlags)",
      "calling_convention": "__cdecl",
      "comment": "CRT internal string-to-unsigned-long conversion with automatic radix detection.\n\nThis is the core implementation for strtoul/strtol, parsing numeric strings\nwith support for multiple bases (2-36), sign handling, and overflow detection.\n\nAlgorithm:\n1. Skip leading whitespace using character type table (mask 0x08)\n2. Check for sign prefix: '-' sets FLAG_NEGATIVE (0x02), '+' skips\n3. Validate radix: must be 0 or 2-36, else return 0 and set endptr to start\n4. Auto-detect radix if nRadix==0:\n   - '0x'/'0X' prefix -> hex (16)\n   - '0' prefix -> octal (8)\n   - else -> decimal (10)\n5. Skip '0x'/'0X' prefix for explicit hex base\n6. Calculate overflow threshold: dwMaxDiv = 0xFFFFFFFF / nRadix\n7. Main digit loop:\n   a. Check if char is digit (mask 0x04) -> digit = char - '0'\n   b. Else check if hex digit (mask 0x103) -> digit = ToUpperCase(char) - 0x37\n   c. If digit >= radix, exit loop\n   d. Check overflow: if result > dwMaxDiv or (result == dwMaxDiv and digit > remainder), set overflow\n   e. Accumulate: result = result * radix + digit\n   f. Set FLAG_HAS_DIGITS (0x08)\n8. Finalize:\n   - If no digits parsed, reset to start position, return 0\n   - If overflow, set errno = ERANGE (0x22), clamp to appropriate max\n   - Set endptr to position after last parsed digit\n   - If negative flag set, negate result\n\nParameters:\n  lpszString - Input string to parse\n  ppszEndPtr - Output: points past last parsed character (can be NULL)\n  nRadix - Number base (0 for auto-detect, 2-36 for explicit)\n  dwFlags - Control flags, caller typically passes 0:\n    0x01 = FLAG_UNSIGNED: treat as unsigned (clamp to 0xFFFFFFFF)\n    0x02 = FLAG_NEGATIVE: negative sign encountered\n    0x04 = FLAG_OVERFLOW: overflow occurred during conversion\n    0x08 = FLAG_HAS_DIGITS: at least one digit was parsed\n\nReturns:\n  Parsed unsigned long value, or:\n  - 0 if no valid digits parsed (endptr set to lpszString)\n  - ULONG_MAX (0xFFFFFFFF) if unsigned overflow\n  - LONG_MAX (0x7FFFFFFF) or LONG_MIN (0x80000000) if signed overflow\n\nMagic Numbers:\n  0x08 - Character type mask for whitespace\n  0x04 - Character type mask for digit (0-9)\n  0x103 - Character type mask for hex digit (A-F, a-f)\n  0x2d - ASCII '-' (minus sign)\n  0x2b - ASCII '+' (plus sign)\n  0x30 - ASCII '0'\n  0x78/0x58 - ASCII 'x'/'X' for hex prefix\n  0x37 - Offset to convert 'A'-'F' to 10-15 (after ToUpperCase)\n  0x22 - ERANGE errno value\n  0x24 - Maximum radix value (36)",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:cf4bba8373cc6f7fefec3dac17cb97f9",
      "basic_block_counts": {
        "LoD/1.07": 65,
        "LoD/1.08": 65,
        "LoD/1.09": 65,
        "LoD/1.09b": 65,
        "LoD/1.09d": 65,
        "LoD/1.10": 65
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "cf4bba8373cc6f7fefec3dac17cb97f9",
        "LoD/1.08": "cf4bba8373cc6f7fefec3dac17cb97f9",
        "LoD/1.09": "cf4bba8373cc6f7fefec3dac17cb97f9",
        "LoD/1.09b": "cf4bba8373cc6f7fefec3dac17cb97f9",
        "LoD/1.09d": "cf4bba8373cc6f7fefec3dac17cb97f9",
        "LoD/1.10": "cf4bba8373cc6f7fefec3dac17cb97f9"
      }
    },
    "d2net.dll_strchr_ReturnFoundChar": {
      "addresses": {
        "LoD/1.07": "0x6FC347B0",
        "LoD/1.08": "0x6FC347B0",
        "LoD/1.09": "0x6FC047B0",
        "LoD/1.09b": "0x6FC047B0",
        "LoD/1.09d": "0x6FC047B0",
        "LoD/1.10": "0x6FC04850",
        "LoD/1.11": "0x6FBF5C90",
        "LoD/1.11b": "0x6FBF5C90",
        "LoD/1.12a": "0x6FBF5D00",
        "LoD/1.13c": "0x6FBF5D00",
        "LoD/1.13d": "0x6FBF5C90"
      },
      "rvas": {
        "LoD/1.07": "0x47B0",
        "LoD/1.08": "0x47B0",
        "LoD/1.09": "0x47B0",
        "LoD/1.09b": "0x47B0",
        "LoD/1.09d": "0x47B0",
        "LoD/1.10": "0x4850",
        "LoD/1.11": "0x5C90",
        "LoD/1.11b": "0x5C90",
        "LoD/1.12a": "0x5D00",
        "LoD/1.13c": "0x5D00",
        "LoD/1.13d": "0x5C90"
      },
      "sizes": {
        "LoD/1.07": 5,
        "LoD/1.08": 5,
        "LoD/1.09": 5,
        "LoD/1.09b": 5,
        "LoD/1.09d": 5,
        "LoD/1.10": 5,
        "LoD/1.11": 5,
        "LoD/1.11b": 5,
        "LoD/1.12a": 5,
        "LoD/1.13c": 5,
        "LoD/1.13d": 5
      },
      "name": "strchr_ReturnFoundChar",
      "signature": "char * strchr_ReturnFoundChar(int nUnused, char * lpszCurrentPos)",
      "calling_convention": "__fastcall",
      "comment": "Return epilogue fragment for _strchr alignment loop.\n\nCalled when character match found during byte-by-byte alignment phase.\nComputes return pointer by decrementing lpszCurrentPos (which was already\nincremented past the matching character at 0x6fc347da).\n\nClassification: Thunk/Fragment - shared return epilogue for _strchr\n\nAlgorithm:\n1. Compute EAX = lpszCurrentPos - 1 (adjust for post-increment)\n2. Restore EBX from caller's stack frame\n3. Return pointer to matched character\n\nParameters:\n- nUnused (ECX): Not used - inherited register state from _strchr\n- lpszCurrentPos (EDX): Pointer one past matched character position\n\nReturns:\n- char *: Pointer to the matched character in the string\n\nCaller Context:\n- Called from _strchr at 0x6fc347dd via conditional jump\n- Jump occurs when byte at [EDX] matches search character (BL)\n- EDX was incremented at 0x6fc347da before comparison\n\nNote: This is an internal fragment, not a standalone function. The POP EBX\nrestores the register saved by _strchr at 0x6fc347c6.",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:3ecdb5e459e29b4117490dc114e98574",
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1,
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "3ecdb5e459e29b4117490dc114e98574",
        "LoD/1.08": "3ecdb5e459e29b4117490dc114e98574",
        "LoD/1.09": "3ecdb5e459e29b4117490dc114e98574",
        "LoD/1.09b": "3ecdb5e459e29b4117490dc114e98574",
        "LoD/1.09d": "3ecdb5e459e29b4117490dc114e98574",
        "LoD/1.10": "3ecdb5e459e29b4117490dc114e98574",
        "LoD/1.11": "3ecdb5e459e29b4117490dc114e98574",
        "LoD/1.11b": "3ecdb5e459e29b4117490dc114e98574",
        "LoD/1.12a": "3ecdb5e459e29b4117490dc114e98574",
        "LoD/1.13c": "3ecdb5e459e29b4117490dc114e98574",
        "LoD/1.13d": "3ecdb5e459e29b4117490dc114e98574"
      }
    },
    "d2net.dll__strchr": {
      "addresses": {
        "LoD/1.07": "0x6FC347C0",
        "LoD/1.08": "0x6FC347C0",
        "LoD/1.09": "0x6FC047C0",
        "LoD/1.09b": "0x6FC047C0",
        "LoD/1.09d": "0x6FC047C0",
        "LoD/1.10": "0x6FC04860"
      },
      "rvas": {
        "LoD/1.07": "0x47C0",
        "LoD/1.08": "0x47C0",
        "LoD/1.09": "0x47C0",
        "LoD/1.09b": "0x47C0",
        "LoD/1.09d": "0x47C0",
        "LoD/1.10": "0x4860"
      },
      "sizes": {
        "LoD/1.07": 188,
        "LoD/1.08": 188,
        "LoD/1.09": 188,
        "LoD/1.09b": 188,
        "LoD/1.09d": 188,
        "LoD/1.10": 188
      },
      "name": "_strchr",
      "signature": "char * _strchr(char * _Str, int _Val)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n _strchr\n\nLibraries: Visual Studio 1998 Debug, Visual Studio 1998 Release",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:85de0cee1ebe7ed32270da528f819b99",
      "basic_block_counts": {
        "LoD/1.07": 25,
        "LoD/1.08": 25,
        "LoD/1.09": 25,
        "LoD/1.09b": 25,
        "LoD/1.09d": 25,
        "LoD/1.10": 25
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "85de0cee1ebe7ed32270da528f819b99",
        "LoD/1.08": "85de0cee1ebe7ed32270da528f819b99",
        "LoD/1.09": "85de0cee1ebe7ed32270da528f819b99",
        "LoD/1.09b": "85de0cee1ebe7ed32270da528f819b99",
        "LoD/1.09d": "85de0cee1ebe7ed32270da528f819b99",
        "LoD/1.10": "85de0cee1ebe7ed32270da528f819b99"
      }
    },
    "d2net.dll__strstr": {
      "addresses": {
        "LoD/1.07": "0x6FC34880",
        "LoD/1.08": "0x6FC34880",
        "LoD/1.09": "0x6FC04880",
        "LoD/1.09b": "0x6FC04880",
        "LoD/1.09d": "0x6FC04880",
        "LoD/1.10": "0x6FC04920"
      },
      "rvas": {
        "LoD/1.07": "0x4880",
        "LoD/1.08": "0x4880",
        "LoD/1.09": "0x4880",
        "LoD/1.09b": "0x4880",
        "LoD/1.09d": "0x4880",
        "LoD/1.10": "0x4920"
      },
      "sizes": {
        "LoD/1.07": 128,
        "LoD/1.08": 128,
        "LoD/1.09": 128,
        "LoD/1.09b": 128,
        "LoD/1.09d": 128,
        "LoD/1.10": 128
      },
      "name": "_strstr",
      "signature": "char * _strstr(char * _Str, char * _SubStr)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n _strstr\n\nLibraries: Visual Studio 1998 Debug, Visual Studio 1998 Release",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:3c60546d8cfb6e92d20e0cc9dd281ae9",
      "basic_block_counts": {
        "LoD/1.07": 18,
        "LoD/1.08": 18,
        "LoD/1.09": 18,
        "LoD/1.09b": 18,
        "LoD/1.09d": 18,
        "LoD/1.10": 18
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "3c60546d8cfb6e92d20e0cc9dd281ae9",
        "LoD/1.08": "3c60546d8cfb6e92d20e0cc9dd281ae9",
        "LoD/1.09": "3c60546d8cfb6e92d20e0cc9dd281ae9",
        "LoD/1.09b": "3c60546d8cfb6e92d20e0cc9dd281ae9",
        "LoD/1.09d": "3c60546d8cfb6e92d20e0cc9dd281ae9",
        "LoD/1.10": "3c60546d8cfb6e92d20e0cc9dd281ae9"
      }
    },
    "d2net.dll__strncmp": {
      "addresses": {
        "LoD/1.07": "0x6FC34900",
        "LoD/1.08": "0x6FC34900",
        "LoD/1.09": "0x6FC04900",
        "LoD/1.09b": "0x6FC04900",
        "LoD/1.09d": "0x6FC04900",
        "LoD/1.10": "0x6FC049A0",
        "LoD/1.11": "0x6FBF5110",
        "LoD/1.11b": "0x6FBF5110",
        "LoD/1.12a": "0x6FBF5140",
        "LoD/1.13c": "0x6FBF5140",
        "LoD/1.13d": "0x6FBF5110"
      },
      "rvas": {
        "LoD/1.07": "0x4900",
        "LoD/1.08": "0x4900",
        "LoD/1.09": "0x4900",
        "LoD/1.09b": "0x4900",
        "LoD/1.09d": "0x4900",
        "LoD/1.10": "0x49A0",
        "LoD/1.11": "0x5110",
        "LoD/1.11b": "0x5110",
        "LoD/1.12a": "0x5140",
        "LoD/1.13c": "0x5140",
        "LoD/1.13d": "0x5110"
      },
      "sizes": {
        "LoD/1.07": 56,
        "LoD/1.08": 56,
        "LoD/1.09": 56,
        "LoD/1.09b": 56,
        "LoD/1.09d": 56,
        "LoD/1.10": 56,
        "LoD/1.11": 57,
        "LoD/1.11b": 57,
        "LoD/1.12a": 57,
        "LoD/1.13c": 57,
        "LoD/1.13d": 57
      },
      "name": "_strncmp",
      "signature": "int _strncmp(char * _Str1, char * _Str2, size_t _MaxCount)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n _strncmp\n\nLibraries: Visual Studio 1998 Debug, Visual Studio 1998 Release",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:4beef3b29c3b4b805408e60c6861211a",
      "basic_block_counts": {
        "LoD/1.07": 6,
        "LoD/1.08": 6,
        "LoD/1.09": 6,
        "LoD/1.09b": 6,
        "LoD/1.09d": 6,
        "LoD/1.10": 6,
        "LoD/1.11": 6,
        "LoD/1.11b": 6,
        "LoD/1.12a": 6,
        "LoD/1.13c": 6,
        "LoD/1.13d": 6
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "4beef3b29c3b4b805408e60c6861211a",
        "LoD/1.08": "4beef3b29c3b4b805408e60c6861211a",
        "LoD/1.09": "4beef3b29c3b4b805408e60c6861211a",
        "LoD/1.09b": "4beef3b29c3b4b805408e60c6861211a",
        "LoD/1.09d": "4beef3b29c3b4b805408e60c6861211a",
        "LoD/1.10": "4beef3b29c3b4b805408e60c6861211a",
        "LoD/1.11": "1ca444181aa479bff1f1eb748b3a2663",
        "LoD/1.11b": "1ca444181aa479bff1f1eb748b3a2663",
        "LoD/1.12a": "1ca444181aa479bff1f1eb748b3a2663",
        "LoD/1.13c": "1ca444181aa479bff1f1eb748b3a2663",
        "LoD/1.13d": "1ca444181aa479bff1f1eb748b3a2663"
      }
    },
    "d2net.dll__alloca_probe": {
      "addresses": {
        "LoD/1.07": "0x6FC34940",
        "LoD/1.08": "0x6FC34940",
        "LoD/1.09": "0x6FC04940",
        "LoD/1.09b": "0x6FC04940",
        "LoD/1.09d": "0x6FC04940",
        "LoD/1.10": "0x6FC049E0"
      },
      "rvas": {
        "LoD/1.07": "0x4940",
        "LoD/1.08": "0x4940",
        "LoD/1.09": "0x4940",
        "LoD/1.09b": "0x4940",
        "LoD/1.09d": "0x4940",
        "LoD/1.10": "0x49E0"
      },
      "sizes": {
        "LoD/1.07": 47,
        "LoD/1.08": 47,
        "LoD/1.09": 47,
        "LoD/1.09b": 47,
        "LoD/1.09d": 47,
        "LoD/1.10": 47
      },
      "name": "_alloca_probe",
      "signature": "void _alloca_probe(void)",
      "calling_convention": "__stdcall",
      "comment": "Stack probe function for large stack allocations (_alloca_probe / __chkstk).\n\nAlgorithm:\n1. Save ECX (return address) on stack\n2. Compare requested size (EAX) against page size (0x1000)\n3. If size >= 0x1000, probe each page in a loop:\n   a. Decrement stack pointer by 0x1000 (one page)\n   b. Touch memory at new stack location to trigger guard page\n   c. Subtract 0x1000 from remaining size\n   d. Repeat until remaining < 0x1000\n4. Subtract final remaining bytes from stack pointer\n5. Probe the final page\n6. Move ESP to new stack location\n7. Restore saved values and return via pushed return address\n\nParameters:\n  IMPLICIT EAX - Size of stack space to allocate in bytes\n\nReturns:\n  IMPLICIT EAX - Original ESP value before allocation\n  Side effect: ESP decremented by requested allocation size\n\nSpecial Cases:\n  - Sizes < 0x1000: Single probe without loop\n  - Sizes >= 0x1000: Page-by-page probing to handle guard pages\n\nMagic Numbers:\n  0x1000 - Page size (4096 bytes), guard page boundary\n\nMemory Model:\n  This is a compiler-generated helper called automatically when local\n  variable allocation exceeds page size threshold. It ensures stack\n  guard pages are properly triggered to expand committed stack memory.\n  The function uses a non-standard calling convention where EAX passes\n  the allocation size and the return address is manipulated manually.",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:2a518bd4b0b93e6cf2e2d91eb6ff7bf6",
      "basic_block_counts": {
        "LoD/1.07": 3,
        "LoD/1.08": 3,
        "LoD/1.09": 3,
        "LoD/1.09b": 3,
        "LoD/1.09d": 3,
        "LoD/1.10": 3
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "2a518bd4b0b93e6cf2e2d91eb6ff7bf6",
        "LoD/1.08": "2a518bd4b0b93e6cf2e2d91eb6ff7bf6",
        "LoD/1.09": "2a518bd4b0b93e6cf2e2d91eb6ff7bf6",
        "LoD/1.09b": "2a518bd4b0b93e6cf2e2d91eb6ff7bf6",
        "LoD/1.09d": "2a518bd4b0b93e6cf2e2d91eb6ff7bf6",
        "LoD/1.10": "2a518bd4b0b93e6cf2e2d91eb6ff7bf6"
      }
    },
    "d2net.dll_CRT_InitializeSmallBlockHeap": {
      "addresses": {
        "LoD/1.07": "0x6FC3496F",
        "LoD/1.08": "0x6FC3496F",
        "LoD/1.09": "0x6FC0496F",
        "LoD/1.09b": "0x6FC0496F",
        "LoD/1.09d": "0x6FC0496F",
        "LoD/1.10": "0x6FC04A0F",
        "LoD/1.11": "0x6FBF3804",
        "LoD/1.11b": "0x6FBF3804",
        "LoD/1.12a": "0x6FBF383C",
        "LoD/1.13c": "0x6FBF383C",
        "LoD/1.13d": "0x6FBF3804"
      },
      "rvas": {
        "LoD/1.07": "0x496F",
        "LoD/1.08": "0x496F",
        "LoD/1.09": "0x496F",
        "LoD/1.09b": "0x496F",
        "LoD/1.09d": "0x496F",
        "LoD/1.10": "0x4A0F",
        "LoD/1.11": "0x3804",
        "LoD/1.11b": "0x3804",
        "LoD/1.12a": "0x383C",
        "LoD/1.13c": "0x383C",
        "LoD/1.13d": "0x3804"
      },
      "sizes": {
        "LoD/1.07": 72,
        "LoD/1.08": 72,
        "LoD/1.09": 72,
        "LoD/1.09b": 72,
        "LoD/1.09d": 72,
        "LoD/1.10": 72,
        "LoD/1.11": 72,
        "LoD/1.11b": 72,
        "LoD/1.12a": 72,
        "LoD/1.13c": 72,
        "LoD/1.13d": 72
      },
      "name": "CRT_InitializeSmallBlockHeap",
      "signature": "int CRT_InitializeSmallBlockHeap(dword dwMaxBlockSize)",
      "calling_convention": "__cdecl",
      "comment": "CRT_InitializeSmallBlockHeap - Initialize small block heap subsystem\n\nAllocates and initializes the region tracking array for the CRT small block\nheap allocator. The small block heap optimizes allocation of objects smaller\nthan dwMaxBlockSize by using a region-based allocation strategy.\n\nAlgorithm:\n1. Allocate 0x140 (320) bytes for region array via HeapAlloc from g_hCrtHeap\n   - Array can hold 0x10 (16) region descriptors at 0x14 (20) bytes each\n2. If allocation fails, return 0 (failure)\n3. Initialize region tracking globals:\n   - g_nRegionIndex = 0 (no regions allocated yet)\n   - g_nRegionCount = 0 (no active regions)\n   - g_pCurrentRegion = g_pRegionArray (point to start of array)\n   - g_dwSmallBlockMaxSize = dwMaxBlockSize (max size for small block alloc)\n   - g_nRegionCapacity = 0x10 (16 region slots available)\n4. Return 1 (success)\n\nParameters:\n  dwMaxBlockSize (dword) - Maximum allocation size handled by small block heap\n    Typical value: 0x3f8 (1016) bytes from CRT_InitializeHeap\n\nReturns:\n  1 - Success: Region array allocated and globals initialized\n  0 - Failure: HeapAlloc failed, heap not initialized\n\nGlobals Modified:\n  g_pRegionArray (0x6fc3b5a4) - Pointer to region descriptor array\n  g_nRegionIndex (0x6fc3b59c) - Current index into region array\n  g_nRegionCount (0x6fc3b5a0) - Count of active regions  \n  g_pCurrentRegion (0x6fc3b598) - Pointer to current region descriptor\n  g_dwSmallBlockMaxSize (0x6fc3b5a8) - Max block size threshold\n  g_nRegionCapacity (0x6fc3b590) - Maximum regions array can hold\n\nRegion Array Layout:\n  Offset  Size  Description\n  0x000   0x14  Region descriptor 0\n  0x014   0x14  Region descriptor 1\n  ...\n  0x12c   0x14  Region descriptor 15 (last slot)\n  Total: 0x140 (320) bytes for 16 descriptors\n\nCalled By: CRT_InitializeHeap when heap type is 3 (small block)",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:a57b3ae583e4f6f104245d4da8d3b9fe",
      "basic_block_counts": {
        "LoD/1.07": 3,
        "LoD/1.08": 3,
        "LoD/1.09": 3,
        "LoD/1.09b": 3,
        "LoD/1.09d": 3,
        "LoD/1.10": 3,
        "LoD/1.11": 3,
        "LoD/1.11b": 3,
        "LoD/1.12a": 3,
        "LoD/1.13c": 3,
        "LoD/1.13d": 3
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "a57b3ae583e4f6f104245d4da8d3b9fe",
        "LoD/1.08": "a57b3ae583e4f6f104245d4da8d3b9fe",
        "LoD/1.09": "a57b3ae583e4f6f104245d4da8d3b9fe",
        "LoD/1.09b": "a57b3ae583e4f6f104245d4da8d3b9fe",
        "LoD/1.09d": "a57b3ae583e4f6f104245d4da8d3b9fe",
        "LoD/1.10": "a57b3ae583e4f6f104245d4da8d3b9fe",
        "LoD/1.11": "288a4a209e4706fee9d14eabda44517a",
        "LoD/1.11b": "288a4a209e4706fee9d14eabda44517a",
        "LoD/1.12a": "288a4a209e4706fee9d14eabda44517a",
        "LoD/1.13c": "288a4a209e4706fee9d14eabda44517a",
        "LoD/1.13d": "288a4a209e4706fee9d14eabda44517a"
      }
    },
    "d2net.dll_CRT_FindRegionByAddress": {
      "addresses": {
        "LoD/1.07": "0x6FC349B7",
        "LoD/1.08": "0x6FC349B7",
        "LoD/1.09": "0x6FC049B7",
        "LoD/1.09b": "0x6FC049B7",
        "LoD/1.09d": "0x6FC049B7",
        "LoD/1.10": "0x6FC04A57",
        "LoD/1.11": "0x6FBF384C",
        "LoD/1.11b": "0x6FBF384C",
        "LoD/1.12a": "0x6FBF3884",
        "LoD/1.13c": "0x6FBF3884",
        "LoD/1.13d": "0x6FBF384C"
      },
      "rvas": {
        "LoD/1.07": "0x49B7",
        "LoD/1.08": "0x49B7",
        "LoD/1.09": "0x49B7",
        "LoD/1.09b": "0x49B7",
        "LoD/1.09d": "0x49B7",
        "LoD/1.10": "0x4A57",
        "LoD/1.11": "0x384C",
        "LoD/1.11b": "0x384C",
        "LoD/1.12a": "0x3884",
        "LoD/1.13c": "0x3884",
        "LoD/1.13d": "0x384C"
      },
      "sizes": {
        "LoD/1.07": 43,
        "LoD/1.08": 43,
        "LoD/1.09": 43,
        "LoD/1.09b": 43,
        "LoD/1.09d": 43,
        "LoD/1.10": 43,
        "LoD/1.11": 43,
        "LoD/1.11b": 43,
        "LoD/1.12a": 43,
        "LoD/1.13c": 43,
        "LoD/1.13d": 43
      },
      "name": "CRT_FindRegionByAddress",
      "signature": "dword CRT_FindRegionByAddress(void * pAddress)",
      "calling_convention": "__cdecl",
      "comment": "Searches region array for region containing the given address.\n\nIterates through the global region array (g_pRegionArray) to find which\nregion record contains the specified memory address. Each region covers\na 1MB (0x100000) address range starting from its base address.\n\nAlgorithm:\n1. Load g_pRegionArray as current pointer\n2. Calculate end pointer: g_pRegionArray + g_nRegionCount * 0x14\n3. Loop while current pointer < end pointer:\n   a. Load region base address from offset 0x0C\n   b. Check if (pAddress - base) < 0x100000 (address within 1MB range)\n   c. If within range, return current region pointer\n   d. Otherwise advance to next region (+0x14 bytes)\n4. Return 0 if no matching region found\n\nParameters:\n  pAddress - Memory address to locate in region array\n\nReturns:\n  Pointer to 20-byte region record if address found within a region\n  0 if address not within any region\n\nStructure Layout (Region Record, 0x14 bytes):\n  Offset  Size  Field         Description\n  0x00    4     unknown       Unknown field\n  0x04    4     unknown       Unknown field  \n  0x08    4     unknown       Unknown field\n  0x0C    4     dwBaseAddress Region base address\n  0x10    4     unknown       Unknown field\n\nMagic Numbers:\n  0x100000 - 1MB region size (each region covers 1MB address range)\n  0x14     - Region record stride (20 bytes per record)\n  0x0C     - Offset to base address field in region record\n\nGlobals:\n  g_pRegionArray - Pointer to array of region records\n  g_nRegionCount - Number of region records in array",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:2a0dd1f395da0f8e13609d337843c676",
      "basic_block_counts": {
        "LoD/1.07": 6,
        "LoD/1.08": 6,
        "LoD/1.09": 6,
        "LoD/1.09b": 6,
        "LoD/1.09d": 6,
        "LoD/1.10": 6,
        "LoD/1.11": 6,
        "LoD/1.11b": 6,
        "LoD/1.12a": 6,
        "LoD/1.13c": 6,
        "LoD/1.13d": 6
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "2a0dd1f395da0f8e13609d337843c676",
        "LoD/1.08": "2a0dd1f395da0f8e13609d337843c676",
        "LoD/1.09": "2a0dd1f395da0f8e13609d337843c676",
        "LoD/1.09b": "2a0dd1f395da0f8e13609d337843c676",
        "LoD/1.09d": "2a0dd1f395da0f8e13609d337843c676",
        "LoD/1.10": "2a0dd1f395da0f8e13609d337843c676",
        "LoD/1.11": "565997ae4f137ad77dea012c57abbb1d",
        "LoD/1.11b": "565997ae4f137ad77dea012c57abbb1d",
        "LoD/1.12a": "565997ae4f137ad77dea012c57abbb1d",
        "LoD/1.13c": "565997ae4f137ad77dea012c57abbb1d",
        "LoD/1.13d": "565997ae4f137ad77dea012c57abbb1d"
      }
    },
    "d2net.dll_CRT_CoalesceFreeBlock": {
      "addresses": {
        "LoD/1.07": "0x6FC349E2",
        "LoD/1.08": "0x6FC349E2",
        "LoD/1.09": "0x6FC049E2",
        "LoD/1.09b": "0x6FC049E2",
        "LoD/1.09d": "0x6FC049E2",
        "LoD/1.10": "0x6FC04A82"
      },
      "rvas": {
        "LoD/1.07": "0x49E2",
        "LoD/1.08": "0x49E2",
        "LoD/1.09": "0x49E2",
        "LoD/1.09b": "0x49E2",
        "LoD/1.09d": "0x49E2",
        "LoD/1.10": "0x4A82"
      },
      "sizes": {
        "LoD/1.07": 809,
        "LoD/1.08": 809,
        "LoD/1.09": 809,
        "LoD/1.09b": 809,
        "LoD/1.09d": 809,
        "LoD/1.10": 809
      },
      "name": "CRT_CoalesceFreeBlock",
      "signature": "void CRT_CoalesceFreeBlock(uint * pHeapState, int nBlockAddress)",
      "calling_convention": "__cdecl",
      "comment": "Coalesces a freed memory block with adjacent free blocks in the CRT heap.\n\nAlgorithm:\n1. Compute page index: (nBlockAddress - heapBase) >> 15 (32KB pages)\n2. Get block header at (nBlockAddress - 4), extract block size\n3. Check if block is already free (low bit clear) - exit if in use\n4. Check next block: If free, merge by adding sizes and unlinking from free list\n5. Check previous block: If free, merge by adding sizes and unlinking from free list\n6. Compute size class index: (combinedSize >> 4) - 1, capped at 63\n7. Insert coalesced block into appropriate size class free list\n8. Update free list bitmaps (64 bits total, split into two 32-bit words)\n9. Update size class counters at (heapData + 4 + sizeClass)\n10. Store combined size at block header and footer (boundary tags)\n11. Decrement page block count; if zero, release page via VirtualFree\n12. If all pages in region freed, release region via HeapFree\n\nParameters:\n  pHeapState  - Pointer to heap state structure containing:\n                [0]: Free list bitmap low (size classes 0-31)\n                [1]: Free list bitmap high (size classes 32-63)\n                [3]: Heap base address\n                [4]: Heap data area base\n  nBlockAddress - Address of user data portion of block being freed\n\nReturns: void\n\nStructure Layout (Free Block Header):\n  Offset  Size  Field        Description\n  -4      4     dwSize       Block size with low bit as free flag (0=free)\n  +0      4     pNext        Next block in free list (when free)\n  +4      4     pPrev        Previous block in free list (when free)\n  +size-4 4     dwSize       Footer copy of size (boundary tag)\n\nHeap Data Structure (at pHeapState[4]):\n  Offset  Size  Field        Description\n  +0x04   64    abSizeCount  Byte counts per size class (64 classes)\n  +0x44   N*4   adwBitmapLo  Low bitmap per page (size classes 0-31)\n  +0xC4   N*4   adwBitmapHi  High bitmap per page (size classes 32-63)\n  +0x144  N*0x204  Pages     Per-page free list headers\n\nSpecial Cases:\n- Block already in use (low bit set): Returns immediately without action\n- Size class > 63: Capped to 63 (largest free list bucket)\n- Last block in page: Releases 32KB page back to OS with MEM_DECOMMIT\n- Last page in region: Releases entire region, shifts region array\n\nMagic Numbers:\n  0x8000   - Page size (32KB)\n  0x4000   - MEM_DECOMMIT flag for VirtualFree\n  0x3F     - Maximum size class index (63)\n  0x20     - Boundary between low/high bitmap words\n  0x204    - Per-page structure stride\n  0x144    - Offset to first page structure\n  0x14     - Region descriptor size (20 bytes)",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:ef5171f8f7487cff01081036951ae8fa",
      "basic_block_counts": {
        "LoD/1.07": 50,
        "LoD/1.08": 50,
        "LoD/1.09": 50,
        "LoD/1.09b": 50,
        "LoD/1.09d": 50,
        "LoD/1.10": 50
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "ef5171f8f7487cff01081036951ae8fa",
        "LoD/1.08": "ef5171f8f7487cff01081036951ae8fa",
        "LoD/1.09": "ef5171f8f7487cff01081036951ae8fa",
        "LoD/1.09b": "ef5171f8f7487cff01081036951ae8fa",
        "LoD/1.09d": "ef5171f8f7487cff01081036951ae8fa",
        "LoD/1.10": "ef5171f8f7487cff01081036951ae8fa"
      }
    },
    "d2net.dll_CRT_AllocSmallBlock": {
      "addresses": {
        "LoD/1.07": "0x6FC34D0B",
        "LoD/1.08": "0x6FC34D0B",
        "LoD/1.09": "0x6FC04D0B",
        "LoD/1.09b": "0x6FC04D0B",
        "LoD/1.09d": "0x6FC04D0B",
        "LoD/1.10": "0x6FC04DAB"
      },
      "rvas": {
        "LoD/1.07": "0x4D0B",
        "LoD/1.08": "0x4D0B",
        "LoD/1.09": "0x4D0B",
        "LoD/1.09b": "0x4D0B",
        "LoD/1.09d": "0x4D0B",
        "LoD/1.10": "0x4DAB"
      },
      "sizes": {
        "LoD/1.07": 777,
        "LoD/1.08": 777,
        "LoD/1.09": 777,
        "LoD/1.09b": 777,
        "LoD/1.09d": 777,
        "LoD/1.10": 777
      },
      "name": "CRT_AllocSmallBlock",
      "signature": "void * CRT_AllocSmallBlock(uint dwRequestedSize)",
      "calling_convention": "__cdecl",
      "comment": "Allocates a small memory block from the CRT small block heap.\n\nThis is a segregated-fit allocator that maintains free lists organized by\nsize class (bucket) within regions. Uses 64 size classes (0-63) with\ntwo 32-bit bitmasks (low/high) tracking which buckets have free blocks.\n\nAlgorithm:\n1. Round requested size up to 16-byte aligned block: (size + 0x17) & 0xFFFFFFF0\n2. Calculate bucket index: (aligned_size >> 4) - 1, capped at 63\n3. Build search bitmasks: low (bits 0-31) and high (bits 32-63)\n4. Search for region with free block in suitable bucket:\n   a. First scan from g_pCurrentRegion to end of region array\n   b. If not found, scan from start to g_pCurrentRegion\n   c. If still not found, search for regions with ANY free space\n   d. If no space, call CRT_AllocateNewRegion to create new region\n5. Initialize bucket group if needed via CRT_InitializeBucketGroup\n6. Find first free block in suitable bucket using bitmap scanning\n7. Remove block from free list (doubly-linked list manipulation)\n8. If remainder after split >= 16 bytes, insert into appropriate bucket\n9. Update bucket bitmasks when adding/removing from empty buckets\n10. Mark allocated block with size+1 header/footer (low bit = allocated)\n11. Update region's active bucket index and return pointer past header\n\nParameters:\n  cbRequestedSize - Number of bytes to allocate (will be rounded up)\n\nReturns:\n  void* - Pointer to allocated memory, or NULL if allocation failed\n\nRegion Structure (20 bytes each at g_pRegionArray):\n  +0x00: dwLowBitmask   - Bits 0-31 of available bucket flags\n  +0x04: dwHighBitmask  - Bits 32-63 of available bucket flags\n  +0x08: dwFreeSpace    - Available bytes in region (0 = needs init)\n  +0x0C: pVirtualMemory - Pointer to 1MB virtual memory block\n  +0x10: pBucketInfo    - Pointer to bucket management structure\n\nBucket Info Structure (0x41C4 bytes):\n  +0x00: dwCurrentBucket - Last used bucket index (or -1)\n  +0x04: abBucketCounts[64] - Per-bucket block counts\n  +0x44: adwLowBitmask[16]  - Low bitmask per bucket group\n  +0xC4: adwHighBitmask[16] - High bitmask per bucket group\n  +0x144+: Bucket free lists (8 bytes each: next/prev pointers)\n\nBlock Header Format:\n  Size field with low bit set = allocated (size | 1)\n  Size field with low bit clear = free block size\n\nMagic Numbers:\n  0x17 - Alignment overhead (23 = 16 + header - 1)\n  0x14 - Region descriptor stride (20 bytes)\n  0x20 - Bucket threshold for high vs low bitmask\n  0x3F - Maximum bucket index (63)\n  0x81 - Bucket group stride in dwords (129 * 4 = 516 bytes)\n  0x204 - Bucket group stride in bytes\n  0x41C4 - Bucket info structure size (16836 bytes)",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:ff64648b3e6e32bc28a5e4bc8d984c1e",
      "basic_block_counts": {
        "LoD/1.07": 65,
        "LoD/1.08": 65,
        "LoD/1.09": 65,
        "LoD/1.09b": 65,
        "LoD/1.09d": 65,
        "LoD/1.10": 65
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "ff64648b3e6e32bc28a5e4bc8d984c1e",
        "LoD/1.08": "ff64648b3e6e32bc28a5e4bc8d984c1e",
        "LoD/1.09": "ff64648b3e6e32bc28a5e4bc8d984c1e",
        "LoD/1.09b": "ff64648b3e6e32bc28a5e4bc8d984c1e",
        "LoD/1.09d": "ff64648b3e6e32bc28a5e4bc8d984c1e",
        "LoD/1.10": "ff64648b3e6e32bc28a5e4bc8d984c1e"
      }
    },
    "d2net.dll_CRT_CreateRegion": {
      "addresses": {
        "LoD/1.07": "0x6FC35014",
        "LoD/1.08": "0x6FC35014",
        "LoD/1.09": "0x6FC05014",
        "LoD/1.09b": "0x6FC05014",
        "LoD/1.09d": "0x6FC05014",
        "LoD/1.10": "0x6FC050B4"
      },
      "rvas": {
        "LoD/1.07": "0x5014",
        "LoD/1.08": "0x5014",
        "LoD/1.09": "0x5014",
        "LoD/1.09b": "0x5014",
        "LoD/1.09d": "0x5014",
        "LoD/1.10": "0x50B4"
      },
      "sizes": {
        "LoD/1.07": 177,
        "LoD/1.08": 177,
        "LoD/1.09": 177,
        "LoD/1.09b": 177,
        "LoD/1.09d": 177,
        "LoD/1.10": 177
      },
      "name": "CRT_CreateRegion",
      "signature": "uint * CRT_CreateRegion(void)",
      "calling_convention": "__stdcall",
      "comment": "Creates and initializes a new memory region for the CRT small-block heap allocator.\n\nClassification: Worker function - called by CRT_AllocSmallBlock when all existing\nregions are exhausted or need expansion.\n\nAlgorithm:\n1. Load current region count (g_nRegionCount) and capacity (g_nRegionCapacity)\n2. Initialize EDI to 0 (used as NULL constant throughout)\n3. Compare count vs capacity - if equal, region array is full\n4. If full, calculate new array size: (capacity * 5 + 0x50) * 4 bytes\n5. Call HeapReAlloc to expand g_pRegionArray\n6. If realloc fails, return NULL\n7. Increment g_nRegionCapacity by 16 (0x10)\n8. Update g_pRegionArray with new pointer\n9. Calculate new region pointer: g_pRegionArray + (g_nRegionCount * 0x14)\n10. Allocate bucket management structure (0x41c4 bytes) via HeapAlloc with HEAP_ZERO_MEMORY (0x8)\n11. Store bucket structure pointer at region[4] (offset +0x10)\n12. If bucket allocation fails, return NULL\n13. Reserve 1MB virtual memory via VirtualAlloc(NULL, 0x100000, MEM_RESERVE, PAGE_READWRITE)\n14. Store virtual memory base at region[3] (offset +0xC)\n15. If virtual alloc fails, free bucket structure and return NULL\n16. Initialize region[2] (offset +0x8) to -1 (0xFFFFFFFF) - marks region as active\n17. Initialize region[0] and region[1] to 0 (low/high availability bitmasks)\n18. Increment g_nRegionCount\n19. Initialize first dword of bucket structure to -1 (no active bucket group)\n20. Return pointer to new region\n\nParameters: None\n\nReturns:\n  - Success: Pointer to newly created region structure (20 bytes)\n  - Failure: NULL (0) if any allocation fails\n\nRegion Structure Layout (0x14 / 20 bytes per region):\n  Offset  Size  Field                Type    Description\n  0x00    4     dwLowBitmask         uint    Availability bits for buckets 0-31\n  0x04    4     dwHighBitmask        uint    Availability bits for buckets 32-63\n  0x08    4     dwActiveFlag         int     -1 when active, 0 when empty\n  0x0C    4     pVirtualBase         void*   1MB reserved virtual memory base\n  0x10    4     pBucketStructure     void*   Bucket management structure (0x41c4 bytes)\n\nBucket Structure (0x41c4 bytes):\n  - First DWORD: Current bucket group index (-1 = none active)\n  - Contains 64 size classes with free lists and counters\n\nMemory Model:\n  - Uses g_hCrtHeap for bucket structure allocation\n  - Uses VirtualAlloc MEM_RESERVE for region address space\n  - Region array owned by CRT heap, grows dynamically\n  - Caller (CRT_AllocSmallBlock) manages region lifecycle\n\nMagic Numbers:\n  0x14      - Region structure stride (20 bytes)\n  0x10      - Region array growth increment (16 entries)\n  0x50      - Base array slots (80 bytes / 4 = 20 initial regions)\n  0x41c4    - Bucket structure size (16836 bytes)\n  0x100000  - Virtual memory reservation (1MB per region)\n  0x2000    - MEM_RESERVE flag\n  0x8       - HEAP_ZERO_MEMORY flag\n  0x4       - PAGE_READWRITE protection\n\nError Handling:\n  - HeapReAlloc failure: Returns NULL immediately\n  - HeapAlloc failure: Returns NULL immediately\n  - VirtualAlloc failure: Frees bucket structure, returns NULL",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:b59a8a7d2c8fdcc2aac183f01f99a847",
      "basic_block_counts": {
        "LoD/1.07": 9,
        "LoD/1.08": 9,
        "LoD/1.09": 9,
        "LoD/1.09b": 9,
        "LoD/1.09d": 9,
        "LoD/1.10": 9
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "b59a8a7d2c8fdcc2aac183f01f99a847",
        "LoD/1.08": "b59a8a7d2c8fdcc2aac183f01f99a847",
        "LoD/1.09": "b59a8a7d2c8fdcc2aac183f01f99a847",
        "LoD/1.09b": "b59a8a7d2c8fdcc2aac183f01f99a847",
        "LoD/1.09d": "b59a8a7d2c8fdcc2aac183f01f99a847",
        "LoD/1.10": "b59a8a7d2c8fdcc2aac183f01f99a847"
      }
    },
    "d2net.dll_CRT_InitBucketGroup": {
      "addresses": {
        "LoD/1.07": "0x6FC350C5",
        "LoD/1.08": "0x6FC350C5",
        "LoD/1.09": "0x6FC050C5",
        "LoD/1.09b": "0x6FC050C5",
        "LoD/1.09d": "0x6FC050C5",
        "LoD/1.10": "0x6FC05165"
      },
      "rvas": {
        "LoD/1.07": "0x50C5",
        "LoD/1.08": "0x50C5",
        "LoD/1.09": "0x50C5",
        "LoD/1.09b": "0x50C5",
        "LoD/1.09d": "0x50C5",
        "LoD/1.10": "0x5165"
      },
      "sizes": {
        "LoD/1.07": 251,
        "LoD/1.08": 251,
        "LoD/1.09": 251,
        "LoD/1.09b": 251,
        "LoD/1.09d": 251,
        "LoD/1.10": 251
      },
      "name": "CRT_InitBucketGroup",
      "signature": "int CRT_InitBucketGroup(CRT_Region * pRegion)",
      "calling_convention": "__cdecl",
      "comment": "Initializes a bucket group within a CRT memory region for small block allocation.\n\nCalled by CRT_AllocSmallBlock when no existing bucket group can satisfy an allocation.\nCreates 63 free list headers and commits 32KB of virtual memory for the bucket group.\n\nAlgorithm:\n1. Load bucket header pointer from pRegion->pBucketHeader\n2. Count leading zeros in availability bitmap (pRegion->dwLowBitmask) to find free bucket group index\n3. Calculate free list base address: index * 0x204 + 0x144 + bucketHeader\n4. Initialize 63 (0x3f) free list headers as circular linked lists (prev=next=self)\n5. Calculate virtual address: index * 0x8000 + pRegion->pVirtualBase\n6. Call VirtualAlloc to commit 32KB (0x8000) with MEM_COMMIT (0x1000) and PAGE_READWRITE (4)\n7. If VirtualAlloc fails, return -1\n8. Initialize 8 memory pages (4KB each):\n   - Set boundary markers to -1 at start and end of each page\n   - Set free block size to 0xFF0 bytes (4080 - leaves 16 bytes for headers)\n   - Link forward/backward pointers within page boundaries\n9. Link first free block (virtualBase+0xC) to free list header at freeListBase+0x1FC\n10. Link last free block (virtualBase+0x700C) to same free list header\n11. Clear allocation count at bucketHeader+0x44+index*4\n12. Set page count to 1 at bucketHeader+0xC4+index*4\n13. Increment bucket group count at bucketHeader+0x43\n14. If first bucket group (prev count was 0), set bit in pRegion->dwHighBitmask\n15. Clear availability bit in pRegion->dwLowBitmask using NOT(0x80000000 >> index)\n\nParameters:\n  pRegion - Pointer to CRT_Region structure containing:\n    +0x04: dwHighBitmask - High availability bitmask (32 bucket groups 32-63)\n    +0x08: dwLowBitmask - Low availability bitmask (32 bucket groups 0-31)\n    +0x0C: pVirtualBase - Virtual memory base address for this region\n    +0x10: pBucketHeader - Pointer to bucket header array\n\nReturns:\n  >= 0: Bucket group index that was initialized (0-31)\n  -1: VirtualAlloc failed, bucket group not initialized\n\nMagic Numbers:\n  0x3F (63): Number of free list size classes per bucket group\n  0x204 (516): Stride between bucket group descriptors in header array\n  0x144 (324): Offset to first bucket group descriptor\n  0x8000 (32768): Size of each bucket group in bytes (32KB)\n  0x1000 (4096): Page size and MEM_COMMIT flag\n  0xFF0 (4080): Usable free block size per page (4096 - 16 byte header)\n  0x1C00 (7168): Offset to last page start (7 * 0x400 dwords = 28KB)\n\nStructure Layout - Page Header (16 bytes at page start):\n  Offset  Size  Field        Description\n  0x00    4     dwBoundary   Boundary marker (-1 indicates page start)\n  0x04    4     dwFreeSize   Size of free block in page\n  0x08    4     pNext        Forward link in free list\n  0x0C    4     pPrev        Backward link in free list\n\nCalled by: CRT_AllocSmallBlock",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:0002c858ef3942a0b403454c72674bfe",
      "basic_block_counts": {
        "LoD/1.07": 14,
        "LoD/1.08": 14,
        "LoD/1.09": 14,
        "LoD/1.09b": 14,
        "LoD/1.09d": 14,
        "LoD/1.10": 14
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "0002c858ef3942a0b403454c72674bfe",
        "LoD/1.08": "0002c858ef3942a0b403454c72674bfe",
        "LoD/1.09": "0002c858ef3942a0b403454c72674bfe",
        "LoD/1.09b": "0002c858ef3942a0b403454c72674bfe",
        "LoD/1.09d": "0002c858ef3942a0b403454c72674bfe",
        "LoD/1.10": "0002c858ef3942a0b403454c72674bfe"
      }
    },
    "d2net.dll_CRT_AllocateHeapNode": {
      "addresses": {
        "LoD/1.07": "0x6FC351C0",
        "LoD/1.08": "0x6FC351C0",
        "LoD/1.09": "0x6FC051C0",
        "LoD/1.09b": "0x6FC051C0",
        "LoD/1.09d": "0x6FC051C0",
        "LoD/1.10": "0x6FC05260"
      },
      "rvas": {
        "LoD/1.07": "0x51C0",
        "LoD/1.08": "0x51C0",
        "LoD/1.09": "0x51C0",
        "LoD/1.09b": "0x51C0",
        "LoD/1.09d": "0x51C0",
        "LoD/1.10": "0x5260"
      },
      "sizes": {
        "LoD/1.07": 324,
        "LoD/1.08": 324,
        "LoD/1.09": 324,
        "LoD/1.09b": 324,
        "LoD/1.09d": 324,
        "LoD/1.10": 324
      },
      "name": "CRT_AllocateHeapNode",
      "signature": "pointer * CRT_AllocateHeapNode(void)",
      "calling_convention": "__stdcall",
      "comment": "Allocates and initializes a CRT heap node for the small block heap allocator.\n\nCLASSIFICATION: Initialization - allocates heap node structure and virtual memory region\n\nAlgorithm:\n1. Check g_dwHeapInitFlag for first-call initialization mode (-1 = use static node)\n2. If not first call, allocate 0x2020 byte node structure from CRT heap\n3. Reserve 4MB virtual memory region (MEM_RESERVE = 0x2000, PAGE_READWRITE = 4)\n4. Commit first 64KB of reserved region (MEM_COMMIT = 0x1000)\n5. Link node into doubly-linked list (g_HeapNodeListHead/g_pHeapNodeListTail)\n6. Initialize node structure fields:\n   - [+0x08] = bucket array pointer (offset +0x18)\n   - [+0x0C] = end of bucket descriptors (offset +0x98)\n   - [+0x10] = virtual base address\n   - [+0x14] = virtual end address (base + 4MB)\n7. Initialize 1024 bucket descriptors (8 bytes each):\n   - First 16 buckets: flags = 0xF0 (available)\n   - Remaining buckets: flags = 0xFFFFFFFF (uninitialized)\n   - All buckets: capacity = 0xF1\n8. Zero-fill first 64KB of virtual memory\n9. Initialize 64 page headers (4KB pages, 0x1000 stride):\n   - [+0x00] = pointer to first block (offset +8)\n   - [+0x04] = 0xF0 (available blocks)\n   - [+0xF8] = 0xFF (page sentinel)\n\nParameters: None\n\nReturns:\n  Success: Pointer to initialized heap node structure\n  Failure: NULL (0) if allocation fails\n\nMemory Layout (Heap Node Structure, 0x2020 bytes):\n  Offset  Size  Field              Description\n  0x00    4     pNext              Next node in list (-> g_HeapNodeListHead)\n  0x04    4     pPrev              Previous node in list\n  0x08    4     pBucketArray       Pointer to bucket descriptor array\n  0x0C    4     pBucketArrayEnd    End of bucket descriptors\n  0x10    4     pVirtualBase       Base of reserved virtual region\n  0x14    4     pVirtualEnd        End of virtual region (base + 4MB)\n  0x18    2048  buckets[1024]      Bucket descriptors (8 bytes each)\n\nMagic Numbers:\n  0x2020    = Heap node structure size (8224 bytes)\n  0x400000  = 4MB virtual memory reservation\n  0x10000   = 64KB initial commit size\n  0x2000    = MEM_RESERVE flag\n  0x1000    = MEM_COMMIT flag / page size\n  0x8000    = MEM_RELEASE flag\n  0xF0      = Available bucket flag\n  0xF1      = Bucket capacity / available blocks\n  0xFF      = Page sentinel marker\n\nError Handling:\n  - HeapAlloc failure: Returns NULL immediately\n  - VirtualAlloc reserve failure: Frees node, returns NULL\n  - VirtualAlloc commit failure: Releases reservation, frees node, returns NULL\n\nCalled by: CRT_InitializeHeap, FUN_6fc354b8",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:b10e654b1e0872dc227e39198444a376",
      "basic_block_counts": {
        "LoD/1.07": 22,
        "LoD/1.08": 22,
        "LoD/1.09": 22,
        "LoD/1.09b": 22,
        "LoD/1.09d": 22,
        "LoD/1.10": 22
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "b10e654b1e0872dc227e39198444a376",
        "LoD/1.08": "b10e654b1e0872dc227e39198444a376",
        "LoD/1.09": "b10e654b1e0872dc227e39198444a376",
        "LoD/1.09b": "b10e654b1e0872dc227e39198444a376",
        "LoD/1.09d": "b10e654b1e0872dc227e39198444a376",
        "LoD/1.10": "b10e654b1e0872dc227e39198444a376"
      }
    },
    "d2net.dll_CRT_FreeHeapNode": {
      "addresses": {
        "LoD/1.07": "0x6FC35304",
        "LoD/1.08": "0x6FC35304",
        "LoD/1.09": "0x6FC05304",
        "LoD/1.09b": "0x6FC05304",
        "LoD/1.09d": "0x6FC05304",
        "LoD/1.10": "0x6FC053A4"
      },
      "rvas": {
        "LoD/1.07": "0x5304",
        "LoD/1.08": "0x5304",
        "LoD/1.09": "0x5304",
        "LoD/1.09b": "0x5304",
        "LoD/1.09d": "0x5304",
        "LoD/1.10": "0x53A4"
      },
      "sizes": {
        "LoD/1.07": 86,
        "LoD/1.08": 86,
        "LoD/1.09": 86,
        "LoD/1.09b": 86,
        "LoD/1.09d": 86,
        "LoD/1.10": 86
      },
      "name": "CRT_FreeHeapNode",
      "signature": "void CRT_FreeHeapNode(void * * ppHeapNode)",
      "calling_convention": "__cdecl",
      "comment": "Frees a heap node and unlinks it from the CRT heap node doubly-linked list.\n\nAlgorithm:\n1. Release virtual memory block at node offset +0x10 using VirtualFree with MEM_RELEASE (0x8000)\n2. Check if this node is the current list head (g_pHeapNodeListHead)\n3. If list head, update g_pHeapNodeListHead to point to next node (offset +0x4)\n4. Check if node is the static sentinel (g_HeapNodeListHead at 0x6fc38950)\n5. If static sentinel, set g_dwHeapInitFlag to -1 (marks heap as uninitialized) and return\n6. Otherwise unlink node from doubly-linked list:\n   - node->next->prev = node->prev (ppHeapNode[1]->0 = ppHeapNode[0])\n   - node->prev->next = node->next (ppHeapNode[0]->4 = ppHeapNode[1])\n7. Free the node structure itself via HeapFree using g_hCrtHeap\n\nParameters:\n  ppHeapNode - Pointer to heap node structure to free. Structure layout:\n               +0x00: pPrevNode (void*) - Previous node in list\n               +0x04: pNextNode (void*) - Next node in list  \n               +0x10: pVirtualMemory (void*) - Virtual memory block to release\n\nReturns: void\n\nSpecial Cases:\n- If freeing the static list head sentinel (g_HeapNodeListHead), does not call HeapFree\n  but instead marks the heap as uninitialized via g_dwHeapInitFlag = -1\n- Always releases virtual memory regardless of whether node is sentinel\n\nCalled By: FUN_6fc3535a (heap scavenger that frees empty heap nodes)",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:54ffff5ceafbb1247d2270b70dfe4f31",
      "basic_block_counts": {
        "LoD/1.07": 5,
        "LoD/1.08": 5,
        "LoD/1.09": 5,
        "LoD/1.09b": 5,
        "LoD/1.09d": 5,
        "LoD/1.10": 5
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "54ffff5ceafbb1247d2270b70dfe4f31",
        "LoD/1.08": "54ffff5ceafbb1247d2270b70dfe4f31",
        "LoD/1.09": "54ffff5ceafbb1247d2270b70dfe4f31",
        "LoD/1.09b": "54ffff5ceafbb1247d2270b70dfe4f31",
        "LoD/1.09d": "54ffff5ceafbb1247d2270b70dfe4f31",
        "LoD/1.10": "54ffff5ceafbb1247d2270b70dfe4f31"
      }
    },
    "d2net.dll_CRT_ReleaseUnusedHeapPages": {
      "addresses": {
        "LoD/1.07": "0x6FC3535A",
        "LoD/1.08": "0x6FC3535A",
        "LoD/1.09": "0x6FC0535A",
        "LoD/1.09b": "0x6FC0535A",
        "LoD/1.09d": "0x6FC0535A",
        "LoD/1.10": "0x6FC053FA"
      },
      "rvas": {
        "LoD/1.07": "0x535A",
        "LoD/1.08": "0x535A",
        "LoD/1.09": "0x535A",
        "LoD/1.09b": "0x535A",
        "LoD/1.09d": "0x535A",
        "LoD/1.10": "0x53FA"
      },
      "sizes": {
        "LoD/1.07": 194,
        "LoD/1.08": 194,
        "LoD/1.09": 194,
        "LoD/1.09b": 194,
        "LoD/1.09d": 194,
        "LoD/1.10": 194
      },
      "name": "CRT_ReleaseUnusedHeapPages",
      "signature": "void CRT_ReleaseUnusedHeapPages(int nMaxPagesToRelease)",
      "calling_convention": "__cdecl",
      "comment": "Releases unused virtual memory pages back to the operating system.\n\nCLASSIFICATION: Worker - decommits memory pages marked as available (0xF0)\n\nAlgorithm:\n1. Start from tail of heap node linked list (g_pHeapNodeListTail)\n2. For each heap node with valid virtual base (not -1):\n   a. Initialize page release counter to 0\n   b. Iterate bucket descriptors from highest index (0x3ff) to lowest\n   c. For each bucket with flag 0xF0 (available/empty):\n      - Calculate page address: virtualBase + (bucketIndex * 0x1000)\n      - Call VirtualFree with MEM_DECOMMIT (0x4000) to release 4KB page\n      - If successful: mark bucket as -1, decrement g_dwAvailablePageCount\n      - Update first-available pointer if needed\n      - Increment release counter, decrement remaining quota\n      - Exit loop if quota exhausted\n   d. If any pages released and first bucket is -1:\n      - Scan all 1024 buckets starting from index 1\n      - If ALL buckets are -1, call CRT_FreeHeapNode to deallocate entire node\n3. Move to next node (via pPrev link) and repeat\n4. Exit when: back at tail node OR release quota exhausted\n\nParameters:\n  nMaxPagesToRelease - Maximum number of pages to decommit (quota)\n\nReturns: void\n\nHeap Node Structure offsets used:\n  [+0x04] pPrev - previous node in list\n  [+0x0C] pFirstAvailable - pointer to first available bucket\n  [+0x10] pVirtualBase - base of virtual memory region\n  [+0x18] buckets[0] - first bucket descriptor (flags at +0, capacity at +4)\n\nBucket Descriptor (8 bytes each):\n  Offset 0: flags (0xF0=available, 0xF1=in-use, -1=decommitted)\n  Offset 4: capacity value\n\nMagic Numbers:\n  0x3ff000 = Starting offset for highest page (bucket 1023 * 0x1000)\n  0x1000   = Page size (4KB)\n  0x4000   = MEM_DECOMMIT flag for VirtualFree\n  0xF0     = Bucket flag: page available for decommit\n  0x400    = Number of buckets per heap node (1024)\n  0x804    = Pointer offset: node + 6 + (0x3ff * 2) = bucket[1023]\n  -1       = Invalid/decommitted marker\n\nCalled by: FUN_6fc35473 when g_dwAvailablePageCount reaches 32",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:4356a93c484fa354f7841c9d1d714a19",
      "basic_block_counts": {
        "LoD/1.07": 20,
        "LoD/1.08": 20,
        "LoD/1.09": 20,
        "LoD/1.09b": 20,
        "LoD/1.09d": 20,
        "LoD/1.10": 20
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "4356a93c484fa354f7841c9d1d714a19",
        "LoD/1.08": "4356a93c484fa354f7841c9d1d714a19",
        "LoD/1.09": "4356a93c484fa354f7841c9d1d714a19",
        "LoD/1.09b": "4356a93c484fa354f7841c9d1d714a19",
        "LoD/1.09d": "4356a93c484fa354f7841c9d1d714a19",
        "LoD/1.10": "4356a93c484fa354f7841c9d1d714a19"
      }
    },
    "d2net.dll_CRT_LookupSmallBlockHeapNode": {
      "addresses": {
        "LoD/1.07": "0x6FC3541C",
        "LoD/1.08": "0x6FC3541C",
        "LoD/1.09": "0x6FC0541C",
        "LoD/1.09b": "0x6FC0541C",
        "LoD/1.09d": "0x6FC0541C",
        "LoD/1.10": "0x6FC054BC"
      },
      "rvas": {
        "LoD/1.07": "0x541C",
        "LoD/1.08": "0x541C",
        "LoD/1.09": "0x541C",
        "LoD/1.09b": "0x541C",
        "LoD/1.09d": "0x541C",
        "LoD/1.10": "0x54BC"
      },
      "sizes": {
        "LoD/1.07": 87,
        "LoD/1.08": 87,
        "LoD/1.09": 87,
        "LoD/1.09b": 87,
        "LoD/1.09d": 87,
        "LoD/1.10": 87
      },
      "name": "CRT_LookupSmallBlockHeapNode",
      "signature": "int CRT_LookupSmallBlockHeapNode(byte * pbBlock, void * * ppHeapNode, uint * pdwPageBase)",
      "calling_convention": "__cdecl",
      "comment": "Locates the heap node containing a memory block and calculates its slot index.\n\nSearches the small block heap node list to find which heap node owns the\ngiven block address. Returns the node pointer, page base, and computed\nslot index for use by the deallocation routines.\n\nAlgorithm:\n1. Start at g_HeapNodeListHead and iterate through linked list\n2. For each node, compare pbBlock against node's address range:\n   - pHeapNode[4] = start of managed memory\n   - pHeapNode[5] = end of managed memory\n3. If pbBlock is within range, proceed to validation\n4. If list exhausted (back at head), return 0 (not found)\n5. Validate 16-byte alignment: (pbBlock & 0xF) must be 0\n6. Validate page offset: (pbBlock & 0xFFF) must be >= 0x100\n   (blocks cannot be in page header area)\n7. Store heap node pointer to *ppHeapNode\n8. Calculate page base: pbBlock & 0xFFFFF000 (4KB boundary)\n9. Store page base to *pdwPageBase\n10. Calculate slot index: ((pbBlock - pageBase - 0x100) >> 4) + 8 + pageBase\n    - Subtract page base and header offset (0x100)\n    - Divide by 16 (shift right 4) for slot number\n    - Add 8 (skip header slots) and page base for final index\n\nParameters:\n  pbBlock     - Pointer to memory block to look up\n  ppHeapNode  - OUT: Receives pointer to owning heap node\n  pdwPageBase - OUT: Receives 4KB-aligned page base address\n\nReturns:\n  Non-zero: Slot index for the block (used by FUN_6fc35473 for deallocation)\n  0: Block not found in any heap node or validation failed\n\nSpecial Cases:\n  - Block outside all heap nodes: Returns 0\n  - Misaligned block (not 16-byte): Returns 0  \n  - Block in page header (offset < 0x100): Returns 0\n\nStructure Layout (HeapNode at g_HeapNodeListHead = 0x6fc38950):\n  Offset  Size  Field         Description\n  0x00    4     pNext         Pointer to next heap node in list\n  0x04    4     pPrev         Pointer to previous heap node\n  0x08    4     (unknown)     Reserved/unknown\n  0x0C    4     (unknown)     Reserved/unknown\n  0x10    4     pRangeStart   Start of managed memory range\n  0x14    4     pRangeEnd     End of managed memory range\n\nMagic Numbers:\n  0x0F       - 16-byte alignment mask\n  0x100      - Page header size (256 bytes)\n  0xFFF      - Page offset mask (4KB - 1)\n  0xFFFFF000 - Page base mask (4KB aligned)\n  8          - Number of header slots to skip",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:d9739637e22d71ed7283b5bc68a6c4ac",
      "basic_block_counts": {
        "LoD/1.07": 9,
        "LoD/1.08": 9,
        "LoD/1.09": 9,
        "LoD/1.09b": 9,
        "LoD/1.09d": 9,
        "LoD/1.10": 9
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "d9739637e22d71ed7283b5bc68a6c4ac",
        "LoD/1.08": "d9739637e22d71ed7283b5bc68a6c4ac",
        "LoD/1.09": "d9739637e22d71ed7283b5bc68a6c4ac",
        "LoD/1.09b": "d9739637e22d71ed7283b5bc68a6c4ac",
        "LoD/1.09d": "d9739637e22d71ed7283b5bc68a6c4ac",
        "LoD/1.10": "d9739637e22d71ed7283b5bc68a6c4ac"
      }
    },
    "d2net.dll_CRT_FreeSmallBlockPage": {
      "addresses": {
        "LoD/1.07": "0x6FC35473",
        "LoD/1.08": "0x6FC35473",
        "LoD/1.09": "0x6FC05473",
        "LoD/1.09b": "0x6FC05473",
        "LoD/1.09d": "0x6FC05473",
        "LoD/1.10": "0x6FC05513"
      },
      "rvas": {
        "LoD/1.07": "0x5473",
        "LoD/1.08": "0x5473",
        "LoD/1.09": "0x5473",
        "LoD/1.09b": "0x5473",
        "LoD/1.09d": "0x5473",
        "LoD/1.10": "0x5513"
      },
      "sizes": {
        "LoD/1.07": 69,
        "LoD/1.08": 69,
        "LoD/1.09": 69,
        "LoD/1.09b": 69,
        "LoD/1.09d": 69,
        "LoD/1.10": 69
      },
      "name": "CRT_FreeSmallBlockPage",
      "signature": "void CRT_FreeSmallBlockPage(void * pHeapNode, uint dwPageBase, byte * pbBlockStatus)",
      "calling_convention": "__cdecl",
      "comment": "Frees a block in the small block heap by updating page descriptor.\n\nCalled when CRT_HeapFree deallocates memory from the small block heap.\nUpdates page descriptor to reflect freed block count and triggers page\ncoalescing when threshold is reached.\n\nAlgorithm:\n1. Calculate page index from dwPageBase offset by shifting right 12 bits\n2. Locate page descriptor at pHeapNode plus 0x18 plus pageIndex times 8\n3. Add freed block count from pbBlockStatus to descriptor available count\n4. Clear block status byte to zero marking block as freed\n5. Set descriptor second field to 0xF1 as page modified marker\n6. Check if page fully free by comparing available count to 0xF0\n7. If fully free increment g_dwAvailablePageCount global counter\n8. If counter reaches 0x20 threshold call CRT_ReleaseUnusedHeapPages\n\nParameters:\npHeapNode - Pointer to heap node structure containing page descriptors\n            Structure offsets at 0x10 base address and 0x18 descriptor array\ndwPageBase - Base address of the page being freed for index calculation\npbBlockStatus - Pointer to block status byte with freed block count\n\nReturns:\nvoid - No return value and modifies page descriptor in place\n\nSpecial Cases:\nFull page with 0xF0 blocks triggers available page counter increment\nThreshold of 0x20 available pages triggers CRT_ReleaseUnusedHeapPages\n\nMagic Numbers:\n0x10 offset for base address field in heap node structure\n0x18 offset for page descriptor array start in heap node\n8 byte stride is size of each page descriptor entry\n12 bit shift for page size calculation with 4KB pages\n0xF0 value is maximum blocks per page at 240 blocks fully available\n0xF1 marker is page modified or freed indicator\n0x20 threshold is count triggering page release at 32 free pages\n0x10 argument is number of pages to release when threshold reached\n\nGlobals:\ng_dwAvailablePageCount tracks fully free pages awaiting release",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:ab1eb8b21e2bded2678160ac668c3175",
      "basic_block_counts": {
        "LoD/1.07": 4,
        "LoD/1.08": 4,
        "LoD/1.09": 4,
        "LoD/1.09b": 4,
        "LoD/1.09d": 4,
        "LoD/1.10": 4
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "ab1eb8b21e2bded2678160ac668c3175",
        "LoD/1.08": "ab1eb8b21e2bded2678160ac668c3175",
        "LoD/1.09": "ab1eb8b21e2bded2678160ac668c3175",
        "LoD/1.09b": "ab1eb8b21e2bded2678160ac668c3175",
        "LoD/1.09d": "ab1eb8b21e2bded2678160ac668c3175",
        "LoD/1.10": "ab1eb8b21e2bded2678160ac668c3175"
      }
    },
    "d2net.dll_CRT_SmallBlockAlloc": {
      "addresses": {
        "LoD/1.07": "0x6FC354B8",
        "LoD/1.08": "0x6FC354B8",
        "LoD/1.09": "0x6FC054B8",
        "LoD/1.09b": "0x6FC054B8",
        "LoD/1.09d": "0x6FC054B8",
        "LoD/1.10": "0x6FC05558"
      },
      "rvas": {
        "LoD/1.07": "0x54B8",
        "LoD/1.08": "0x54B8",
        "LoD/1.09": "0x54B8",
        "LoD/1.09b": "0x54B8",
        "LoD/1.09d": "0x54B8",
        "LoD/1.10": "0x5558"
      },
      "sizes": {
        "LoD/1.07": 520,
        "LoD/1.08": 520,
        "LoD/1.09": 520,
        "LoD/1.09b": 520,
        "LoD/1.09d": 520,
        "LoD/1.10": 520
      },
      "name": "CRT_SmallBlockAlloc",
      "signature": "void * CRT_SmallBlockAlloc(uint dwBlockSize)",
      "calling_convention": "__cdecl",
      "comment": "Allocates a small memory block from the CRT small block heap allocator.\n\nCLASSIFICATION: Worker function - core allocation routine for small block heap\n\nAlgorithm:\n1. Start from g_pHeapNodeListHead and iterate through heap node linked list\n2. For each node with valid virtual base (piVar7[4] != -1):\n   a. Calculate bucket descriptor pointer from node offset (+0x08)\n   b. Compute page base address: ((bucketOffset - 0x18) >> 3) * 0x1000 + virtualBase\n3. LOOP 1 - Scan buckets from current position to end of descriptor array (+0x2018):\n   a. Check if bucket has enough space: available >= dwBlockSize AND capacity > dwBlockSize\n   b. Call FUN_6fc356c0 to find/allocate block within the 4KB page\n   c. If successful, update g_pHeapNodeListHead and return block pointer\n   d. On failure, update capacity to dwBlockSize (mark bucket as insufficient)\n   e. Advance to next bucket (stride 8 bytes) and next page (+0x1000)\n4. LOOP 2 - Scan buckets from start of array (offset +0x18) to current position:\n   a. Same allocation logic as LOOP 1\n   b. Wraps around bucket array for full coverage\n5. If no space found in any node, follow linked list to next node\n6. If traversed entire list (back to head), search for uncommitted buckets:\n   a. Find node with uninitialized pages (flags == -1) and valid pBucketArrayEnd\n   b. Count consecutive uncommitted buckets (up to 16 pages max)\n   c. VirtualAlloc MEM_COMMIT the pages (local_8 << 12 bytes)\n   d. Zero-fill with _memset\n   e. Initialize page headers: sentinel (0xFF), next-block ptr, available (0xF0)\n   f. Initialize bucket descriptors: available = 0xF0, capacity = 0xF1\n7. If no uncommitted buckets, call CRT_AllocateHeapNode for new node\n8. Allocate block from newly committed/created page\n\nParameters:\n  dwBlockSize - Size of block to allocate in allocation units (1-240 range)\n\nReturns:\n  Success: Pointer to allocated block (page base + 0x100 offset)\n  Failure: NULL (0) if no memory available\n\nMemory Layout - Heap Node Structure:\n  Offset  Size  Field           Description\n  0x00    4     pNext           Next node in circular list\n  0x04    4     pPrev           Previous node in list\n  0x08    4     pBucketCurrent  Current bucket descriptor pointer\n  0x0C    4     pBucketEnd      End of bucket descriptors (first uncommitted)\n  0x10    4     pVirtualBase    Base of reserved 4MB virtual region\n  0x14    4     pVirtualEnd     End of virtual region\n  0x18    8192  buckets[1024]   Bucket descriptors (8 bytes each)\n\nMemory Layout - Bucket Descriptor (8 bytes):\n  Offset  Size  Field      Description\n  0x00    4     available  Available units in page (0xF0 = 240 initial)\n  0x04    4     capacity   Max allocation size for page (0xF1 = 241 initial)\n\nMemory Layout - Page Header (at page base):\n  Offset  Size  Field      Description\n  0x00    4     pNextFree  Pointer to next free block\n  0x04    4     nFreeUnits Available allocation units\n  0x08    1     nBlockSize Size of last allocated block\n  0xF8    1     sentinel   Page end sentinel (0xFF)\n  0x100   -     blocks     Start of allocatable block region\n\nMagic Numbers:\n  0x1000  = Page size (4KB)\n  0x2018  = End of bucket descriptor array (node + 0x18 + 1024*8)\n  0x806   = 2054 dwords = bucket array end offset in int* units\n  0xF0    = Initial available units per page (240)\n  0xF1    = Initial capacity per page (241)\n  0xFF    = Uninitialized bucket / page sentinel\n  0x100   = Block region offset from page base (256 bytes)\n  0x40    = Block offset in int* units (0x100 / 4)\n\nCalled by: CRT_HeapAlloc, CRT_Calloc",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:de76025ed2839a23b964285c7e0d5701",
      "basic_block_counts": {
        "LoD/1.07": 43,
        "LoD/1.08": 43,
        "LoD/1.09": 43,
        "LoD/1.09b": 43,
        "LoD/1.09d": 43,
        "LoD/1.10": 43
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "de76025ed2839a23b964285c7e0d5701",
        "LoD/1.08": "de76025ed2839a23b964285c7e0d5701",
        "LoD/1.09": "de76025ed2839a23b964285c7e0d5701",
        "LoD/1.09b": "de76025ed2839a23b964285c7e0d5701",
        "LoD/1.09d": "de76025ed2839a23b964285c7e0d5701",
        "LoD/1.10": "de76025ed2839a23b964285c7e0d5701"
      }
    },
    "d2net.dll_CRT_SmallBlockPageAlloc": {
      "addresses": {
        "LoD/1.07": "0x6FC356C0",
        "LoD/1.08": "0x6FC356C0",
        "LoD/1.09": "0x6FC056C0",
        "LoD/1.09b": "0x6FC056C0",
        "LoD/1.09d": "0x6FC056C0",
        "LoD/1.10": "0x6FC05760"
      },
      "rvas": {
        "LoD/1.07": "0x56C0",
        "LoD/1.08": "0x56C0",
        "LoD/1.09": "0x56C0",
        "LoD/1.09b": "0x56C0",
        "LoD/1.09d": "0x56C0",
        "LoD/1.10": "0x5760"
      },
      "sizes": {
        "LoD/1.07": 292,
        "LoD/1.08": 292,
        "LoD/1.09": 292,
        "LoD/1.09b": 292,
        "LoD/1.09d": 292,
        "LoD/1.10": 292
      },
      "name": "CRT_SmallBlockPageAlloc",
      "signature": "int CRT_SmallBlockPageAlloc(int * pPageDesc, uint dwAvailableSpace, uint dwBlockSize)",
      "calling_convention": "__cdecl",
      "comment": "Allocates a block from a small block heap page descriptor.\n\nSearches the page for a contiguous free region of dwBlockSize bytes. Each\nallocated block stores its size at offset 0, followed by user data at offset 8.\nFree regions are indicated by zero bytes; the count of consecutive zeros\ndetermines free space. Returns an encoded pointer on success, 0 on failure.\n\nAlgorithm:\n1. Get next free pointer and page boundary (pPageDesc + 0x3E = 248 bytes)\n2. If remaining space (pPageDesc[1]) >= dwBlockSize, use fast path allocation\n3. Fast path: write size byte, advance next pointer, update remaining space\n4. If at page boundary, reset next pointer to pPageDesc + 8 (allocation base)\n5. Slow path: search from pPageDesc[1] offset or allocation base\n6. Skip allocated blocks by advancing by their size byte value\n7. Count consecutive zero bytes to find free region\n8. If free region >= dwBlockSize, allocate at that position\n9. Track search budget (dwAvailableSpace) to limit scan time\n10. Return 0 if no suitable block found or budget exhausted\n11. Return encoded pointer: (blockPtr + 8) * 16 - pPageDesc * 15\n\nParameters:\n  pPageDesc - Pointer to page descriptor structure:\n              [0x00] Pointer to next free position\n              [0x04] Remaining space at next free position\n              [0x08] Start of allocation area (248 bytes total)\n              [0xF8] End boundary marker\n  dwAvailableSpace - Search budget decremented during scan\n  dwBlockSize - Size of block to allocate (1-240 bytes)\n\nReturns:\n  Non-zero encoded pointer on success\n  0 if allocation failed (no space or budget exhausted)\n\nSpecial Cases:\n  - Block size stored as single byte (max 255)\n  - Page boundary at offset 0xF8 (248 bytes from base)\n  - Reset to base when next pointer reaches boundary",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:4f3543287939943021eaf1632a1582f1",
      "basic_block_counts": {
        "LoD/1.07": 41,
        "LoD/1.08": 41,
        "LoD/1.09": 41,
        "LoD/1.09b": 41,
        "LoD/1.09d": 41,
        "LoD/1.10": 41
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "4f3543287939943021eaf1632a1582f1",
        "LoD/1.08": "4f3543287939943021eaf1632a1582f1",
        "LoD/1.09": "4f3543287939943021eaf1632a1582f1",
        "LoD/1.09b": "4f3543287939943021eaf1632a1582f1",
        "LoD/1.09d": "4f3543287939943021eaf1632a1582f1",
        "LoD/1.10": "4f3543287939943021eaf1632a1582f1"
      }
    },
    "d2net.dll_CrtShowMessageBox": {
      "addresses": {
        "LoD/1.07": "0x6FC357E4",
        "LoD/1.08": "0x6FC357E4",
        "LoD/1.09": "0x6FC057E4",
        "LoD/1.09b": "0x6FC057E4",
        "LoD/1.09d": "0x6FC057E4",
        "LoD/1.10": "0x6FC05884"
      },
      "rvas": {
        "LoD/1.07": "0x57E4",
        "LoD/1.08": "0x57E4",
        "LoD/1.09": "0x57E4",
        "LoD/1.09b": "0x57E4",
        "LoD/1.09d": "0x57E4",
        "LoD/1.10": "0x5884"
      },
      "sizes": {
        "LoD/1.07": 137,
        "LoD/1.08": 137,
        "LoD/1.09": 137,
        "LoD/1.09b": 137,
        "LoD/1.09d": 137,
        "LoD/1.10": 137
      },
      "name": "CrtShowMessageBox",
      "signature": "int CrtShowMessageBox(char * lpszText, char * lpszCaption, int nType)",
      "calling_convention": "__cdecl",
      "comment": "Displays a message box by dynamically loading user32.dll and calling MessageBoxA.\n\nThis is a CRT runtime helper that lazily loads the MessageBox API to avoid linking\nuser32.dll statically. It caches function pointers for repeated calls.\n\nCLASSIFICATION: Worker function - provides MessageBox functionality without static linkage\n\nAlgorithm:\n  1. Check if g_pfnMessageBoxA is already cached\n  2. If not cached, load user32.dll via LoadLibraryA\n  3. If load fails, return 0\n  4. Get address of MessageBoxA via GetProcAddress and cache in g_pfnMessageBoxA\n  5. If GetProcAddress fails, return 0\n  6. Get addresses of GetActiveWindow and GetLastActivePopup, cache in globals\n  7. If g_pfnGetActiveWindow is valid, call it to get active window handle\n  8. If active window exists and g_pfnGetLastActivePopup is valid, get last popup\n  9. Call MessageBoxA with hwnd, text, caption, and type parameters\n  10. Return MessageBoxA result\n\nParameters:\n  lpszText - [in] Message box body text (passed to MessageBoxA)\n  lpszCaption - [in] Message box title/caption (passed to MessageBoxA)\n  nType - [in] Message box style flags (MB_OK, MB_YESNO, etc.)\n\nReturns:\n  int - MessageBoxA return value (button clicked: IDOK, IDYES, etc.)\n        Returns 0 if user32.dll load fails or MessageBoxA not found\n\nCalled By:\n  CrtDisplayRuntimeError (0x6fc3394f) - displays runtime error dialogs\n\nGlobal State:\n  g_pfnMessageBoxA (0x6fc3b404) - Cached pointer to MessageBoxA\n  g_pfnGetActiveWindow (0x6fc3b408) - Cached pointer to GetActiveWindow\n  g_pfnGetLastActivePopup (0x6fc3b40c) - Cached pointer to GetLastActivePopup",
      "name_source": "LoD/1.07",
      "method": "STR",
      "index": "STR:f59c01a33eca433430cfbab05d487108",
      "strings": {
        "LoD/1.07": [
          "\"user32.dll\"",
          "\"MessageBoxA\"",
          "\"GetActiveWindow\""
        ],
        "LoD/1.08": [
          "\"user32.dll\"",
          "\"MessageBoxA\"",
          "\"GetActiveWindow\""
        ],
        "LoD/1.09": [
          "\"user32.dll\"",
          "\"MessageBoxA\"",
          "\"GetActiveWindow\""
        ],
        "LoD/1.09b": [
          "\"user32.dll\"",
          "\"MessageBoxA\"",
          "\"GetActiveWindow\""
        ],
        "LoD/1.09d": [
          "\"user32.dll\"",
          "\"MessageBoxA\"",
          "\"GetActiveWindow\""
        ],
        "LoD/1.10": [
          "\"user32.dll\"",
          "\"MessageBoxA\"",
          "\"GetActiveWindow\""
        ]
      },
      "basic_block_counts": {
        "LoD/1.07": 11,
        "LoD/1.08": 11,
        "LoD/1.09": 11,
        "LoD/1.09b": 11,
        "LoD/1.09d": 11,
        "LoD/1.10": 11
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "d28466b802ff41201d4ac81308d22266",
        "LoD/1.08": "d28466b802ff41201d4ac81308d22266",
        "LoD/1.09": "d28466b802ff41201d4ac81308d22266",
        "LoD/1.09b": "d28466b802ff41201d4ac81308d22266",
        "LoD/1.09d": "d28466b802ff41201d4ac81308d22266",
        "LoD/1.10": "d28466b802ff41201d4ac81308d22266"
      }
    },
    "d2net.dll__strncpy": {
      "addresses": {
        "LoD/1.07": "0x6FC35870",
        "LoD/1.08": "0x6FC35870",
        "LoD/1.09": "0x6FC05870",
        "LoD/1.09b": "0x6FC05870",
        "LoD/1.09d": "0x6FC05870",
        "LoD/1.10": "0x6FC05910",
        "LoD/1.11": "0x6FBF4980",
        "LoD/1.11b": "0x6FBF4980",
        "LoD/1.12a": "0x6FBF49B0",
        "LoD/1.13c": "0x6FBF49B0",
        "LoD/1.13d": "0x6FBF4980"
      },
      "rvas": {
        "LoD/1.07": "0x5870",
        "LoD/1.08": "0x5870",
        "LoD/1.09": "0x5870",
        "LoD/1.09b": "0x5870",
        "LoD/1.09d": "0x5870",
        "LoD/1.10": "0x5910",
        "LoD/1.11": "0x4980",
        "LoD/1.11b": "0x4980",
        "LoD/1.12a": "0x49B0",
        "LoD/1.13c": "0x49B0",
        "LoD/1.13d": "0x4980"
      },
      "sizes": {
        "LoD/1.07": 254,
        "LoD/1.08": 254,
        "LoD/1.09": 254,
        "LoD/1.09b": 254,
        "LoD/1.09d": 254,
        "LoD/1.10": 254,
        "LoD/1.11": 292,
        "LoD/1.11b": 292,
        "LoD/1.12a": 292,
        "LoD/1.13c": 292,
        "LoD/1.13d": 292
      },
      "name": "_strncpy",
      "signature": "char * _strncpy(char * _Dest, char * _Source, size_t _Count)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n _strncpy\n\nLibraries: Visual Studio 1998 Debug, Visual Studio 1998 Release",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:60fb4369558c571ee3e9892006835a82",
      "basic_block_counts": {
        "LoD/1.07": 35,
        "LoD/1.08": 35,
        "LoD/1.09": 35,
        "LoD/1.09b": 35,
        "LoD/1.09d": 35,
        "LoD/1.10": 35,
        "LoD/1.11": 35,
        "LoD/1.11b": 35,
        "LoD/1.12a": 35,
        "LoD/1.13c": 35,
        "LoD/1.13d": 35
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "60fb4369558c571ee3e9892006835a82",
        "LoD/1.08": "60fb4369558c571ee3e9892006835a82",
        "LoD/1.09": "60fb4369558c571ee3e9892006835a82",
        "LoD/1.09b": "60fb4369558c571ee3e9892006835a82",
        "LoD/1.09d": "60fb4369558c571ee3e9892006835a82",
        "LoD/1.10": "60fb4369558c571ee3e9892006835a82",
        "LoD/1.11": "3c09a404c09b60148d7501f511aba84d",
        "LoD/1.11b": "3c09a404c09b60148d7501f511aba84d",
        "LoD/1.12a": "3c09a404c09b60148d7501f511aba84d",
        "LoD/1.13c": "3c09a404c09b60148d7501f511aba84d",
        "LoD/1.13d": "3c09a404c09b60148d7501f511aba84d"
      }
    },
    "d2net.dll___global_unwind2": {
      "addresses": {
        "LoD/1.07": "0x6FC35970",
        "LoD/1.08": "0x6FC35970",
        "LoD/1.09": "0x6FC05970",
        "LoD/1.09b": "0x6FC05970",
        "LoD/1.09d": "0x6FC05970",
        "LoD/1.10": "0x6FC05A10",
        "LoD/1.11": "0x6FBF2C1C",
        "LoD/1.11b": "0x6FBF2C1C",
        "LoD/1.12a": "0x6FBF2C3C",
        "LoD/1.13c": "0x6FBF2C3C",
        "LoD/1.13d": "0x6FBF2C1C"
      },
      "rvas": {
        "LoD/1.07": "0x5970",
        "LoD/1.08": "0x5970",
        "LoD/1.09": "0x5970",
        "LoD/1.09b": "0x5970",
        "LoD/1.09d": "0x5970",
        "LoD/1.10": "0x5A10",
        "LoD/1.11": "0x2C1C",
        "LoD/1.11b": "0x2C1C",
        "LoD/1.12a": "0x2C3C",
        "LoD/1.13c": "0x2C3C",
        "LoD/1.13d": "0x2C1C"
      },
      "sizes": {
        "LoD/1.07": 32,
        "LoD/1.08": 32,
        "LoD/1.09": 32,
        "LoD/1.09b": 32,
        "LoD/1.09d": 32,
        "LoD/1.10": 32,
        "LoD/1.11": 32,
        "LoD/1.11b": 32,
        "LoD/1.12a": 32,
        "LoD/1.13c": 32,
        "LoD/1.13d": 32
      },
      "name": "__global_unwind2",
      "signature": "void __global_unwind2(PVOID param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __global_unwind2\n\nLibrary: Visual Studio",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:059e9bb2efc1de93bfe21089d0ad96d3",
      "callees": {
        "LoD/1.07": [
          "RtlUnwind"
        ],
        "LoD/1.08": [
          "RtlUnwind"
        ],
        "LoD/1.09": [
          "RtlUnwind"
        ],
        "LoD/1.09b": [
          "RtlUnwind"
        ],
        "LoD/1.09d": [
          "RtlUnwind"
        ],
        "LoD/1.10": [
          "RtlUnwind"
        ],
        "LoD/1.11": [
          "RtlUnwind"
        ],
        "LoD/1.11b": [
          "RtlUnwind"
        ],
        "LoD/1.12a": [
          "RtlUnwind"
        ],
        "LoD/1.13c": [
          "RtlUnwind"
        ],
        "LoD/1.13d": [
          "RtlUnwind"
        ]
      },
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1,
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "059e9bb2efc1de93bfe21089d0ad96d3",
        "LoD/1.08": "059e9bb2efc1de93bfe21089d0ad96d3",
        "LoD/1.09": "059e9bb2efc1de93bfe21089d0ad96d3",
        "LoD/1.09b": "059e9bb2efc1de93bfe21089d0ad96d3",
        "LoD/1.09d": "059e9bb2efc1de93bfe21089d0ad96d3",
        "LoD/1.10": "059e9bb2efc1de93bfe21089d0ad96d3",
        "LoD/1.11": "059e9bb2efc1de93bfe21089d0ad96d3",
        "LoD/1.11b": "059e9bb2efc1de93bfe21089d0ad96d3",
        "LoD/1.12a": "059e9bb2efc1de93bfe21089d0ad96d3",
        "LoD/1.13c": "059e9bb2efc1de93bfe21089d0ad96d3",
        "LoD/1.13d": "059e9bb2efc1de93bfe21089d0ad96d3"
      }
    },
    "d2net.dll___local_unwind2": {
      "addresses": {
        "LoD/1.07": "0x6FC359B2",
        "LoD/1.08": "0x6FC359B2",
        "LoD/1.09": "0x6FC059B2",
        "LoD/1.09b": "0x6FC059B2",
        "LoD/1.09d": "0x6FC059B2",
        "LoD/1.10": "0x6FC05A52",
        "LoD/1.11": "0x6FBF2C5E",
        "LoD/1.11b": "0x6FBF2C5E",
        "LoD/1.12a": "0x6FBF2C7E",
        "LoD/1.13c": "0x6FBF2C7E",
        "LoD/1.13d": "0x6FBF2C5E"
      },
      "rvas": {
        "LoD/1.07": "0x59B2",
        "LoD/1.08": "0x59B2",
        "LoD/1.09": "0x59B2",
        "LoD/1.09b": "0x59B2",
        "LoD/1.09d": "0x59B2",
        "LoD/1.10": "0x5A52",
        "LoD/1.11": "0x2C5E",
        "LoD/1.11b": "0x2C5E",
        "LoD/1.12a": "0x2C7E",
        "LoD/1.13c": "0x2C7E",
        "LoD/1.13d": "0x2C5E"
      },
      "sizes": {
        "LoD/1.07": 104,
        "LoD/1.08": 104,
        "LoD/1.09": 104,
        "LoD/1.09b": 104,
        "LoD/1.09d": 104,
        "LoD/1.10": 104,
        "LoD/1.11": 104,
        "LoD/1.11b": 104,
        "LoD/1.12a": 104,
        "LoD/1.13c": 104,
        "LoD/1.13d": 104
      },
      "name": "__local_unwind2",
      "signature": "void __local_unwind2(int param_1, int param_2)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __local_unwind2\n\nLibraries: Visual Studio 1998 Debug, Visual Studio 1998 Release, Visual Studio 2003 Debug, Visual Studio 2003 Release",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:cd4ab8e23ed6997cd2e2434b8d375458",
      "basic_block_counts": {
        "LoD/1.07": 7,
        "LoD/1.08": 7,
        "LoD/1.09": 7,
        "LoD/1.09b": 7,
        "LoD/1.09d": 7,
        "LoD/1.10": 7,
        "LoD/1.11": 7,
        "LoD/1.11b": 7,
        "LoD/1.12a": 7,
        "LoD/1.13c": 7,
        "LoD/1.13d": 7
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "cd4ab8e23ed6997cd2e2434b8d375458",
        "LoD/1.08": "cd4ab8e23ed6997cd2e2434b8d375458",
        "LoD/1.09": "cd4ab8e23ed6997cd2e2434b8d375458",
        "LoD/1.09b": "cd4ab8e23ed6997cd2e2434b8d375458",
        "LoD/1.09d": "cd4ab8e23ed6997cd2e2434b8d375458",
        "LoD/1.10": "cd4ab8e23ed6997cd2e2434b8d375458",
        "LoD/1.11": "cd4ab8e23ed6997cd2e2434b8d375458",
        "LoD/1.11b": "cd4ab8e23ed6997cd2e2434b8d375458",
        "LoD/1.12a": "cd4ab8e23ed6997cd2e2434b8d375458",
        "LoD/1.13c": "cd4ab8e23ed6997cd2e2434b8d375458",
        "LoD/1.13d": "cd4ab8e23ed6997cd2e2434b8d375458"
      }
    },
    "d2net.dll_SehSaveExceptionContext": {
      "addresses": {
        "LoD/1.07": "0x6FC35A46",
        "LoD/1.08": "0x6FC35A46",
        "LoD/1.09": "0x6FC05A46",
        "LoD/1.09b": "0x6FC05A46",
        "LoD/1.09d": "0x6FC05A46",
        "LoD/1.10": "0x6FC05AE6",
        "LoD/1.11": "0x6FBF2CF2",
        "LoD/1.11b": "0x6FBF2CF2",
        "LoD/1.12a": "0x6FBF2D12",
        "LoD/1.13c": "0x6FBF2D12",
        "LoD/1.13d": "0x6FBF2CF2"
      },
      "rvas": {
        "LoD/1.07": "0x5A46",
        "LoD/1.08": "0x5A46",
        "LoD/1.09": "0x5A46",
        "LoD/1.09b": "0x5A46",
        "LoD/1.09d": "0x5A46",
        "LoD/1.10": "0x5AE6",
        "LoD/1.11": "0x2CF2",
        "LoD/1.11b": "0x2CF2",
        "LoD/1.12a": "0x2D12",
        "LoD/1.13c": "0x2D12",
        "LoD/1.13d": "0x2CF2"
      },
      "sizes": {
        "LoD/1.07": 24,
        "LoD/1.08": 24,
        "LoD/1.09": 24,
        "LoD/1.09b": 24,
        "LoD/1.09d": 24,
        "LoD/1.10": 24,
        "LoD/1.11": 24,
        "LoD/1.11b": 24,
        "LoD/1.12a": 24,
        "LoD/1.13c": 24,
        "LoD/1.13d": 24
      },
      "name": "SehSaveExceptionContext",
      "signature": "void SehSaveExceptionContext(void)",
      "calling_convention": "__stdcall",
      "comment": "SehSaveExceptionContext - Saves exception context before filter/handler execution\n\nCalled by __local_unwind2 before invoking exception filter or handler code.\nCaptures caller context to global structure for SEH runtime support.\n\nParameters:\n  IMPLICIT EAX - Filter result or handler state value (uint)\n  IMPLICIT EBP - Current stack frame pointer (uint)\n  IMPLICIT [EBP+8] - Return address from exception frame (uint)\n\nReturns:\n  void - No return value; context saved to g_SehExceptionContext\n\nAlgorithm:\n1. Load base address of g_SehExceptionContext (0x6fc3a980) into EBX\n2. Save [EBP+8] (return address) to dwReturnAddress field (offset +8)\n3. Save EAX (filter result) to dwFilterResult field (offset +4)\n4. Save EBP (frame pointer) to dwFramePointer field (offset +12)\n5. Return to caller, popping 4 bytes (RET 0x4)\n\nStructure Layout - SehExceptionContext (16 bytes):\n  Offset  Size  Field            Type  Description\n  0x00    4     dwReserved       uint  Reserved/unused\n  0x04    4     dwFilterResult   uint  EAX value (filter result)\n  0x08    4     dwReturnAddress  uint  Return address from [EBP+8]\n  0x0C    4     dwFramePointer   uint  EBP frame pointer\n\nCallers: __local_unwind2 (SEH unwinding)",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:ed17ad9d511f6e330c2b6a62378d83cf",
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1,
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "ed17ad9d511f6e330c2b6a62378d83cf",
        "LoD/1.08": "ed17ad9d511f6e330c2b6a62378d83cf",
        "LoD/1.09": "ed17ad9d511f6e330c2b6a62378d83cf",
        "LoD/1.09b": "ed17ad9d511f6e330c2b6a62378d83cf",
        "LoD/1.09d": "ed17ad9d511f6e330c2b6a62378d83cf",
        "LoD/1.10": "ed17ad9d511f6e330c2b6a62378d83cf",
        "LoD/1.11": "ed17ad9d511f6e330c2b6a62378d83cf",
        "LoD/1.11b": "ed17ad9d511f6e330c2b6a62378d83cf",
        "LoD/1.12a": "ed17ad9d511f6e330c2b6a62378d83cf",
        "LoD/1.13c": "ed17ad9d511f6e330c2b6a62378d83cf",
        "LoD/1.13d": "ed17ad9d511f6e330c2b6a62378d83cf"
      }
    },
    "d2net.dll_SehUnwindHelper": {
      "addresses": {
        "LoD/1.07": "0x6FC35B25",
        "LoD/1.08": "0x6FC35B25",
        "LoD/1.09": "0x6FC05B25",
        "LoD/1.09b": "0x6FC05B25",
        "LoD/1.09d": "0x6FC05B25",
        "LoD/1.10": "0x6FC05BC5",
        "LoD/1.11": "0x6FBF1BC6",
        "LoD/1.11b": "0x6FBF1BC6",
        "LoD/1.12a": "0x6FBF1BCE",
        "LoD/1.13c": "0x6FBF1BC6",
        "LoD/1.13d": "0x6FBF1BCE"
      },
      "rvas": {
        "LoD/1.07": "0x5B25",
        "LoD/1.08": "0x5B25",
        "LoD/1.09": "0x5B25",
        "LoD/1.09b": "0x5B25",
        "LoD/1.09d": "0x5B25",
        "LoD/1.10": "0x5BC5",
        "LoD/1.11": "0x1BC6",
        "LoD/1.11b": "0x1BC6",
        "LoD/1.12a": "0x1BCE",
        "LoD/1.13c": "0x1BC6",
        "LoD/1.13d": "0x1BCE"
      },
      "sizes": {
        "LoD/1.07": 27,
        "LoD/1.08": 27,
        "LoD/1.09": 27,
        "LoD/1.09b": 27,
        "LoD/1.09d": 27,
        "LoD/1.10": 27,
        "LoD/1.11": 27,
        "LoD/1.11b": 27,
        "LoD/1.12a": 27,
        "LoD/1.13c": 27,
        "LoD/1.13d": 27
      },
      "name": "SehUnwindHelper",
      "signature": "void SehUnwindHelper(void * pExceptionFrame)",
      "calling_convention": "__stdcall",
      "comment": "SEH exception handler unwind helper thunk.\n\nExtracts scope table and try level from the exception registration frame\nand calls __local_unwind2 to perform stack unwinding during exception handling.\n\nAlgorithm:\n1. Save EBP (standard SEH frame setup)\n2. Load exception frame pointer from stack parameter\n3. Dereference [pExceptionFrame+0x00] to load EBP (frame base)\n4. Extract scope table pointer from [pExceptionFrame+0x18]\n5. Extract target try level from [pExceptionFrame+0x1c]\n6. Call __local_unwind2(scopeTable, tryLevel) to unwind\n7. Restore EBP and return\n\nParameters:\n  pExceptionFrame (void *): Pointer to EXCEPTION_REGISTRATION structure\n    +0x00: EBP - Base frame pointer\n    +0x18: Scope table pointer for unwinding\n    +0x1c: Target try level to unwind to\n\nReturns:\n  void - No return value\n\nClassification: Thunk/Wrapper for __local_unwind2\n\nCalled by: SEH exception dispatch mechanism (no direct xrefs - callback)",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:89d1b619054116ad559c7c543db397fd",
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1,
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "89d1b619054116ad559c7c543db397fd",
        "LoD/1.08": "89d1b619054116ad559c7c543db397fd",
        "LoD/1.09": "89d1b619054116ad559c7c543db397fd",
        "LoD/1.09b": "89d1b619054116ad559c7c543db397fd",
        "LoD/1.09d": "89d1b619054116ad559c7c543db397fd",
        "LoD/1.10": "89d1b619054116ad559c7c543db397fd",
        "LoD/1.11": "89d1b619054116ad559c7c543db397fd",
        "LoD/1.11b": "89d1b619054116ad559c7c543db397fd",
        "LoD/1.12a": "89d1b619054116ad559c7c543db397fd",
        "LoD/1.13c": "89d1b619054116ad559c7c543db397fd",
        "LoD/1.13d": "89d1b619054116ad559c7c543db397fd"
      }
    },
    "d2net.dll_CRT_InvokeNewHandler": {
      "addresses": {
        "LoD/1.07": "0x6FC35B40",
        "LoD/1.08": "0x6FC35B40",
        "LoD/1.09": "0x6FC05B40",
        "LoD/1.09b": "0x6FC05B40",
        "LoD/1.09d": "0x6FC05B40",
        "LoD/1.10": "0x6FC05BE0",
        "LoD/1.11": "0x6FBF4327",
        "LoD/1.11b": "0x6FBF4327",
        "LoD/1.12a": "0x6FBF435F",
        "LoD/1.13c": "0x6FBF435F",
        "LoD/1.13d": "0x6FBF4327"
      },
      "rvas": {
        "LoD/1.07": "0x5B40",
        "LoD/1.08": "0x5B40",
        "LoD/1.09": "0x5B40",
        "LoD/1.09b": "0x5B40",
        "LoD/1.09d": "0x5B40",
        "LoD/1.10": "0x5BE0",
        "LoD/1.11": "0x4327",
        "LoD/1.11b": "0x4327",
        "LoD/1.12a": "0x435F",
        "LoD/1.13c": "0x435F",
        "LoD/1.13d": "0x4327"
      },
      "sizes": {
        "LoD/1.07": 27,
        "LoD/1.08": 27,
        "LoD/1.09": 27,
        "LoD/1.09b": 27,
        "LoD/1.09d": 27,
        "LoD/1.10": 27,
        "LoD/1.11": 27,
        "LoD/1.11b": 27,
        "LoD/1.12a": 27,
        "LoD/1.13c": 27,
        "LoD/1.13d": 27
      },
      "name": "CRT_InvokeNewHandler",
      "signature": "int CRT_InvokeNewHandler(dword dwRequestedSize)",
      "calling_convention": "__cdecl",
      "comment": "CRT_InvokeNewHandler - Invoke registered new handler callback for OOM recovery\n\nChecks if a new handler callback function is registered in g_pfnNewHandler.\nIf registered, calls the handler with the requested allocation size to allow\napplication-level memory recovery (e.g., freeing caches, compacting heap).\n\nAlgorithm:\n1. Load g_pfnNewHandler function pointer\n2. If NULL, return 0 (no handler registered)\n3. Call handler with dwRequestedSize parameter\n4. If handler returns non-zero (success), return 1\n5. If handler returns 0 (failure), return 0\n\nParameters:\n  dwRequestedSize (dword) - Size in bytes of failed allocation request\n\nReturns:\n  int - 1 if new handler succeeded (retry allocation), 0 if no handler or handler failed\n\nCallers:\n  CRT_Calloc - Calls after HeapAlloc fails to attempt recovery\n  __nh_malloc - Calls in retry loop when allocation fails\n\nGlobals Referenced:\n  g_pfnNewHandler (0x6fc3b414) - Function pointer to registered new handler callback\n                                 Set by _set_new_handler() CRT function\n\nNotes:\n  The new handler mechanism is part of C++ operator new semantics.\n  When allocation fails, the handler can free memory or throw std::bad_alloc.\n  Returning non-zero signals the allocator should retry the allocation.",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:ee4facdaccbd6fc5f3297fd5b85b73c2",
      "basic_block_counts": {
        "LoD/1.07": 4,
        "LoD/1.08": 4,
        "LoD/1.09": 4,
        "LoD/1.09b": 4,
        "LoD/1.09d": 4,
        "LoD/1.10": 4,
        "LoD/1.11": 4,
        "LoD/1.11b": 4,
        "LoD/1.12a": 4,
        "LoD/1.13c": 4,
        "LoD/1.13d": 4
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "ee4facdaccbd6fc5f3297fd5b85b73c2",
        "LoD/1.08": "ee4facdaccbd6fc5f3297fd5b85b73c2",
        "LoD/1.09": "ee4facdaccbd6fc5f3297fd5b85b73c2",
        "LoD/1.09b": "ee4facdaccbd6fc5f3297fd5b85b73c2",
        "LoD/1.09d": "ee4facdaccbd6fc5f3297fd5b85b73c2",
        "LoD/1.10": "ee4facdaccbd6fc5f3297fd5b85b73c2",
        "LoD/1.11": "45d24cae1027649da4393ef4c4f0d99b",
        "LoD/1.11b": "45d24cae1027649da4393ef4c4f0d99b",
        "LoD/1.12a": "45d24cae1027649da4393ef4c4f0d99b",
        "LoD/1.13c": "45d24cae1027649da4393ef4c4f0d99b",
        "LoD/1.13d": "45d24cae1027649da4393ef4c4f0d99b"
      }
    },
    "d2net.dll__memset": {
      "addresses": {
        "LoD/1.07": "0x6FC35B60",
        "LoD/1.08": "0x6FC35B60",
        "LoD/1.09": "0x6FC05B60",
        "LoD/1.09b": "0x6FC05B60",
        "LoD/1.09d": "0x6FC05B60",
        "LoD/1.10": "0x6FC05C00",
        "LoD/1.11": "0x6FBF4350",
        "LoD/1.11b": "0x6FBF4350",
        "LoD/1.12a": "0x6FBF4380",
        "LoD/1.13c": "0x6FBF4380",
        "LoD/1.13d": "0x6FBF4350"
      },
      "rvas": {
        "LoD/1.07": "0x5B60",
        "LoD/1.08": "0x5B60",
        "LoD/1.09": "0x5B60",
        "LoD/1.09b": "0x5B60",
        "LoD/1.09d": "0x5B60",
        "LoD/1.10": "0x5C00",
        "LoD/1.11": "0x4350",
        "LoD/1.11b": "0x4350",
        "LoD/1.12a": "0x4380",
        "LoD/1.13c": "0x4380",
        "LoD/1.13d": "0x4350"
      },
      "sizes": {
        "LoD/1.07": 88,
        "LoD/1.08": 88,
        "LoD/1.09": 88,
        "LoD/1.09b": 88,
        "LoD/1.09d": 88,
        "LoD/1.10": 88,
        "LoD/1.11": 96,
        "LoD/1.11b": 96,
        "LoD/1.12a": 96,
        "LoD/1.13c": 96,
        "LoD/1.13d": 96
      },
      "name": "_memset",
      "signature": "void * _memset(void * _Dst, int _Val, size_t _Size)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n _memset\n\nLibraries: Visual Studio 1998 Debug, Visual Studio 1998 Release",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:b99d3962c0b26901db87269607fbf85a",
      "basic_block_counts": {
        "LoD/1.07": 10,
        "LoD/1.08": 10,
        "LoD/1.09": 10,
        "LoD/1.09b": 10,
        "LoD/1.09d": 10,
        "LoD/1.10": 10,
        "LoD/1.11": 10,
        "LoD/1.11b": 10,
        "LoD/1.12a": 10,
        "LoD/1.13c": 10,
        "LoD/1.13d": 10
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "b99d3962c0b26901db87269607fbf85a",
        "LoD/1.08": "b99d3962c0b26901db87269607fbf85a",
        "LoD/1.09": "b99d3962c0b26901db87269607fbf85a",
        "LoD/1.09b": "b99d3962c0b26901db87269607fbf85a",
        "LoD/1.09d": "b99d3962c0b26901db87269607fbf85a",
        "LoD/1.10": "b99d3962c0b26901db87269607fbf85a",
        "LoD/1.11": "cb39780517b1dd8e5312f6fce0a00812",
        "LoD/1.11b": "cb39780517b1dd8e5312f6fce0a00812",
        "LoD/1.12a": "cb39780517b1dd8e5312f6fce0a00812",
        "LoD/1.13c": "cb39780517b1dd8e5312f6fce0a00812",
        "LoD/1.13d": "cb39780517b1dd8e5312f6fce0a00812"
      }
    },
    "d2net.dll_CRT_LCMapStringMB": {
      "addresses": {
        "LoD/1.07": "0x6FC35BB8",
        "LoD/1.08": "0x6FC35BB8",
        "LoD/1.09": "0x6FC05BB8",
        "LoD/1.09b": "0x6FC05BB8",
        "LoD/1.09d": "0x6FC05BB8",
        "LoD/1.10": "0x6FC05C58"
      },
      "rvas": {
        "LoD/1.07": "0x5BB8",
        "LoD/1.08": "0x5BB8",
        "LoD/1.09": "0x5BB8",
        "LoD/1.09b": "0x5BB8",
        "LoD/1.09d": "0x5BB8",
        "LoD/1.10": "0x5C58"
      },
      "sizes": {
        "LoD/1.07": 511,
        "LoD/1.08": 511,
        "LoD/1.09": 511,
        "LoD/1.09b": 511,
        "LoD/1.09d": 511,
        "LoD/1.10": 511
      },
      "name": "CRT_LCMapStringMB",
      "signature": "int CRT_LCMapStringMB(uint dwLocaleId, uint dwMapFlags, char * lpszSrcString, int nSrcLen, wchar_t * wszDestString, int nDestLen, uint dwCodePage, int nMbWcFlags)",
      "calling_convention": "__cdecl",
      "comment": "Maps a character string using locale-specific rules via LCMapString with multi-byte/wide character conversion.\n\nAlgorithm:\n1. Set up SEH frame for stack-based buffer allocation protection\n2. Check g_dwLCMapStringMode to determine API availability:\n   - 0: Test LCMapStringW with empty string; if fails, test LCMapStringA\n   - 1: Unicode mode (LCMapStringW available)\n   - 2: ANSI mode (only LCMapStringA available)\n3. If nSrcLen > 0, call FUN_6fc35ddc to calculate actual string length\n4. Mode 2 (ANSI only): Call LCMapStringA directly with parameters and return\n5. Mode 1 (Unicode): \n   a. Use g_dwThreadLocaleCodePage if dwCodePage is 0\n   b. Convert dwMapFlags to MB_ERR_INVALID_CHARS (0x8) + 1 if nMbWcFlags != 0\n   c. Call MultiByteToWideChar to get required wide buffer size\n   d. Allocate wide buffer on stack via _alloca_probe\n   e. Call MultiByteToWideChar to convert source to wide string\n   f. Call LCMapStringW on wide buffer to get mapped result size\n   g. If LCMAP_SORTKEY (0x400) flag NOT set:\n      - Allocate second wide buffer for mapped result\n      - Call LCMapStringW to perform actual mapping\n      - Convert result back via WideCharToMultiByte with WC_COMPOSITECHECK|WC_SEPCHARS (0x220)\n   h. If LCMAP_SORTKEY flag set:\n      - Return wide result directly if nDestLen is 0 (size query)\n      - Return 0 if nDestLen < mapped size (buffer too small)\n      - Call LCMapStringW with output buffer\n6. Return mapped string length or 0 on failure\n\nParameters:\n  dwLocaleId - LCID for locale-specific mapping rules\n  dwMapFlags - LCMAP_* flags controlling mapping type (LOWERCASE, UPPERCASE, SORTKEY, etc.)\n  lpszSrcString - Multi-byte source string to map\n  nSrcLen - Length of source string (-1 for null-terminated)\n  lpwszDestString - Output buffer for mapped string\n  nDestLen - Size of output buffer (0 for size query)\n  dwCodePage - Code page for MB/WC conversion (0 = use thread locale)\n  nMbWcFlags - If non-zero, use MB_ERR_INVALID_CHARS flag\n\nReturns:\n  Length of mapped string on success\n  0 on failure\n\nSpecial Cases:\n  - Size query mode: Pass nDestLen=0 to get required buffer size\n  - LCMAP_SORTKEY returns binary sort key directly without back-conversion\n  - ANSI fallback mode used on systems without Unicode support",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:c1d05e132bc8c3bc87e7a971916e9b9b",
      "basic_block_counts": {
        "LoD/1.07": 31,
        "LoD/1.08": 31,
        "LoD/1.09": 31,
        "LoD/1.09b": 31,
        "LoD/1.09d": 31,
        "LoD/1.10": 31
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "c1d05e132bc8c3bc87e7a971916e9b9b",
        "LoD/1.08": "c1d05e132bc8c3bc87e7a971916e9b9b",
        "LoD/1.09": "c1d05e132bc8c3bc87e7a971916e9b9b",
        "LoD/1.09b": "c1d05e132bc8c3bc87e7a971916e9b9b",
        "LoD/1.09d": "c1d05e132bc8c3bc87e7a971916e9b9b",
        "LoD/1.10": "c1d05e132bc8c3bc87e7a971916e9b9b"
      }
    },
    "d2net.dll_GetStringLengthBounded": {
      "addresses": {
        "LoD/1.07": "0x6FC35DDC",
        "LoD/1.08": "0x6FC35DDC",
        "LoD/1.09": "0x6FC05DDC",
        "LoD/1.09b": "0x6FC05DDC",
        "LoD/1.09d": "0x6FC05DDC",
        "LoD/1.10": "0x6FC05E7C"
      },
      "rvas": {
        "LoD/1.07": "0x5DDC",
        "LoD/1.08": "0x5DDC",
        "LoD/1.09": "0x5DDC",
        "LoD/1.09b": "0x5DDC",
        "LoD/1.09d": "0x5DDC",
        "LoD/1.10": "0x5E7C"
      },
      "sizes": {
        "LoD/1.07": 43,
        "LoD/1.08": 43,
        "LoD/1.09": 43,
        "LoD/1.09b": 43,
        "LoD/1.09d": 43,
        "LoD/1.10": 43
      },
      "name": "GetStringLengthBounded",
      "signature": "int GetStringLengthBounded(char * lpszString, int nMaxCount)",
      "calling_convention": "__cdecl",
      "comment": "Calculates string length up to a maximum count (strnlen equivalent).\n\nAlgorithm:\n1. Initialize current pointer to string start and remaining count\n2. If nMaxCount is 0, skip loop entirely\n3. Loop: decrement remaining, check for null terminator, advance pointer\n4. After loop: if current char is null, return length (pointer difference)\n5. Otherwise return nMaxCount (no null found within limit)\n\nParameters:\n  lpszString - Input ANSI string to measure\n  nMaxCount  - Maximum characters to scan\n\nReturns:\n  String length if null terminator found within nMaxCount\n  nMaxCount if no null terminator found (string >= nMaxCount chars)\n\nSpecial Cases:\n  - nMaxCount=0 returns 0 if first char is null, else nMaxCount\n  - Empty string (\"\") returns 0 immediately\n\nCalled by: FUN_6fc35bb8 (LCMapString wrapper) to bound string length for\nlocale mapping operations before passing to MultiByteToWideChar.\n\nClassification: Leaf function / Internal utility",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:c365f0335b7bc4452623cbc78de16e67",
      "basic_block_counts": {
        "LoD/1.07": 6,
        "LoD/1.08": 6,
        "LoD/1.09": 6,
        "LoD/1.09b": 6,
        "LoD/1.09d": 6,
        "LoD/1.10": 6
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "c365f0335b7bc4452623cbc78de16e67",
        "LoD/1.08": "c365f0335b7bc4452623cbc78de16e67",
        "LoD/1.09": "c365f0335b7bc4452623cbc78de16e67",
        "LoD/1.09b": "c365f0335b7bc4452623cbc78de16e67",
        "LoD/1.09d": "c365f0335b7bc4452623cbc78de16e67",
        "LoD/1.10": "c365f0335b7bc4452623cbc78de16e67"
      }
    },
    "d2net.dll_CRT_GetStringTypeExInternal": {
      "addresses": {
        "LoD/1.07": "0x6FC35E07",
        "LoD/1.08": "0x6FC35E07",
        "LoD/1.09": "0x6FC05E07",
        "LoD/1.09b": "0x6FC05E07",
        "LoD/1.09d": "0x6FC05E07",
        "LoD/1.10": "0x6FC05EA7"
      },
      "rvas": {
        "LoD/1.07": "0x5E07",
        "LoD/1.08": "0x5E07",
        "LoD/1.09": "0x5E07",
        "LoD/1.09b": "0x5E07",
        "LoD/1.09d": "0x5E07",
        "LoD/1.10": "0x5EA7"
      },
      "sizes": {
        "LoD/1.07": 318,
        "LoD/1.08": 318,
        "LoD/1.09": 318,
        "LoD/1.09b": 318,
        "LoD/1.09d": 318,
        "LoD/1.10": 318
      },
      "name": "CRT_GetStringTypeExInternal",
      "signature": "BOOL CRT_GetStringTypeExInternal(DWORD dwInfoType, LPCSTR lpszSrcStr, int nSrcLen, LPWORD pwCharType, UINT dwCodePage, LCID dwLocaleId, int nUsePrecomposed)",
      "calling_convention": "__cdecl",
      "comment": "CRT_GetStringTypeExInternal - Internal string character type retrieval with Unicode fallback.\n\nRetrieves character type information for a multibyte string, automatically detecting\nand using the appropriate API (GetStringTypeW or GetStringTypeA) based on system\ncapabilities. Performs lazy initialization of g_dwStringTypeMode on first call.\n\nAlgorithm:\n1. Set up SEH frame for stack allocation protection\n2. If g_dwStringTypeMode == 0 (uninitialized):\n   a. Test GetStringTypeW with empty wide string\n   b. If succeeds, set mode = 1 (Unicode preferred)\n   c. If fails, test GetStringTypeA with empty ANSI string\n   d. If ANSI succeeds, set mode = 2 (ANSI only)\n   e. If both fail, return FALSE (no string type support)\n3. If mode == 2 (ANSI only):\n   a. Use dwLocaleId or fall back to g_dwThreadLocaleId\n   b. Call GetStringTypeA directly\n4. If mode == 1 (Unicode preferred):\n   a. Use dwCodePage or fall back to g_dwThreadLocaleCodePage\n   b. Call MultiByteToWideChar to get required buffer size\n   c. Allocate wide char buffer on stack via _alloca_probe\n   d. Zero-initialize the buffer with _memset\n   e. Convert MBCS to wide chars\n   f. Call GetStringTypeW on the converted wide string\n5. Return character type result or FALSE on failure\n\nParameters:\n  dwInfoType (DWORD) - CT_CTYPE1, CT_CTYPE2, or CT_CTYPE3 flags\n  lpszSrcStr (LPCSTR) - Source multibyte string to analyze\n  nSrcLen (int) - Length of source string, or -1 for null-terminated\n  pwCharType (LPWORD) - Output array for character type values\n  dwCodePage (UINT) - Code page for conversion, 0 = use thread locale\n  dwLocaleId (LCID) - Locale ID for ANSI path, 0 = use thread locale\n  nUsePrecomposed (int) - If non-zero, use MB_PRECOMPOSED (0x1), else MB_USEGLYPHCHARS (0x8) + 1\n\nReturns:\n  BOOL - TRUE if character types retrieved successfully, FALSE on failure\n\nSpecial Cases:\n  - First call performs lazy initialization testing both Unicode and ANSI APIs\n  - Code page 0 uses g_dwThreadLocaleCodePage global\n  - Locale ID 0 uses g_dwThreadLocaleId global\n  - MB_PRECOMPOSED flag selection: (-(nUsePrecomposed != 0) & 8) + 1 yields 1 or 9\n\nLocal Variables:\n  dVar1 (uint): Temporary for mode detection result\n  puVar2 (byte*): Stack pointer for alloca buffer\n  BVar3 (BOOL): API call return value\n  iVar4 (int): Wide character count from MultiByteToWideChar\n  local_20 (WORD[2]): Test buffer for GetStringType API detection\n  local_1c (byte*): Wide char buffer pointer from stack allocation\n  local_14 (void*): Saved exception list pointer for SEH\n  puStack_10 (byte*): SEH handler address\n  puStack_c (byte*): SEH scope table pointer\n  local_8 (uint): SEH state variable (0xFFFFFFFF = outside try, 0 = inside try)\n\nGlobals Referenced:\n  g_dwStringTypeMode (0x6fc3b43c) - API mode: 0=uninitialized, 1=Unicode, 2=ANSI\n  g_dwThreadLocaleCodePage (0x6fc3b430) - Default code page for thread\n  g_dwThreadLocaleId (0x6fc3b420) - Default locale ID for thread",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:a7046d73bbd286a50d5e7204509858d2",
      "basic_block_counts": {
        "LoD/1.07": 20,
        "LoD/1.08": 20,
        "LoD/1.09": 20,
        "LoD/1.09b": 20,
        "LoD/1.09d": 20,
        "LoD/1.10": 20
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "a7046d73bbd286a50d5e7204509858d2",
        "LoD/1.08": "a7046d73bbd286a50d5e7204509858d2",
        "LoD/1.09": "a7046d73bbd286a50d5e7204509858d2",
        "LoD/1.09b": "a7046d73bbd286a50d5e7204509858d2",
        "LoD/1.09d": "a7046d73bbd286a50d5e7204509858d2",
        "LoD/1.10": "a7046d73bbd286a50d5e7204509858d2"
      }
    },
    "d2net.dll_GetErrnoPtr": {
      "addresses": {
        "LoD/1.07": "0x6FC35F50",
        "LoD/1.08": "0x6FC35F50",
        "LoD/1.09": "0x6FC05F50",
        "LoD/1.09b": "0x6FC05F50",
        "LoD/1.09d": "0x6FC05F50",
        "LoD/1.10": "0x6FC05FF0",
        "LoD/1.11": "0x6FBF2B57",
        "LoD/1.11b": "0x6FBF2B57",
        "LoD/1.12a": "0x6FBF2B78",
        "LoD/1.13c": "0x6FBF2B78",
        "LoD/1.13d": "0x6FBF2B57"
      },
      "rvas": {
        "LoD/1.07": "0x5F50",
        "LoD/1.08": "0x5F50",
        "LoD/1.09": "0x5F50",
        "LoD/1.09b": "0x5F50",
        "LoD/1.09d": "0x5F50",
        "LoD/1.10": "0x5FF0",
        "LoD/1.11": "0x2B57",
        "LoD/1.11b": "0x2B57",
        "LoD/1.12a": "0x2B78",
        "LoD/1.13c": "0x2B78",
        "LoD/1.13d": "0x2B57"
      },
      "sizes": {
        "LoD/1.07": 9,
        "LoD/1.08": 9,
        "LoD/1.09": 9,
        "LoD/1.09b": 9,
        "LoD/1.09d": 9,
        "LoD/1.10": 9,
        "LoD/1.11": 9,
        "LoD/1.11b": 9,
        "LoD/1.12a": 9,
        "LoD/1.13c": 9,
        "LoD/1.13d": 9
      },
      "name": "GetErrnoPtr",
      "signature": "uint * GetErrnoPtr(void)",
      "calling_convention": "__stdcall",
      "comment": "Returns pointer to thread-local errno storage.\n\nThis leaf function retrieves the CRT Thread Local Storage (TLS) data block\nand returns a pointer to the errno field at offset +8 (DWORD index 2).\n\nAlgorithm:\n1. Call CRT_GetOrAllocateTlsData to get TLS data block base pointer\n2. Add offset 8 (2 DWORDs) to reach errno storage location\n3. Return pointer to errno\n\nParameters:\n  None\n\nReturns:\n  DWORD* - Pointer to thread-local errno value (offset +8 in TLS block)\n\nCallers:\n  StringToULongInternal - Sets errno to ERANGE (0x22) on overflow\n\nTLS Block Layout (partial):\n  Offset  Size  Field\n  +0x00   4     (unknown)\n  +0x04   4     (unknown)\n  +0x08   4     errno value <- returned pointer targets here",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:b1691d6b7b8ba065c3fc1a089e8db64e",
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1,
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "b1691d6b7b8ba065c3fc1a089e8db64e",
        "LoD/1.08": "b1691d6b7b8ba065c3fc1a089e8db64e",
        "LoD/1.09": "b1691d6b7b8ba065c3fc1a089e8db64e",
        "LoD/1.09b": "b1691d6b7b8ba065c3fc1a089e8db64e",
        "LoD/1.09d": "b1691d6b7b8ba065c3fc1a089e8db64e",
        "LoD/1.10": "b1691d6b7b8ba065c3fc1a089e8db64e",
        "LoD/1.11": "b1691d6b7b8ba065c3fc1a089e8db64e",
        "LoD/1.11b": "b1691d6b7b8ba065c3fc1a089e8db64e",
        "LoD/1.12a": "b1691d6b7b8ba065c3fc1a089e8db64e",
        "LoD/1.13c": "b1691d6b7b8ba065c3fc1a089e8db64e",
        "LoD/1.13d": "b1691d6b7b8ba065c3fc1a089e8db64e"
      }
    },
    "d2net.dll_ToUpperCase": {
      "addresses": {
        "LoD/1.07": "0x6FC35F59",
        "LoD/1.08": "0x6FC35F59",
        "LoD/1.09": "0x6FC05F59",
        "LoD/1.09b": "0x6FC05F59",
        "LoD/1.09d": "0x6FC05F59",
        "LoD/1.10": "0x6FC05FF9"
      },
      "rvas": {
        "LoD/1.07": "0x5F59",
        "LoD/1.08": "0x5F59",
        "LoD/1.09": "0x5F59",
        "LoD/1.09b": "0x5F59",
        "LoD/1.09d": "0x5F59",
        "LoD/1.10": "0x5FF9"
      },
      "sizes": {
        "LoD/1.07": 111,
        "LoD/1.08": 111,
        "LoD/1.09": 111,
        "LoD/1.09b": 111,
        "LoD/1.09d": 111,
        "LoD/1.10": 111
      },
      "name": "ToUpperCase",
      "signature": "dword ToUpperCase(dword chCharacter)",
      "calling_convention": "__cdecl",
      "comment": "Converts a character to uppercase with locale awareness.\n\nClassification: Worker function - CRT string utility\n\nAlgorithm:\n1. Check if thread locale ID (g_dwThreadLocaleId) is zero\n2. If zero (default C locale), use fast ASCII path:\n   a. Check if character is lowercase ASCII 'a'-'z' (0x61-0x7A)\n   b. If so, subtract 0x20 to convert to uppercase 'A'-'Z'\n   c. Return original character if not lowercase ASCII\n3. If locale is set (non-zero), use thread-safe locale path:\n   a. Increment reference count g_nLocaleRefCount via InterlockedIncrement\n   b. Check g_fLocaleInitRequired flag for critical section need\n   c. If flag set, decrement ref count and enter critical section index 0x13\n   d. Call FUN_6fc35fc8 (locale-aware LCMapString wrapper) for conversion\n   e. If flag was set, leave critical section; else decrement ref count\n4. Return converted character\n\nParameters:\n  chCharacter (dword) - Character code point to convert to uppercase\n\nReturns:\n  dword - Uppercase character code, or original if not convertible\n\nSpecial Cases:\n- Fast path for ASCII lowercase only when no locale set\n- Thread-safe synchronization for locale-dependent conversion\n- Critical section index 0x13 used for locale operations\n\nMagic Numbers:\n  0x60 - Character before 'a' (0x61)\n  0x7B - Character after 'z' (0x7A)  \n  0x20 - ASCII case difference ('a' - 'A')\n  0x13 - Critical section index for locale operations\n\nCaller Context:\n- Called from StringToULongInternal for case-insensitive number parsing",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:e038b71e990839fd36df244ad8c1a314",
      "basic_block_counts": {
        "LoD/1.07": 11,
        "LoD/1.08": 11,
        "LoD/1.09": 11,
        "LoD/1.09b": 11,
        "LoD/1.09d": 11,
        "LoD/1.10": 11
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "e038b71e990839fd36df244ad8c1a314",
        "LoD/1.08": "e038b71e990839fd36df244ad8c1a314",
        "LoD/1.09": "e038b71e990839fd36df244ad8c1a314",
        "LoD/1.09b": "e038b71e990839fd36df244ad8c1a314",
        "LoD/1.09d": "e038b71e990839fd36df244ad8c1a314",
        "LoD/1.10": "e038b71e990839fd36df244ad8c1a314"
      }
    },
    "d2net.dll_ToUpperCaseLocaleAware": {
      "addresses": {
        "LoD/1.07": "0x6FC35FC8",
        "LoD/1.08": "0x6FC35FC8",
        "LoD/1.09": "0x6FC05FC8",
        "LoD/1.09b": "0x6FC05FC8",
        "LoD/1.09d": "0x6FC05FC8",
        "LoD/1.10": "0x6FC06068"
      },
      "rvas": {
        "LoD/1.07": "0x5FC8",
        "LoD/1.08": "0x5FC8",
        "LoD/1.09": "0x5FC8",
        "LoD/1.09b": "0x5FC8",
        "LoD/1.09d": "0x5FC8",
        "LoD/1.10": "0x6068"
      },
      "sizes": {
        "LoD/1.07": 204,
        "LoD/1.08": 204,
        "LoD/1.09": 204,
        "LoD/1.09b": 204,
        "LoD/1.09d": 204,
        "LoD/1.10": 204
      },
      "name": "ToUpperCaseLocaleAware",
      "signature": "uint ToUpperCaseLocaleAware(void * this, uint dwCharacter)",
      "calling_convention": "__thiscall",
      "comment": "Converts a character to uppercase using locale-specific mapping rules.\n\nClassification: Worker function - CRT locale-aware string utility\n\nAlgorithm:\n1. Check if thread locale ID (g_dwThreadLocaleId) is zero\n2. If zero (default C locale), use fast ASCII path:\n   a. Check if character is lowercase ASCII 'a'-'z' (0x61-0x7A)\n   b. If lowercase, subtract 0x20 to convert to uppercase\n   c. Return original character if not lowercase ASCII\n3. If locale is set (non-zero), use locale-aware path:\n   a. Save 'this' pointer to byResult buffer (reused for LCMapString output)\n   b. If character < 0x100 (single-byte range):\n      - Check g_dwMultiByteMode: if < 2, lookup in g_pCharTypeTable\n      - If >= 2, call GetCharTypeMask for character type\n      - If C2_LOWERCASE (0x2) bit not set, return original character\n   c. Check if high byte of character indicates lead byte (multibyte char):\n      - Use g_pCharTypeTable[highbyte * 2 + 1] & 0x80 to detect lead byte\n   d. If single-byte character: set up 1-byte buffer, nSrcLen = 1\n   e. If double-byte character: swap bytes for proper encoding, nSrcLen = 2\n   f. Call CRT_LCMapStringMB with LCMAP_UPPERCASE (0x200) flag\n   g. If LCMapString returns 1, extract single byte result\n   h. If LCMapString returns 2, extract two-byte (wide char) result\n4. Return uppercase character or original if conversion failed\n\nParameters:\n  this (ECX, implicit) - Locale info pointer, reused as output buffer\n  chInput (stack) - Character code point to convert to uppercase (uint)\n\nReturns:\n  uint - Uppercase character code, or original if not convertible\n\nSpecial Cases:\n- Fast ASCII path bypasses locale lookup for 'a'-'z' when no locale set\n- Single-byte characters (< 0x100) checked for lowercase before LCMapString\n- Multi-byte characters have bytes swapped for proper MBCS encoding\n- Returns original character if GetCharTypeMask indicates not lowercase\n- Returns original character if LCMapString returns 0 (failure)\n\nMagic Numbers:\n  0x60 (96) - Character before 'a' (0x61)\n  0x7B (123) - Character after 'z' (0x7A)\n  0x20 (32) - ASCII case difference ('a' - 'A' = 32)\n  0x100 (256) - Single-byte character limit\n  0x200 - LCMAP_UPPERCASE flag for LCMapString\n  0x80 - Lead byte indicator in character type table\n  0x02 - C2_LOWERCASE character type mask\n  3 - Output buffer size for LCMapString\n\nGlobals Referenced:\n  g_dwThreadLocaleId (0x6fc3b420) - Current thread's locale ID (0 = C locale)\n  g_dwMultiByteMode (0x6fc3ad04) - Multi-byte character handling mode\n  g_pCharTypeTable (0x6fc3aaf8) - Character type lookup table\n\nCaller Context:\n  Called from ToUpperCase after acquiring locale critical section",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:5918dc16e1bf74054af7a7988b490678",
      "basic_block_counts": {
        "LoD/1.07": 18,
        "LoD/1.08": 18,
        "LoD/1.09": 18,
        "LoD/1.09b": 18,
        "LoD/1.09d": 18,
        "LoD/1.10": 18
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "5918dc16e1bf74054af7a7988b490678",
        "LoD/1.08": "5918dc16e1bf74054af7a7988b490678",
        "LoD/1.09": "5918dc16e1bf74054af7a7988b490678",
        "LoD/1.09b": "5918dc16e1bf74054af7a7988b490678",
        "LoD/1.09d": "5918dc16e1bf74054af7a7988b490678",
        "LoD/1.10": "5918dc16e1bf74054af7a7988b490678"
      }
    },
    "d2net.dll_GetCharTypeMask": {
      "addresses": {
        "LoD/1.07": "0x6FC36094",
        "LoD/1.08": "0x6FC36094",
        "LoD/1.09": "0x6FC06094",
        "LoD/1.09b": "0x6FC06094",
        "LoD/1.09d": "0x6FC06094",
        "LoD/1.10": "0x6FC06134"
      },
      "rvas": {
        "LoD/1.07": "0x6094",
        "LoD/1.08": "0x6094",
        "LoD/1.09": "0x6094",
        "LoD/1.09b": "0x6094",
        "LoD/1.09d": "0x6094",
        "LoD/1.10": "0x6134"
      },
      "sizes": {
        "LoD/1.07": 117,
        "LoD/1.08": 117,
        "LoD/1.09": 117,
        "LoD/1.09b": 117,
        "LoD/1.09d": 117,
        "LoD/1.10": 117
      },
      "name": "GetCharTypeMask",
      "signature": "uint GetCharTypeMask(void * this, void * pThis, int nCharCode, uint dwTypeMask)",
      "calling_convention": "__thiscall",
      "comment": "GetCharTypeMask - Retrieves Windows character type flags masked by specified type bits.\n\nThis function queries character type information (CT_CTYPE1/2/3) for a given character\ncode and returns only the bits specified by the mask. Uses a cached lookup table for\nASCII characters (0x00-0xFF) and falls back to GetStringTypeEx for extended characters.\n\nClassification: Worker function (internal utility for character classification)\n\nAlgorithm:\n1. Check if character code is in ASCII range (nCharCode + 1 < 0x101)\n2. If ASCII: directly lookup character type from g_pCharTypeTable[nCharCode * 2]\n3. If extended character (>= 0x100):\n   a. Extract high byte (nCharCode >> 8) and check lead byte flag in table\n   b. If high byte has 0x80 flag (DBCS lead byte):\n      - Build 2-byte MBCS sequence: [high_byte, low_byte, 0x00]\n      - Set byte length = 2\n   c. If single-byte extended:\n      - Build 1-byte sequence: [low_byte, 0x00]\n      - Set byte length = 1\n   d. Call CRT_GetStringTypeExInternal to get character type\n   e. If API fails, return 0\n4. Return (wCharType & dwTypeMask)\n\nParameters:\n  pThis (void *) - Implicit __thiscall parameter (unused, provides temp storage)\n  nCharCode (int) - Unicode code point or MBCS character value to classify\n  dwTypeMask (uint) - Bitmask for CT_CTYPE1 flags to return (C1_UPPER=0x1, etc.)\n\nReturns:\n  uint - Character type flags ANDed with dwTypeMask, or 0 on failure\n\nSpecial Cases:\n  - Characters 0x00-0xFF use fast table lookup (no API call)\n  - DBCS lead bytes (high byte with 0x80 flag) trigger 2-byte sequence\n  - CRT_GetStringTypeExInternal called with dwInfoType=CT_CTYPE1 (0x1)\n\nCharacter Type Table (g_pCharTypeTable @ 0x6fc3aaf8):\n  - Array of 256 WORD entries (512 bytes)\n  - Entry[n] = CT_CTYPE1 flags for character n\n  - High byte (+1 offset) bit 0x80 indicates DBCS lead byte\n\nStack Frame Layout:\n  Offset  Size  Name         Description\n  +0x0C   4     dwTypeMask   Type mask parameter\n  +0x08   4     nCharCode    Character code parameter\n  +0x0A   2     wCharType    Output from GetStringTypeEx (overlaps nCharCode high word)\n  -0x04   4     abCharBytes  MBCS byte sequence for API call\n\nCallers:\n  - StringToULongInternal (character classification during parsing)\n  - FUN_6fc35fc8 (character type checking)\n  - FUN_6fc364e5 (character type checking)",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:d858691b25ff9d68f1965dc04bb2a9aa",
      "basic_block_counts": {
        "LoD/1.07": 9,
        "LoD/1.08": 9,
        "LoD/1.09": 9,
        "LoD/1.09b": 9,
        "LoD/1.09d": 9,
        "LoD/1.10": 9
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "d858691b25ff9d68f1965dc04bb2a9aa",
        "LoD/1.08": "d858691b25ff9d68f1965dc04bb2a9aa",
        "LoD/1.09": "d858691b25ff9d68f1965dc04bb2a9aa",
        "LoD/1.09b": "d858691b25ff9d68f1965dc04bb2a9aa",
        "LoD/1.09d": "d858691b25ff9d68f1965dc04bb2a9aa",
        "LoD/1.10": "d858691b25ff9d68f1965dc04bb2a9aa"
      }
    },
    "d2net.dll_strcmp": {
      "addresses": {
        "LoD/1.07": "0x6FC36110",
        "LoD/1.08": "0x6FC36110",
        "LoD/1.09": "0x6FC06110",
        "LoD/1.09b": "0x6FC06110",
        "LoD/1.09d": "0x6FC06110",
        "LoD/1.10": "0x6FC061B0"
      },
      "rvas": {
        "LoD/1.07": "0x6110",
        "LoD/1.08": "0x6110",
        "LoD/1.09": "0x6110",
        "LoD/1.09b": "0x6110",
        "LoD/1.09d": "0x6110",
        "LoD/1.10": "0x61B0"
      },
      "sizes": {
        "LoD/1.07": 129,
        "LoD/1.08": 129,
        "LoD/1.09": 129,
        "LoD/1.09b": 129,
        "LoD/1.09d": 129,
        "LoD/1.10": 129
      },
      "name": "strcmp",
      "signature": "int strcmp(char * lpszString1, char * lpszString2)",
      "calling_convention": "__cdecl",
      "comment": "Standard C runtime string comparison function (strcmp).\n\nALGORITHM:\n1. Check if lpszString1 pointer is DWORD-aligned (addr & 3)\n2. If not DWORD-aligned:\n   a. Handle single byte if address is odd (addr & 1)\n   b. Handle word if still misaligned (addr & 2)\n3. Enter DWORD-optimized comparison loop:\n   a. Load 4 bytes from lpszString1 at once\n   b. Compare each byte against corresponding lpszString2 byte\n   c. Exit on mismatch or null terminator\n   d. Advance both pointers by 4 and repeat\n4. Return comparison result via SBB/SHL/INC pattern\n\nPARAMETERS:\n  lpszString1 (char *): First null-terminated string to compare\n  lpszString2 (char *): Second null-terminated string to compare\n\nRETURNS:\n  <0: lpszString1 is lexicographically less than lpszString2\n   0: Strings are equal\n  >0: lpszString1 is lexicographically greater than lpszString2\n\nSPECIAL CASES:\n  - Handles unaligned string pointers with byte/word prefix handling\n  - Uses DWORD reads for aligned addresses (performance optimization)\n  - Returns -1 or +1 using SBB+SHL+INC pattern (not raw difference)\n\nDECOMPILER NOTES:\n  - uVar1 (undefined2): Word read for 2-byte alignment handling\n  - uVar2 (undefined4): DWORD read in main comparison loop\n  - bVar3, bVar4 (byte): Individual characters being compared\n  - bVar5 (bool): Less-than comparison flag for return value\n\nFUNCTION TYPE: Leaf function - Standard CRT implementation\nCALLING CONVENTION: __cdecl (stack parameters, caller cleanup)",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:f93a26193b15127770b523718dea2fb3",
      "basic_block_counts": {
        "LoD/1.07": 21,
        "LoD/1.08": 21,
        "LoD/1.09": 21,
        "LoD/1.09b": 21,
        "LoD/1.09d": 21,
        "LoD/1.10": 21
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "f93a26193b15127770b523718dea2fb3",
        "LoD/1.08": "f93a26193b15127770b523718dea2fb3",
        "LoD/1.09": "f93a26193b15127770b523718dea2fb3",
        "LoD/1.09b": "f93a26193b15127770b523718dea2fb3",
        "LoD/1.09d": "f93a26193b15127770b523718dea2fb3",
        "LoD/1.10": "f93a26193b15127770b523718dea2fb3"
      }
    },
    "d2net.dll_strcspn": {
      "addresses": {
        "LoD/1.07": "0x6FC361A0",
        "LoD/1.08": "0x6FC361A0",
        "LoD/1.09": "0x6FC061A0",
        "LoD/1.09b": "0x6FC061A0",
        "LoD/1.09d": "0x6FC061A0",
        "LoD/1.10": "0x6FC06240"
      },
      "rvas": {
        "LoD/1.07": "0x61A0",
        "LoD/1.08": "0x61A0",
        "LoD/1.09": "0x61A0",
        "LoD/1.09b": "0x61A0",
        "LoD/1.09d": "0x61A0",
        "LoD/1.10": "0x6240"
      },
      "sizes": {
        "LoD/1.07": 62,
        "LoD/1.08": 62,
        "LoD/1.09": 62,
        "LoD/1.09b": 62,
        "LoD/1.09d": 62,
        "LoD/1.10": 62
      },
      "name": "strcspn",
      "signature": "int strcspn(char * lpszStr, char * lpszReject)",
      "calling_convention": "__cdecl",
      "comment": "strcspn - Scan string for characters NOT in reject set\n\nImplementation of C standard library strcspn function. Returns the length\nof the initial segment of lpszStr consisting entirely of characters NOT\nin the lpszReject string.\n\nAlgorithm:\n1. Initialize 256-bit bitmap (32 bytes) on stack to all zeros\n2. Loop through lpszReject string:\n   - For each character, set corresponding bit in bitmap\n   - Bitmap index = char_value >> 3 (byte index)\n   - Bit position = char_value & 7 (bit within byte)\n   - Use BTS instruction for atomic bit set\n3. Initialize counter to -1 (pre-increment loop)\n4. Loop through lpszStr string:\n   - Increment counter\n   - Load current character\n   - If null terminator, return counter (reached end without match)\n   - Increment string pointer\n   - Test corresponding bit in bitmap using BT instruction\n   - If bit NOT set, continue loop (character not in reject set)\n   - If bit IS set, return counter (found character in reject set)\n\nParameters:\n  lpszStr    - [in] Pointer to null-terminated string to scan\n  lpszReject - [in] Pointer to null-terminated string of reject characters\n\nReturns:\n  int - Length of initial segment of lpszStr not containing any\n        characters from lpszReject. If lpszStr begins with a character\n        from lpszReject, returns 0. If no characters from lpszReject\n        are found, returns strlen(lpszStr).\n\nStack Frame:\n  [EBP-0x20] - abCharBitmap[32] - 256-bit character presence bitmap\n\nAssembly Notes:\n  Uses BTS (Bit Test and Set) for efficient bitmap population\n  Uses BT (Bit Test) for efficient bitmap lookup\n  8x PUSH EAX zeros 32 bytes of stack for bitmap initialization",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:30f0fd08cad97c1e8bd24ed371c4d8a2",
      "basic_block_counts": {
        "LoD/1.07": 7,
        "LoD/1.08": 7,
        "LoD/1.09": 7,
        "LoD/1.09b": 7,
        "LoD/1.09d": 7,
        "LoD/1.10": 7
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "30f0fd08cad97c1e8bd24ed371c4d8a2",
        "LoD/1.08": "30f0fd08cad97c1e8bd24ed371c4d8a2",
        "LoD/1.09": "30f0fd08cad97c1e8bd24ed371c4d8a2",
        "LoD/1.09b": "30f0fd08cad97c1e8bd24ed371c4d8a2",
        "LoD/1.09d": "30f0fd08cad97c1e8bd24ed371c4d8a2",
        "LoD/1.10": "30f0fd08cad97c1e8bd24ed371c4d8a2"
      }
    },
    "d2net.dll_CRT_strpbrk": {
      "addresses": {
        "LoD/1.07": "0x6FC361E0",
        "LoD/1.08": "0x6FC361E0",
        "LoD/1.09": "0x6FC061E0",
        "LoD/1.09b": "0x6FC061E0",
        "LoD/1.09d": "0x6FC061E0",
        "LoD/1.10": "0x6FC06280"
      },
      "rvas": {
        "LoD/1.07": "0x61E0",
        "LoD/1.08": "0x61E0",
        "LoD/1.09": "0x61E0",
        "LoD/1.09b": "0x61E0",
        "LoD/1.09d": "0x61E0",
        "LoD/1.10": "0x6280"
      },
      "sizes": {
        "LoD/1.07": 58,
        "LoD/1.08": 58,
        "LoD/1.09": 58,
        "LoD/1.09b": 58,
        "LoD/1.09d": 58,
        "LoD/1.10": 58
      },
      "name": "CRT_strpbrk",
      "signature": "byte * CRT_strpbrk(byte * pbString, byte * pbCharset)",
      "calling_convention": "__cdecl",
      "comment": "CRT_strpbrk - C Runtime strpbrk implementation using bitset optimization\n\nScans pbString for the first occurrence of any character from pbCharset.\nUses a 256-bit (32-byte) stack bitset for O(1) character lookup.\n\nAlgorithm:\n1. Initialize 32-byte bitset on stack (8 PUSH EAX = 32 zero bytes)\n2. Build charset bitset: For each character in pbCharset, set bit at position (char_value)\n   - Bit index = char_value & 7 (bit within byte)\n   - Byte index = char_value >> 3 (which byte in 32-byte array)\n   - Uses BTS (Bit Test and Set) instruction for atomic set\n3. Scan string: For each character in pbString, test if bit is set\n   - Uses BT (Bit Test) instruction to check membership\n   - If bit set (carry flag), character is in charset - return pointer\n   - If bit clear, continue to next character\n4. If null terminator reached, return 0 (NULL)\n\nParameters:\n  pbString  - Input string to scan\n  pbCharset - Set of characters to search for (null-terminated)\n\nReturns:\n  byte* - Pointer to first character in pbString that appears in pbCharset\n          Returns 0 (NULL cast) if no match found or pbString is empty\n\nSpecial Cases:\n  - Empty pbCharset: No bits set, returns 0 for any input\n  - Empty pbString: Returns 0 immediately\n  - Null terminator in pbString is not matched\n\nBitset Layout (32 bytes = 256 bits on stack at ESP):\n  Offset    Characters Covered\n  0x00-0x03 ASCII 0-31 (control chars)\n  0x04-0x07 ASCII 32-63 (space, punctuation, digits)\n  0x08-0x0B ASCII 64-95 (@, uppercase, brackets)\n  0x0C-0x0F ASCII 96-127 (backtick, lowercase, DEL)\n  0x10-0x1F ASCII 128-255 (extended ASCII)",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:0eb6c316488d30b6ee5d8d243ea3c5d6",
      "basic_block_counts": {
        "LoD/1.07": 8,
        "LoD/1.08": 8,
        "LoD/1.09": 8,
        "LoD/1.09b": 8,
        "LoD/1.09d": 8,
        "LoD/1.10": 8
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "0eb6c316488d30b6ee5d8d243ea3c5d6",
        "LoD/1.08": "0eb6c316488d30b6ee5d8d243ea3c5d6",
        "LoD/1.09": "0eb6c316488d30b6ee5d8d243ea3c5d6",
        "LoD/1.09b": "0eb6c316488d30b6ee5d8d243ea3c5d6",
        "LoD/1.09d": "0eb6c316488d30b6ee5d8d243ea3c5d6",
        "LoD/1.10": "0eb6c316488d30b6ee5d8d243ea3c5d6"
      }
    },
    "d2net.dll_CRT_StrICmpLocale": {
      "addresses": {
        "LoD/1.07": "0x6FC36220",
        "LoD/1.08": "0x6FC36220",
        "LoD/1.09": "0x6FC06220",
        "LoD/1.09b": "0x6FC06220",
        "LoD/1.09d": "0x6FC06220",
        "LoD/1.10": "0x6FC062C0"
      },
      "rvas": {
        "LoD/1.07": "0x6220",
        "LoD/1.08": "0x6220",
        "LoD/1.09": "0x6220",
        "LoD/1.09b": "0x6220",
        "LoD/1.09d": "0x6220",
        "LoD/1.10": "0x62C0"
      },
      "sizes": {
        "LoD/1.07": 208,
        "LoD/1.08": 208,
        "LoD/1.09": 208,
        "LoD/1.09b": 208,
        "LoD/1.09d": 208,
        "LoD/1.10": 208
      },
      "name": "CRT_StrICmpLocale",
      "signature": "int CRT_StrICmpLocale(void * this, byte * pbStr1, byte * pbStr2)",
      "calling_convention": "__thiscall",
      "comment": "CRT case-insensitive string comparison with locale awareness (_stricmp).\n\nClassification: Worker function - CRT string comparison utility.\n\nAlgorithm:\n1. Save current locale reference count\n2. Check if thread locale ID is zero (C locale / no locale)\n3. If C locale (fast path):\n   a. Initialize comparison byte to 0xFF (non-zero sentinel)\n   b. Loop: Load bytes from both strings, advance pointers\n   c. If bytes equal, continue until null terminator\n   d. If bytes differ, convert both to lowercase using inline arithmetic:\n      - Subtract 0x41 ('A'), check if < 0x1A (26 letters)\n      - If uppercase, add 0x20 to convert to lowercase\n      - Add 0x41 back to restore character value\n   e. Compare lowercase bytes; if equal continue loop\n   f. Return -1 if str1 < str2, 0 if equal, 1 if str1 > str2\n4. If locale set (slow path):\n   a. Atomically increment g_nLocaleRefCount (LOCK INC)\n   b. If g_fLocaleInitRequired > 0, enter critical section 0x13\n   c. Loop: Load bytes from both strings\n   d. If bytes differ, call CRT_ToLowerLocale on each\n   e. Compare lowercase results\n   f. Return comparison result\n   g. Atomically decrement g_nLocaleRefCount or leave critical section\n\nParameters:\n  lpszStr1 (byte *) - First null-terminated string to compare\n  lpszStr2 (byte *) - Second null-terminated string to compare\n\nReturns:\n  int - Comparison result:\n    <0 (typically -1): lpszStr1 < lpszStr2 (case-insensitive)\n     0: strings are equal (case-insensitive)\n    >0 (typically 1): lpszStr1 > lpszStr2 (case-insensitive)\n\nSpecial Cases:\n  - Empty strings: Returns 0 (equal)\n  - One empty string: Returns based on first char of non-empty string\n  - Identical strings: Fast path exits immediately on match\n\nGlobal Data:\n  g_dwThreadLocaleId (0x6fc3b420) - Thread locale ID; 0 = C locale\n  g_nLocaleRefCount (0x6fc3b58c) - Locale usage reference count\n  g_fLocaleInitRequired (0x6fc3b588) - Flag indicating locale needs init\n\nMagic Numbers:\n  0x41 = 'A' (ASCII uppercase A)\n  0xBF = -65 (0x41 subtracted as signed, wraps)\n  0x1A = 26 (number of letters in alphabet)\n  0x20 = 32 (case difference between upper/lower)\n  0x13 = 19 (CRT critical section index for locale)\n  0xFF = Initial comparison byte (non-null sentinel)\n\nCalls: CRT_EnterCritSectByIndex, CRT_LeaveCritSectByIndex, CRT_ToLowerLocale",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:8c1ef08c13327b78f680f81ff5d26364",
      "basic_block_counts": {
        "LoD/1.07": 20,
        "LoD/1.08": 20,
        "LoD/1.09": 20,
        "LoD/1.09b": 20,
        "LoD/1.09d": 20,
        "LoD/1.10": 20
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "8c1ef08c13327b78f680f81ff5d26364",
        "LoD/1.08": "8c1ef08c13327b78f680f81ff5d26364",
        "LoD/1.09": "8c1ef08c13327b78f680f81ff5d26364",
        "LoD/1.09b": "8c1ef08c13327b78f680f81ff5d26364",
        "LoD/1.09d": "8c1ef08c13327b78f680f81ff5d26364",
        "LoD/1.10": "8c1ef08c13327b78f680f81ff5d26364"
      }
    },
    "d2net.dll_CRT_strnicmp": {
      "addresses": {
        "LoD/1.07": "0x6FC362F0",
        "LoD/1.08": "0x6FC362F0",
        "LoD/1.09": "0x6FC062F0",
        "LoD/1.09b": "0x6FC062F0",
        "LoD/1.09d": "0x6FC062F0",
        "LoD/1.10": "0x6FC06390"
      },
      "rvas": {
        "LoD/1.07": "0x62F0",
        "LoD/1.08": "0x62F0",
        "LoD/1.09": "0x62F0",
        "LoD/1.09b": "0x62F0",
        "LoD/1.09d": "0x62F0",
        "LoD/1.10": "0x6390"
      },
      "sizes": {
        "LoD/1.07": 257,
        "LoD/1.08": 257,
        "LoD/1.09": 257,
        "LoD/1.09b": 257,
        "LoD/1.09d": 257,
        "LoD/1.10": 257
      },
      "name": "CRT_strnicmp",
      "signature": "int CRT_strnicmp(char * lpszStr1, char * lpszStr2, int nMaxCount)",
      "calling_convention": "__cdecl",
      "comment": "CRT_strnicmp - Case-insensitive string comparison up to n characters.\n\nStandard CRT _strnicmp implementation with locale support. Compares two\nstrings lexicographically, ignoring case, up to nMaxCount characters.\n\nAlgorithm:\n1. If nMaxCount is 0, return 0 (strings equal by definition)\n2. Check if thread-specific locale is configured (g_dwThreadLocaleId)\n3. IF no locale configured (simple ASCII mode):\n   a. Loop through characters while nMaxCount > 0\n   b. Load byte from lpszStr1 into AH, byte from lpszStr2 into AL\n   c. If either character is null terminator, exit loop\n   d. Convert AH to lowercase if in range 'A'-'Z' (0x41-0x5A) by adding 0x20\n   e. Convert AL to lowercase if in range 'A'-'Z' (0x41-0x5A) by adding 0x20\n   f. Compare lowercased characters; if different, compute return value\n   g. Decrement nMaxCount and continue\n   h. Return 0 if equal, -1 if str1 < str2, +1 if str1 > str2\n4. ELSE (locale-aware mode):\n   a. Increment global locale reference count (atomic LOCK INC)\n   b. If locale initialization required, enter critical section 0x13\n   c. Loop through characters calling FUN_6fc364e5 for locale-aware lowercase\n   d. Compare lowercased characters\n   e. Decrement reference count or leave critical section on exit\n   f. Return comparison result\n\nParameters:\n  lpszStr1 - First null-terminated string to compare\n  lpszStr2 - Second null-terminated string to compare\n  nMaxCount - Maximum number of characters to compare\n\nReturns:\n  0  - Strings are equal (case-insensitive) up to nMaxCount characters\n  -1 - lpszStr1 is less than lpszStr2 lexicographically\n  +1 - lpszStr1 is greater than lpszStr2 lexicographically\n\nSpecial Cases:\n  - If nMaxCount is 0, returns 0 immediately\n  - Null terminators end comparison early\n  - Thread-safe via atomic increment/decrement of locale ref count\n\nMagic Numbers:\n  0x41 (65) - ASCII 'A'\n  0x5A (90) - ASCII 'Z'\n  0x20 (32) - Offset to convert uppercase to lowercase ASCII\n  0x13 (19) - Critical section index for locale operations",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:662566ebcde3842108cf876001e2ae79",
      "basic_block_counts": {
        "LoD/1.07": 31,
        "LoD/1.08": 31,
        "LoD/1.09": 31,
        "LoD/1.09b": 31,
        "LoD/1.09d": 31,
        "LoD/1.10": 31
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "662566ebcde3842108cf876001e2ae79",
        "LoD/1.08": "662566ebcde3842108cf876001e2ae79",
        "LoD/1.09": "662566ebcde3842108cf876001e2ae79",
        "LoD/1.09b": "662566ebcde3842108cf876001e2ae79",
        "LoD/1.09d": "662566ebcde3842108cf876001e2ae79",
        "LoD/1.10": "662566ebcde3842108cf876001e2ae79"
      }
    },
    "d2net.dll__aulldiv": {
      "addresses": {
        "LoD/1.07": "0x6FC36400",
        "LoD/1.08": "0x6FC36400",
        "LoD/1.09": "0x6FC06400",
        "LoD/1.09b": "0x6FC06400",
        "LoD/1.09d": "0x6FC06400",
        "LoD/1.10": "0x6FC064A0"
      },
      "rvas": {
        "LoD/1.07": "0x6400",
        "LoD/1.08": "0x6400",
        "LoD/1.09": "0x6400",
        "LoD/1.09b": "0x6400",
        "LoD/1.09d": "0x6400",
        "LoD/1.10": "0x64A0"
      },
      "sizes": {
        "LoD/1.07": 104,
        "LoD/1.08": 104,
        "LoD/1.09": 104,
        "LoD/1.09b": 104,
        "LoD/1.09d": 104,
        "LoD/1.10": 104
      },
      "name": "_aulldiv",
      "signature": "ulonglong _aulldiv(ulonglong qwDividend, ulonglong qwDivisor)",
      "calling_convention": "__stdcall",
      "comment": "MSVC Compiler Helper: Unsigned 64-bit Division (_aulldiv)\n\nClassification: Leaf function - compiler runtime support\n\nPerforms unsigned 64-bit integer division of qwDividend by qwDivisor.\nThis is a standard MSVC compiler helper for 64-bit arithmetic on 32-bit x86.\n\nAlgorithm:\n1. Save EBX, ESI registers\n2. Load high DWORD of divisor from [ESP+0x18]\n3. If high DWORD is zero (fast path):\n   a. Load low DWORD divisor into ECX\n   b. Load high DWORD dividend into EAX\n   c. XOR EDX,EDX and DIV ECX -> quotient high in EBX\n   d. Load low DWORD dividend into EAX\n   e. DIV ECX -> quotient low in EAX\n   f. Move EBX to EDX for high result\n4. Else (slow path - full 64-bit division):\n   a. Load all operands into registers\n   b. Shift both dividend and divisor right until divisor fits in 32 bits\n   c. Perform 32-bit division to get approximate quotient\n   d. Multiply quotient by original divisor\n   e. Adjust if product exceeds original dividend\n   f. Return quotient in EDX:EAX\n5. Restore ESI, EBX and return (RET 0x10 cleans 16 bytes)\n\nParameters:\n  qwDividend (ulonglong) - Stack offset +0x04 to +0x0B\n    64-bit unsigned dividend (low DWORD at +0x04, high DWORD at +0x08)\n  qwDivisor (ulonglong) - Stack offset +0x0C to +0x13\n    64-bit unsigned divisor (low DWORD at +0x0C, high DWORD at +0x10)\n\nReturns:\n  ulonglong - 64-bit unsigned quotient in EDX:EAX register pair\n\nCalling Convention: __stdcall\n  - Parameters passed on stack, right-to-left\n  - Callee cleans stack (RET 0x10 = 16 bytes)\n  - Preserves EBX, ESI\n\nMemory Model:\n  - Stack frame: 16 bytes of parameters, no local variables\n  - No heap allocation\n  - Clobbers: EAX, ECX, EDX (return value in EDX:EAX)\n\nGHIDRA NOTE: Function body incomplete - only first instruction defined.\nActual function spans 0x6fc36400 to 0x6fc36467 (104 bytes).\nTo fix: Delete function, disassemble full range, recreate function.",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:9e01ab6a0c2f67c73794c17804322b4d",
      "basic_block_counts": {
        "LoD/1.07": 11,
        "LoD/1.08": 11,
        "LoD/1.09": 11,
        "LoD/1.09b": 11,
        "LoD/1.09d": 11,
        "LoD/1.10": 11
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "9e01ab6a0c2f67c73794c17804322b4d",
        "LoD/1.08": "9e01ab6a0c2f67c73794c17804322b4d",
        "LoD/1.09": "9e01ab6a0c2f67c73794c17804322b4d",
        "LoD/1.09b": "9e01ab6a0c2f67c73794c17804322b4d",
        "LoD/1.09d": "9e01ab6a0c2f67c73794c17804322b4d",
        "LoD/1.10": "9e01ab6a0c2f67c73794c17804322b4d"
      }
    },
    "d2net.dll__aullrem": {
      "addresses": {
        "LoD/1.07": "0x6FC36470",
        "LoD/1.08": "0x6FC36470",
        "LoD/1.09": "0x6FC06470",
        "LoD/1.09b": "0x6FC06470",
        "LoD/1.09d": "0x6FC06470",
        "LoD/1.10": "0x6FC06510"
      },
      "rvas": {
        "LoD/1.07": "0x6470",
        "LoD/1.08": "0x6470",
        "LoD/1.09": "0x6470",
        "LoD/1.09b": "0x6470",
        "LoD/1.09d": "0x6470",
        "LoD/1.10": "0x6510"
      },
      "sizes": {
        "LoD/1.07": 117,
        "LoD/1.08": 117,
        "LoD/1.09": 117,
        "LoD/1.09b": 117,
        "LoD/1.09d": 117,
        "LoD/1.10": 117
      },
      "name": "_aullrem",
      "signature": "ulonglong _aullrem(ulonglong ullDividend, ulonglong ullDivisor)",
      "calling_convention": "__stdcall",
      "comment": "_aullrem - Microsoft CRT unsigned 64-bit remainder helper function.\n\nClassification: Leaf function (compiler-generated CRT helper)\n\nFUNCTION BODY STATUS: BROKEN\n- Ghidra shows only single instruction (PUSH EBX)\n- Actual code: 0x6fc36470 to 0x6fc364e7 (0x78 bytes)\n- Bytes after first instruction marked as undefined data\n- Fix: Run Script Manager -> RecreateFunction_6fc36470.java\n\nAlgorithm:\n1. Save EBX register\n2. Load high DWORD of divisor [ESP+0x14]\n3. Test if high DWORD is zero (32-bit divisor case)\n4. If divisor fits in 32 bits (JNZ skipped):\n   a. Load high DWORD of dividend [ESP+0x10] into ECX\n   b. Load low DWORD of dividend [ESP+0x0C] into EAX\n   c. XOR EDX to zero\n   d. DIV ECX - divide high:0 by divisor low\n   e. Load low DWORD of dividend [ESP+0x08] into EAX\n   f. DIV ECX - divide remainder:low by divisor\n   g. Move remainder (EDX) to EAX, zero EDX\n   h. Jump to return\n5. Else (64-bit divisor case):\n   a. Copy dividend and divisor to working registers\n   b. Normalize loop: right-shift both until divisor high DWORD is zero\n   c. Perform 32-bit division on normalized values\n   d. Multiply quotient by original divisor low DWORD\n   e. Add carry and quotient * divisor high DWORD\n   f. Compare result with original dividend\n   g. If result > dividend, subtract divisor (off-by-one fix)\n   h. Subtract product from dividend to get remainder\n   i. Negate result if needed (two's complement)\n6. Restore EBX and return (RET 0x10 cleans 16 bytes)\n\nParameters:\n  ullDividend (ulonglong) - 64-bit unsigned dividend\n    [ESP+0x04] = low DWORD\n    [ESP+0x08] = high DWORD\n  ullDivisor (ulonglong) - 64-bit unsigned divisor\n    [ESP+0x0C] = low DWORD\n    [ESP+0x10] = high DWORD\n\nReturns:\n  ulonglong - 64-bit remainder (ullDividend % ullDivisor)\n    EAX = low DWORD of result\n    EDX = high DWORD of result\n\nSpecial Cases:\n  - If divisor is 0, behavior is undefined (hardware exception)\n  - If divisor fits in 32 bits, uses faster 2-division path\n  - 64-bit divisor path uses iterative normalization\n\nCalling Convention: __stdcall\n  - Parameters passed on stack (16 bytes)\n  - Callee cleans stack via RET 0x10\n  - Result returned in EDX:EAX\n\nRelated Functions:\n  _aulldiv @ 0x6fc36400 - Unsigned 64-bit division\n\nNote: Standard MSVC CRT helper, identical to ullrem.asm source.",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:e318b2efa2b7ed9dcb619fe5ba3fc2d5",
      "basic_block_counts": {
        "LoD/1.07": 11,
        "LoD/1.08": 11,
        "LoD/1.09": 11,
        "LoD/1.09b": 11,
        "LoD/1.09d": 11,
        "LoD/1.10": 11
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "e318b2efa2b7ed9dcb619fe5ba3fc2d5",
        "LoD/1.08": "e318b2efa2b7ed9dcb619fe5ba3fc2d5",
        "LoD/1.09": "e318b2efa2b7ed9dcb619fe5ba3fc2d5",
        "LoD/1.09b": "e318b2efa2b7ed9dcb619fe5ba3fc2d5",
        "LoD/1.09d": "e318b2efa2b7ed9dcb619fe5ba3fc2d5",
        "LoD/1.10": "e318b2efa2b7ed9dcb619fe5ba3fc2d5"
      }
    },
    "d2net.dll_CRT_ToLowerLocale": {
      "addresses": {
        "LoD/1.07": "0x6FC364E5",
        "LoD/1.08": "0x6FC364E5",
        "LoD/1.09": "0x6FC064E5",
        "LoD/1.09b": "0x6FC064E5",
        "LoD/1.09d": "0x6FC064E5",
        "LoD/1.10": "0x6FC06585"
      },
      "rvas": {
        "LoD/1.07": "0x64E5",
        "LoD/1.08": "0x64E5",
        "LoD/1.09": "0x64E5",
        "LoD/1.09b": "0x64E5",
        "LoD/1.09d": "0x64E5",
        "LoD/1.10": "0x6585"
      },
      "sizes": {
        "LoD/1.07": 203,
        "LoD/1.08": 203,
        "LoD/1.09": 203,
        "LoD/1.09b": 203,
        "LoD/1.09d": 203,
        "LoD/1.10": 203
      },
      "name": "CRT_ToLowerLocale",
      "signature": "void * CRT_ToLowerLocale(void * this, void * dwCharCode)",
      "calling_convention": "__thiscall",
      "comment": "CRT_ToLowerLocale - Converts a character to lowercase using locale-aware mapping.\n\nClassification: Worker function (internal CRT utility for case conversion)\n\nAlgorithm:\n1. If g_dwThreadLocaleId == 0 (C locale):\n   a. Check if character is ASCII uppercase (0x41-0x5A / 'A'-'Z')\n   b. If uppercase, add 0x20 to convert to lowercase\n   c. Return result\n2. If locale-aware mode (g_dwThreadLocaleId != 0):\n   a. Set initial byte length = 1\n   b. If character < 0x100 (single-byte range):\n      - If g_dwMultiByteMode < 2: lookup C1_UPPER flag (0x01) from g_pCharTypeTable\n      - Else: call GetCharTypeMask to get character type\n      - If not uppercase (flag == 0), return character unchanged\n   c. Check if high byte is DBCS lead byte (0x80 flag in char type table):\n      - If single-byte: build 1-byte MBCS sequence [char, 0]\n      - If DBCS: build 2-byte sequence [high, low, 0], set length = 2\n   d. Call CRT_LCMapStringMB with LCMAP_LOWERCASE (0x100) flag\n   e. If conversion succeeded:\n      - If result length == 1: extract single byte result\n      - If result length == 2: combine high/low bytes into result\n3. Return converted character\n\nParameters:\n  this (void *) - IMPLICIT: __thiscall parameter (unused, temp storage for API)\n  dwCharCode (uint) - Character code to convert (ASCII, MBCS, or Unicode code point)\n\nReturns:\n  uint - Lowercase character code, or original if no lowercase mapping exists\n\nSpecial Cases:\n  - C locale (g_dwThreadLocaleId == 0): Only ASCII A-Z converted\n  - Non-uppercase characters return unchanged\n  - DBCS characters handled as 2-byte sequences\n  - Characters >= 0x100 always go through locale API path\n\nMagic Numbers:\n  0x41 (65) - ASCII 'A'\n  0x5A (90) - ASCII 'Z'  \n  0x20 (32) - Case offset between uppercase and lowercase ASCII\n  0x100 (256) - LCMAP_LOWERCASE flag for LCMapString\n  0x80 - DBCS lead byte indicator in character type table\n  0x01 - C1_UPPER character type flag\n\nGlobal Variables:\n  g_dwThreadLocaleId @ 0x6fc3b420 - Current thread locale ID (0 = C locale)\n  g_dwMultiByteMode @ 0x6fc3ad04 - Multibyte character handling mode\n  g_pCharTypeTable @ 0x6fc3aaf8 - Pointer to character type lookup table (CT_CTYPE1 flags)\n\nCallers:\n  CRT_StrICmpLocale - Case-insensitive string comparison\n  CRT_strnicmp - Case-insensitive string comparison with length",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:cc0e19248bdb90cb6bf790db102f9ddf",
      "basic_block_counts": {
        "LoD/1.07": 18,
        "LoD/1.08": 18,
        "LoD/1.09": 18,
        "LoD/1.09b": 18,
        "LoD/1.09d": 18,
        "LoD/1.10": 18
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "cc0e19248bdb90cb6bf790db102f9ddf",
        "LoD/1.08": "cc0e19248bdb90cb6bf790db102f9ddf",
        "LoD/1.09": "cc0e19248bdb90cb6bf790db102f9ddf",
        "LoD/1.09b": "cc0e19248bdb90cb6bf790db102f9ddf",
        "LoD/1.09d": "cc0e19248bdb90cb6bf790db102f9ddf",
        "LoD/1.10": "cc0e19248bdb90cb6bf790db102f9ddf"
      }
    },
    "d2net.dll___WSAFDIsSet": {
      "addresses": {
        "LoD/1.07": "0x6FC365E4",
        "LoD/1.08": "0x6FC365E4",
        "LoD/1.09": "0x6FC065E4",
        "LoD/1.09b": "0x6FC065E4",
        "LoD/1.09d": "0x6FC065E4",
        "LoD/1.10": "0x6FC06684",
        "LoD/1.11": "0x6FBF5D6A",
        "LoD/1.11b": "0x6FBF5D70",
        "LoD/1.12a": "0x6FBF5DDA",
        "LoD/1.13c": "0x6FBF5DDA",
        "LoD/1.13d": "0x6FBF5D6A"
      },
      "rvas": {
        "LoD/1.07": "0x65E4",
        "LoD/1.08": "0x65E4",
        "LoD/1.09": "0x65E4",
        "LoD/1.09b": "0x65E4",
        "LoD/1.09d": "0x65E4",
        "LoD/1.10": "0x6684",
        "LoD/1.11": "0x5D6A",
        "LoD/1.11b": "0x5D70",
        "LoD/1.12a": "0x5DDA",
        "LoD/1.13c": "0x5DDA",
        "LoD/1.13d": "0x5D6A"
      },
      "sizes": {
        "LoD/1.07": 6,
        "LoD/1.08": 6,
        "LoD/1.09": 6,
        "LoD/1.09b": 6,
        "LoD/1.09d": 6,
        "LoD/1.10": 6,
        "LoD/1.11": 6,
        "LoD/1.11b": 6,
        "LoD/1.12a": 6,
        "LoD/1.13c": 6,
        "LoD/1.13d": 6
      },
      "name": "__WSAFDIsSet",
      "signature": "int __WSAFDIsSet(SOCKET param_1, fd_set * param_2)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:e3e7225badfcf3c2e051c42d71d7237a",
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1,
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.08": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09d": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.10": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.12a": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13c": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13d": "e3e7225badfcf3c2e051c42d71d7237a"
      }
    },
    "d2net.dll_RtlUnwind": {
      "addresses": {
        "LoD/1.07": "0x6FC365EA",
        "LoD/1.08": "0x6FC365EA",
        "LoD/1.09": "0x6FC065EA",
        "LoD/1.09b": "0x6FC065EA",
        "LoD/1.09d": "0x6FC065EA",
        "LoD/1.10": "0x6FC0668A",
        "LoD/1.11": "0x6FBF5D5E",
        "LoD/1.11b": "0x6FBF5D5E",
        "LoD/1.12a": "0x6FBF5DCE",
        "LoD/1.13c": "0x6FBF5DCE",
        "LoD/1.13d": "0x6FBF5D5E"
      },
      "rvas": {
        "LoD/1.07": "0x65EA",
        "LoD/1.08": "0x65EA",
        "LoD/1.09": "0x65EA",
        "LoD/1.09b": "0x65EA",
        "LoD/1.09d": "0x65EA",
        "LoD/1.10": "0x668A",
        "LoD/1.11": "0x5D5E",
        "LoD/1.11b": "0x5D5E",
        "LoD/1.12a": "0x5DCE",
        "LoD/1.13c": "0x5DCE",
        "LoD/1.13d": "0x5D5E"
      },
      "sizes": {
        "LoD/1.07": 6,
        "LoD/1.08": 6,
        "LoD/1.09": 6,
        "LoD/1.09b": 6,
        "LoD/1.09d": 6,
        "LoD/1.10": 6,
        "LoD/1.11": 6,
        "LoD/1.11b": 6,
        "LoD/1.12a": 6,
        "LoD/1.13c": 6,
        "LoD/1.13d": 6
      },
      "name": "RtlUnwind",
      "signature": "void RtlUnwind(PVOID TargetFrame, PVOID TargetIp, PEXCEPTION_RECORD ExceptionRecord, PVOID ReturnValue)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:e3e7225badfcf3c2e051c42d71d7237a",
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1,
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.08": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.09d": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.10": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.12a": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13c": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13d": "e3e7225badfcf3c2e051c42d71d7237a"
      }
    },
    "d2net.dll_EXP_10007": {
      "addresses": {
        "LoD/1.10": "0x6FC01300",
        "LoD/1.11": "0x6FBF74D0",
        "LoD/1.11b": "0x6FBF6F30",
        "LoD/1.12a": "0x6FBF6E80",
        "LoD/1.13c": "0x6FBF7540",
        "LoD/1.13d": "0x6FBF6E10"
      },
      "rvas": {
        "LoD/1.10": "0x1300",
        "LoD/1.11": "0x74D0",
        "LoD/1.11b": "0x6F30",
        "LoD/1.12a": "0x6E80",
        "LoD/1.13c": "0x7540",
        "LoD/1.13d": "0x6E10"
      },
      "sizes": {
        "LoD/1.10": 15,
        "LoD/1.11": 160,
        "LoD/1.11b": 160,
        "LoD/1.12a": 160,
        "LoD/1.13c": 160,
        "LoD/1.13d": 160
      },
      "name": "Ordinal_10007",
      "signature": "undefined Ordinal_10007(undefined4 * param_1, uint param_2)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.10",
      "method": "EXP",
      "index": "EXP:10007",
      "callees": {
        "LoD/1.11": [
          "Ordinal_10042",
          "Ordinal_10018"
        ],
        "LoD/1.11b": [
          "AllocateMemoryWithTracking",
          "Ordinal_10018"
        ],
        "LoD/1.12a": [
          "AllocateMemoryWithTracking",
          "Ordinal_10015"
        ],
        "LoD/1.13c": [
          "AllocateMemoryWithTracking",
          "Ordinal_10002"
        ],
        "LoD/1.13d": [
          "AllocateMemoryWithTracking",
          "Ordinal_10012"
        ]
      },
      "strings": {
        "LoD/1.11": [
          "\"..\\\\Source\\\\D2Net\\\\SRC\\\\Client.cpp\""
        ],
        "LoD/1.11b": [
          "\"..\\\\Source\\\\D2Net\\\\SRC\\\\Client.cpp\""
        ],
        "LoD/1.12a": [
          "\"..\\\\Source\\\\D2Net\\\\SRC\\\\Client.cpp\""
        ],
        "LoD/1.13c": [
          "\"..\\\\Source\\\\D2Net\\\\SRC\\\\Client.cpp\""
        ],
        "LoD/1.13d": [
          "\"..\\\\Source\\\\D2Net\\\\SRC\\\\Client.cpp\""
        ]
      },
      "basic_block_counts": {
        "LoD/1.10": 1,
        "LoD/1.11": 4,
        "LoD/1.11b": 4,
        "LoD/1.12a": 4,
        "LoD/1.13c": 4,
        "LoD/1.13d": 4
      },
      "loop_counts": {
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.10": "6bf7fd11028bc7338456190299049511",
        "LoD/1.11": "5026bda7564f6c57a1513df914fb323d",
        "LoD/1.11b": "5026bda7564f6c57a1513df914fb323d",
        "LoD/1.12a": "5026bda7564f6c57a1513df914fb323d",
        "LoD/1.13c": "5026bda7564f6c57a1513df914fb323d",
        "LoD/1.13d": "5026bda7564f6c57a1513df914fb323d"
      }
    },
    "d2net.dll_EXP_10008": {
      "addresses": {
        "LoD/1.10": "0x6FC01310"
      },
      "rvas": {
        "LoD/1.10": "0x1310"
      },
      "sizes": {
        "LoD/1.10": 15
      },
      "name": "Ordinal_10008",
      "signature": "undefined Ordinal_10008(undefined4 * param_1, uint param_2)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.10",
      "method": "EXP",
      "index": "EXP:10008",
      "basic_block_counts": {
        "LoD/1.10": 1
      },
      "loop_counts": {
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.10": "6bf7fd11028bc7338456190299049511"
      }
    },
    "d2net.dll_BinkBufferGetError": {
      "addresses": {
        "LoD/1.10": "0x6FC01FA0",
        "LoD/1.11": "0x6FBF69F0",
        "LoD/1.11b": "0x6FBF7550",
        "LoD/1.12a": "0x6FBF63A0",
        "LoD/1.13c": "0x6FBF6A60",
        "LoD/1.13d": "0x6FBF6330"
      },
      "rvas": {
        "LoD/1.10": "0x1FA0",
        "LoD/1.11": "0x69F0",
        "LoD/1.11b": "0x7550",
        "LoD/1.12a": "0x63A0",
        "LoD/1.13c": "0x6A60",
        "LoD/1.13d": "0x6330"
      },
      "sizes": {
        "LoD/1.10": 6,
        "LoD/1.11": 6,
        "LoD/1.11b": 6,
        "LoD/1.12a": 6,
        "LoD/1.13c": 6,
        "LoD/1.13d": 6
      },
      "name": "BinkBufferGetError",
      "signature": "char * BinkBufferGetError(void)",
      "calling_convention": "__stdcall",
      "comment": "Retrieves pointer to the global Bink buffer error message string.\n\nAlgorithm:\n1. Return address of global error buffer array g_szErrorBuffer\n\nParameters:\nNone\n\nReturns:\nchar * - Pointer to null-terminated error message string in g_szErrorBuffer\n         The buffer contains the most recent error message from Bink buffer operations\n         Returns valid pointer to 256-byte character array (never NULL)\n\nSpecial Cases:\n- Function always returns same buffer address (0x1002f01c)\n- Error buffer is shared across all Bink buffer operations\n- Calling code should copy error message if persistence needed\n- Buffer content may be overwritten by subsequent Bink operations\n\nMagic Numbers Reference:\n0x1002f01c - Address of global error buffer g_szErrorBuffer (256 bytes)",
      "name_source": "LoD/1.10",
      "method": "MNE",
      "index": "MNE:7b4de9f0cf357b113d12e0c7e214792b",
      "basic_block_counts": {
        "LoD/1.10": 1,
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.10": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.11": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.11b": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.12a": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.13c": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.13d": "7b4de9f0cf357b113d12e0c7e214792b"
      }
    },
    "d2net.dll_BinkBufferGetError_1FB0": {
      "addresses": {
        "LoD/1.10": "0x6FC01FB0"
      },
      "rvas": {
        "LoD/1.10": "0x1FB0"
      },
      "sizes": {
        "LoD/1.10": 6
      },
      "name": "BinkBufferGetError",
      "signature": "char * BinkBufferGetError(void)",
      "calling_convention": "__stdcall",
      "comment": "Retrieves pointer to the global Bink buffer error message string.\n\nAlgorithm:\n1. Return address of global error buffer array g_szErrorBuffer\n\nParameters:\nNone\n\nReturns:\nchar * - Pointer to null-terminated error message string in g_szErrorBuffer\n         The buffer contains the most recent error message from Bink buffer operations\n         Returns valid pointer to 256-byte character array (never NULL)\n\nSpecial Cases:\n- Function always returns same buffer address (0x1002f01c)\n- Error buffer is shared across all Bink buffer operations\n- Calling code should copy error message if persistence needed\n- Buffer content may be overwritten by subsequent Bink operations\n\nMagic Numbers Reference:\n0x1002f01c - Address of global error buffer g_szErrorBuffer (256 bytes)",
      "name_source": "LoD/1.10",
      "method": "MNE",
      "index": "MNE:7b4de9f0cf357b113d12e0c7e214792b",
      "basic_block_counts": {
        "LoD/1.10": 1
      },
      "loop_counts": {
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.10": "7b4de9f0cf357b113d12e0c7e214792b"
      }
    },
    "d2net.dll_MNE_551ea07f3904": {
      "addresses": {
        "LoD/1.10": "0x6FC01FE0"
      },
      "rvas": {
        "LoD/1.10": "0x1FE0"
      },
      "sizes": {
        "LoD/1.10": 197
      },
      "name_source": "LoD/1.10",
      "method": "MNE",
      "index": "MNE:551ea07f390454f09f1c9f8ed9474b78",
      "callees": {
        "LoD/1.10": [
          "Ordinal_10031"
        ]
      },
      "basic_block_counts": {
        "LoD/1.10": 17
      },
      "loop_counts": {
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.10": "551ea07f390454f09f1c9f8ed9474b78"
      }
    },
    "d2net.dll_NET_WaitForSendEvent_2130": {
      "addresses": {
        "LoD/1.10": "0x6FC02130",
        "LoD/1.11": "0x6FBF60C0",
        "LoD/1.11b": "0x6FBF6240",
        "LoD/1.12a": "0x6FBF7230",
        "LoD/1.13c": "0x6FBF62B0",
        "LoD/1.13d": "0x6FBF70E0"
      },
      "rvas": {
        "LoD/1.10": "0x2130",
        "LoD/1.11": "0x60C0",
        "LoD/1.11b": "0x6240",
        "LoD/1.12a": "0x7230",
        "LoD/1.13c": "0x62B0",
        "LoD/1.13d": "0x70E0"
      },
      "sizes": {
        "LoD/1.10": 20,
        "LoD/1.11": 20,
        "LoD/1.11b": 20,
        "LoD/1.12a": 20,
        "LoD/1.13c": 20,
        "LoD/1.13d": 20
      },
      "name": "NET_WaitForSendEvent",
      "signature": "DWORD NET_WaitForSendEvent(DWORD dwTimeoutMs)",
      "calling_convention": "__stdcall",
      "comment": "Waits for network send operation to complete or timeout.\n\nPublic API wrapper (Ordinal 10002) that blocks the calling thread until\na network send event is signaled or the specified timeout elapses.\n\nAlgorithm:\n1. Load global network send event handle from g_dwNetSendCount\n2. Forward call to WaitForArchiveEvent with handle and timeout\n3. Return wait result to caller\n\nParameters:\n  dwTimeoutMs [in] - Wait timeout in milliseconds. Use INFINITE (0xFFFFFFFF)\n                     for indefinite wait.\n\nReturns:\n  DWORD - Wait result from WaitForArchiveEvent:\n    WAIT_OBJECT_0 (0) - Send event was signaled\n    WAIT_TIMEOUT (258) - Timeout elapsed before event signaled\n    WAIT_FAILED (0xFFFFFFFF) - Error occurred\n\nSpecial Cases:\n  - If g_dwNetSendCount is not initialized, behavior is undefined\n  - Timeout of 0 performs a non-blocking check\n\nRelated:\n  - Ordinal_10003: Initializes g_dwNetSendCount\n  - Ordinal_10004: Gets/sets send count state",
      "name_source": "LoD/1.10",
      "method": "MNE",
      "index": "MNE:0c7249cc723d27c36926c4cb05e7aa15",
      "callees": {
        "LoD/1.10": [
          "WaitOnObjectHandle"
        ],
        "LoD/1.11": [
          "FindHashTableEntryById"
        ],
        "LoD/1.11b": [
          "WaitOnObjectHandle"
        ],
        "LoD/1.12a": [
          "FindHashTableEntryById"
        ],
        "LoD/1.13c": [
          "WaitOnObjectHandle"
        ],
        "LoD/1.13d": [
          "SetUnitFieldBBC"
        ]
      },
      "basic_block_counts": {
        "LoD/1.10": 1,
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.10": "0c7249cc723d27c36926c4cb05e7aa15",
        "LoD/1.11": "0c7249cc723d27c36926c4cb05e7aa15",
        "LoD/1.11b": "0c7249cc723d27c36926c4cb05e7aa15",
        "LoD/1.12a": "0c7249cc723d27c36926c4cb05e7aa15",
        "LoD/1.13c": "0c7249cc723d27c36926c4cb05e7aa15",
        "LoD/1.13d": "0c7249cc723d27c36926c4cb05e7aa15"
      }
    },
    "d2net.dll_NET_WaitForSendEvent_2530": {
      "addresses": {
        "LoD/1.10": "0x6FC02530",
        "LoD/1.11": "0x6FBF5FE0",
        "LoD/1.11b": "0x6FBF5ED0",
        "LoD/1.12a": "0x6FBF7040",
        "LoD/1.13c": "0x6FBF6150",
        "LoD/1.13d": "0x6FBF71C0"
      },
      "rvas": {
        "LoD/1.10": "0x2530",
        "LoD/1.11": "0x5FE0",
        "LoD/1.11b": "0x5ED0",
        "LoD/1.12a": "0x7040",
        "LoD/1.13c": "0x6150",
        "LoD/1.13d": "0x71C0"
      },
      "sizes": {
        "LoD/1.10": 20,
        "LoD/1.11": 20,
        "LoD/1.11b": 20,
        "LoD/1.12a": 20,
        "LoD/1.13c": 20,
        "LoD/1.13d": 20
      },
      "name": "NET_WaitForSendEvent",
      "signature": "DWORD NET_WaitForSendEvent(DWORD dwTimeoutMs)",
      "calling_convention": "__stdcall",
      "comment": "Waits for network send operation to complete or timeout.\n\nPublic API wrapper (Ordinal 10002) that blocks the calling thread until\na network send event is signaled or the specified timeout elapses.\n\nAlgorithm:\n1. Load global network send event handle from g_dwNetSendCount\n2. Forward call to WaitForArchiveEvent with handle and timeout\n3. Return wait result to caller\n\nParameters:\n  dwTimeoutMs [in] - Wait timeout in milliseconds. Use INFINITE (0xFFFFFFFF)\n                     for indefinite wait.\n\nReturns:\n  DWORD - Wait result from WaitForArchiveEvent:\n    WAIT_OBJECT_0 (0) - Send event was signaled\n    WAIT_TIMEOUT (258) - Timeout elapsed before event signaled\n    WAIT_FAILED (0xFFFFFFFF) - Error occurred\n\nSpecial Cases:\n  - If g_dwNetSendCount is not initialized, behavior is undefined\n  - Timeout of 0 performs a non-blocking check\n\nRelated:\n  - Ordinal_10003: Initializes g_dwNetSendCount\n  - Ordinal_10004: Gets/sets send count state",
      "name_source": "LoD/1.10",
      "method": "MNE",
      "index": "MNE:0c7249cc723d27c36926c4cb05e7aa15",
      "callees": {
        "LoD/1.10": [
          "SetStructField0xBBC"
        ],
        "LoD/1.11": [
          "SetUnitFieldBBC"
        ],
        "LoD/1.11b": [
          "WaitOrProcessContextSlots"
        ],
        "LoD/1.12a": [
          "WaitOrProcessContextSlots"
        ],
        "LoD/1.13c": [
          "SearchHashTableEntry"
        ],
        "LoD/1.13d": [
          "FindHashTableEntryById"
        ]
      },
      "basic_block_counts": {
        "LoD/1.10": 1,
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.10": "0c7249cc723d27c36926c4cb05e7aa15",
        "LoD/1.11": "0c7249cc723d27c36926c4cb05e7aa15",
        "LoD/1.11b": "0c7249cc723d27c36926c4cb05e7aa15",
        "LoD/1.12a": "0c7249cc723d27c36926c4cb05e7aa15",
        "LoD/1.13c": "0c7249cc723d27c36926c4cb05e7aa15",
        "LoD/1.13d": "0c7249cc723d27c36926c4cb05e7aa15"
      }
    },
    "d2net.dll_WaitForArchiveEvent_26A0": {
      "addresses": {
        "LoD/1.10": "0x6FC026A0",
        "LoD/1.11": "0x6FBF5E2A",
        "LoD/1.11b": "0x6FBF5E2A",
        "LoD/1.12a": "0x6FBF5E6A",
        "LoD/1.13c": "0x6FBF5E9A",
        "LoD/1.13d": "0x6FBF5DFA"
      },
      "rvas": {
        "LoD/1.10": "0x26A0",
        "LoD/1.11": "0x5E2A",
        "LoD/1.11b": "0x5E2A",
        "LoD/1.12a": "0x5E6A",
        "LoD/1.13c": "0x5E9A",
        "LoD/1.13d": "0x5DFA"
      },
      "sizes": {
        "LoD/1.10": 6,
        "LoD/1.11": 6,
        "LoD/1.11b": 6,
        "LoD/1.12a": 6,
        "LoD/1.13c": 6,
        "LoD/1.13d": 6
      },
      "name": "WaitForArchiveEvent",
      "signature": "void WaitForArchiveEvent(void * pStruct, dword dwValue)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.10",
      "method": "MNE",
      "index": "MNE:e3e7225badfcf3c2e051c42d71d7237a",
      "basic_block_counts": {
        "LoD/1.10": 1,
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.10": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.12a": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13c": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13d": "e3e7225badfcf3c2e051c42d71d7237a"
      }
    },
    "d2net.dll_WaitForArchiveEvent_270C": {
      "addresses": {
        "LoD/1.10": "0x6FC0270C",
        "LoD/1.11": "0x6FBF5E36",
        "LoD/1.11b": "0x6FBF5E36",
        "LoD/1.12a": "0x6FBF5E76",
        "LoD/1.13c": "0x6FBF5EA6",
        "LoD/1.13d": "0x6FBF5E06"
      },
      "rvas": {
        "LoD/1.10": "0x270C",
        "LoD/1.11": "0x5E36",
        "LoD/1.11b": "0x5E36",
        "LoD/1.12a": "0x5E76",
        "LoD/1.13c": "0x5EA6",
        "LoD/1.13d": "0x5E06"
      },
      "sizes": {
        "LoD/1.10": 6,
        "LoD/1.11": 6,
        "LoD/1.11b": 6,
        "LoD/1.12a": 6,
        "LoD/1.13c": 6,
        "LoD/1.13d": 6
      },
      "name": "WaitForArchiveEvent",
      "signature": "uint WaitForArchiveEvent(void * pContext, uint dwTimeout)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.10",
      "method": "MNE",
      "index": "MNE:e3e7225badfcf3c2e051c42d71d7237a",
      "basic_block_counts": {
        "LoD/1.10": 1,
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.10": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.12a": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13c": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13d": "e3e7225badfcf3c2e051c42d71d7237a"
      }
    },
    "d2net.dll__memmove": {
      "addresses": {
        "LoD/1.11": "0x6FBF1000",
        "LoD/1.11b": "0x6FBF1000",
        "LoD/1.12a": "0x6FBF4570",
        "LoD/1.13c": "0x6FBF1000",
        "LoD/1.13d": "0x6FBF11C0"
      },
      "rvas": {
        "LoD/1.11": "0x1000",
        "LoD/1.11b": "0x1000",
        "LoD/1.12a": "0x4570",
        "LoD/1.13c": "0x1000",
        "LoD/1.13d": "0x11C0"
      },
      "sizes": {
        "LoD/1.11": 672,
        "LoD/1.11b": 672,
        "LoD/1.12a": 672,
        "LoD/1.13c": 672,
        "LoD/1.13d": 672
      },
      "name": "_memmove",
      "signature": "void * _memmove(void * _Dst, void * _Src, size_t _Size)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n _memmove\n\nLibraries: Visual Studio 2003 Debug, Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:378e464c38840f3332fec8fa0fd86d30",
      "basic_block_counts": {
        "LoD/1.11": 63,
        "LoD/1.11b": 63,
        "LoD/1.12a": 63,
        "LoD/1.13c": 63,
        "LoD/1.13d": 63
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "378e464c38840f3332fec8fa0fd86d30",
        "LoD/1.11b": "378e464c38840f3332fec8fa0fd86d30",
        "LoD/1.12a": "378e464c38840f3332fec8fa0fd86d30",
        "LoD/1.13c": "378e464c38840f3332fec8fa0fd86d30",
        "LoD/1.13d": "378e464c38840f3332fec8fa0fd86d30"
      }
    },
    "d2net.dll____crtExitProcess": {
      "addresses": {
        "LoD/1.11": "0x6FBF133D",
        "LoD/1.11b": "0x6FBF133D",
        "LoD/1.12a": "0x6FBF1000",
        "LoD/1.13c": "0x6FBF133D",
        "LoD/1.13d": "0x6FBF1000"
      },
      "rvas": {
        "LoD/1.11": "0x133D",
        "LoD/1.11b": "0x133D",
        "LoD/1.12a": "0x1000",
        "LoD/1.13c": "0x133D",
        "LoD/1.13d": "0x1000"
      },
      "sizes": {
        "LoD/1.11": 47,
        "LoD/1.11b": 47,
        "LoD/1.12a": 47,
        "LoD/1.13c": 47,
        "LoD/1.13d": 47
      },
      "name": "___crtExitProcess",
      "signature": "void ___crtExitProcess(int param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___crtExitProcess\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "STR",
      "index": "STR:c170bd72c7a30c3be9e6aa15fb836e49",
      "strings": {
        "LoD/1.11": [
          "\"CorExitProcess\"",
          "\"mscoree.dll\""
        ],
        "LoD/1.11b": [
          "\"CorExitProcess\"",
          "\"mscoree.dll\""
        ],
        "LoD/1.12a": [
          "\"CorExitProcess\"",
          "\"mscoree.dll\""
        ],
        "LoD/1.13c": [
          "\"CorExitProcess\"",
          "\"mscoree.dll\""
        ],
        "LoD/1.13d": [
          "\"CorExitProcess\"",
          "\"mscoree.dll\""
        ]
      },
      "basic_block_counts": {
        "LoD/1.11": 4,
        "LoD/1.11b": 4,
        "LoD/1.12a": 4,
        "LoD/1.13c": 4,
        "LoD/1.13d": 4
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "df0a04b7db34c5f035a394dc061ca513",
        "LoD/1.11b": "df0a04b7db34c5f035a394dc061ca513",
        "LoD/1.12a": "df0a04b7db34c5f035a394dc061ca513",
        "LoD/1.13c": "df0a04b7db34c5f035a394dc061ca513",
        "LoD/1.13d": "df0a04b7db34c5f035a394dc061ca513"
      }
    },
    "d2net.dll_AcquireFileHandleLock8": {
      "addresses": {
        "LoD/1.11": "0x6FBF1376",
        "LoD/1.11b": "0x6FBF1376",
        "LoD/1.12a": "0x6FBF1039",
        "LoD/1.13c": "0x6FBF1376",
        "LoD/1.13d": "0x6FBF1039"
      },
      "rvas": {
        "LoD/1.11": "0x1376",
        "LoD/1.11b": "0x1376",
        "LoD/1.12a": "0x1039",
        "LoD/1.13c": "0x1376",
        "LoD/1.13d": "0x1039"
      },
      "sizes": {
        "LoD/1.11": 9,
        "LoD/1.11b": 9,
        "LoD/1.12a": 9,
        "LoD/1.13c": 9,
        "LoD/1.13d": 9
      },
      "name": "AcquireFileHandleLock8",
      "signature": "void AcquireFileHandleLock8(void)",
      "calling_convention": "__stdcall",
      "comment": "Acquires the multi-threaded critical section lock for file handle 8.\n\nAlgorithm:\n1. Call __lock(8) to acquire the critical section for file handle 8\n2. Return to caller with lock held\n\nParameters:\nNone\n\nReturns:\nvoid - no return value. The function acquires a lock that persists until\nthe thread explicitly releases it or terminates.\n\nSpecial Cases:\n- Lock initialization: If lock initialization fails in __lock, the program\n  terminates with exit code 17\n- Shutdown synchronization: This function is registered as an exit handler\n  (via __onexit) and is called during program termination to ensure proper\n  cleanup of file I/O synchronization\n- Thread safety: The lock must be released before the thread exits to avoid\n  deadlock in other threads waiting on this same lock\n\nStructure Layout:\nThe file handle 8 lock is part of the Visual Studio C runtime's multi-threaded\nfile I/O synchronization array, indexed by the handle ID (0-7 for standard\nfile handles).",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:f23ef2b3a6cfdeb1f35221d5fc7b15e0",
      "basic_block_counts": {
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.11b": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.12a": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.13c": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.13d": "f23ef2b3a6cfdeb1f35221d5fc7b15e0"
      }
    },
    "d2net.dll___initterm": {
      "addresses": {
        "LoD/1.11": "0x6FBF137F",
        "LoD/1.11b": "0x6FBF137F",
        "LoD/1.12a": "0x6FBF1042",
        "LoD/1.13c": "0x6FBF137F",
        "LoD/1.13d": "0x6FBF1042"
      },
      "rvas": {
        "LoD/1.11": "0x137F",
        "LoD/1.11b": "0x137F",
        "LoD/1.12a": "0x1042",
        "LoD/1.13c": "0x137F",
        "LoD/1.13d": "0x1042"
      },
      "sizes": {
        "LoD/1.11": 24,
        "LoD/1.11b": 24,
        "LoD/1.12a": 24,
        "LoD/1.13c": 24,
        "LoD/1.13d": 24
      },
      "name": "__initterm",
      "signature": "undefined __initterm(undefined4 * param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __initterm\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:996e3f0c6129985d37a2b36d657b6892",
      "basic_block_counts": {
        "LoD/1.11": 6,
        "LoD/1.11b": 6,
        "LoD/1.12a": 6,
        "LoD/1.13c": 6,
        "LoD/1.13d": 6
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "996e3f0c6129985d37a2b36d657b6892",
        "LoD/1.11b": "996e3f0c6129985d37a2b36d657b6892",
        "LoD/1.12a": "996e3f0c6129985d37a2b36d657b6892",
        "LoD/1.13c": "996e3f0c6129985d37a2b36d657b6892",
        "LoD/1.13d": "996e3f0c6129985d37a2b36d657b6892"
      }
    },
    "d2net.dll___cinit": {
      "addresses": {
        "LoD/1.11": "0x6FBF1397",
        "LoD/1.11b": "0x6FBF1397",
        "LoD/1.12a": "0x6FBF105A",
        "LoD/1.13c": "0x6FBF1397",
        "LoD/1.13d": "0x6FBF105A"
      },
      "rvas": {
        "LoD/1.11": "0x1397",
        "LoD/1.11b": "0x1397",
        "LoD/1.12a": "0x105A",
        "LoD/1.13c": "0x1397",
        "LoD/1.13d": "0x105A"
      },
      "sizes": {
        "LoD/1.11": 106,
        "LoD/1.11b": 106,
        "LoD/1.12a": 106,
        "LoD/1.13c": 106,
        "LoD/1.13d": 106
      },
      "name": "__cinit",
      "signature": "int __cinit(int param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __cinit\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:28a1cba9ddfd9945ee3fec59104d67a8",
      "basic_block_counts": {
        "LoD/1.11": 14,
        "LoD/1.11b": 14,
        "LoD/1.12a": 14,
        "LoD/1.13c": 14,
        "LoD/1.13d": 14
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "28a1cba9ddfd9945ee3fec59104d67a8",
        "LoD/1.11b": "28a1cba9ddfd9945ee3fec59104d67a8",
        "LoD/1.12a": "28a1cba9ddfd9945ee3fec59104d67a8",
        "LoD/1.13c": "28a1cba9ddfd9945ee3fec59104d67a8",
        "LoD/1.13d": "28a1cba9ddfd9945ee3fec59104d67a8"
      }
    },
    "d2net.dll_ProcessTerminationHandler": {
      "addresses": {
        "LoD/1.11": "0x6FBF1401",
        "LoD/1.11b": "0x6FBF1401",
        "LoD/1.12a": "0x6FBF10C4",
        "LoD/1.13c": "0x6FBF1401",
        "LoD/1.13d": "0x6FBF10C4"
      },
      "rvas": {
        "LoD/1.11": "0x1401",
        "LoD/1.11b": "0x1401",
        "LoD/1.12a": "0x10C4",
        "LoD/1.13c": "0x1401",
        "LoD/1.13d": "0x10C4"
      },
      "sizes": {
        "LoD/1.11": 176,
        "LoD/1.11b": 176,
        "LoD/1.12a": 176,
        "LoD/1.13c": 176,
        "LoD/1.13d": 176
      },
      "name": "ProcessTerminationHandler",
      "signature": "void ProcessTerminationHandler(uint dwExitCode, int iSkipHandlers, int iExitLock)",
      "calling_convention": "__cdecl",
      "comment": "Setting prototype: void CrtExitHandler(uint dwExitCode, int iSkipHandlers, int iExitLock)",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:2ef7e47ffada49e021fc9ebda7c95a50",
      "basic_block_counts": {
        "LoD/1.11": 11,
        "LoD/1.11b": 11,
        "LoD/1.12a": 11,
        "LoD/1.13c": 11,
        "LoD/1.13d": 11
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "2ef7e47ffada49e021fc9ebda7c95a50",
        "LoD/1.11b": "2ef7e47ffada49e021fc9ebda7c95a50",
        "LoD/1.12a": "2ef7e47ffada49e021fc9ebda7c95a50",
        "LoD/1.13c": "2ef7e47ffada49e021fc9ebda7c95a50",
        "LoD/1.13d": "2ef7e47ffada49e021fc9ebda7c95a50"
      }
    },
    "d2net.dll_VerifyCriticalSectionExitLock": {
      "addresses": {
        "LoD/1.11": "0x6FBF14B0",
        "LoD/1.11b": "0x6FBF14B0",
        "LoD/1.12a": "0x6FBF1173",
        "LoD/1.13c": "0x6FBF14B0",
        "LoD/1.13d": "0x6FBF1173"
      },
      "rvas": {
        "LoD/1.11": "0x14B0",
        "LoD/1.11b": "0x14B0",
        "LoD/1.12a": "0x1173",
        "LoD/1.13c": "0x14B0",
        "LoD/1.13d": "0x1173"
      },
      "sizes": {
        "LoD/1.11": 14,
        "LoD/1.11b": 14,
        "LoD/1.12a": 14,
        "LoD/1.13c": 14,
        "LoD/1.13d": 14
      },
      "name": "VerifyCriticalSectionExitLock",
      "signature": "void VerifyCriticalSectionExitLock(void)",
      "calling_convention": "__stdcall",
      "comment": "Verifies that critical section exit lock state matches expected value.\n\nAlgorithm:\n1. Compare exit lock count at [EBP+0x10] with the EDI register (expected count)\n2. If values match (ZF set), skip to exit_lock_verified label\n3. If values don't match, push 8 (critical section index) and call LeaveCriticalSectionByIndex\n4. Pop return address and return to caller\n\nParameters:\nIMPLICIT - Implicit register parameters:\n- [EBP+0x10]: Exit lock count (stack-based synchronization counter)\n- EDI: Expected exit lock count to verify against\n\nReturns:\nvoid - No return value; used for side effects only (synchronization state verification)\n\nSpecial Cases:\n- Called during C runtime exit sequence (doexit) for cleanup\n- If lock counts mismatch, forces release of critical section 8\n- Part of Visual C++ runtime synchronization handling for multi-threaded cleanup\n- Uses __stdcall calling convention (callee cleans stack)",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:ca7f27832b0deaebe496b377f1c5001a",
      "basic_block_counts": {
        "LoD/1.11": 3,
        "LoD/1.11b": 3,
        "LoD/1.12a": 3,
        "LoD/1.13c": 3,
        "LoD/1.13d": 3
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "ca7f27832b0deaebe496b377f1c5001a",
        "LoD/1.11b": "ca7f27832b0deaebe496b377f1c5001a",
        "LoD/1.12a": "ca7f27832b0deaebe496b377f1c5001a",
        "LoD/1.13c": "ca7f27832b0deaebe496b377f1c5001a",
        "LoD/1.13d": "ca7f27832b0deaebe496b377f1c5001a"
      }
    },
    "d2net.dll___CRT_INIT@12": {
      "addresses": {
        "LoD/1.11": "0x6FBF14F5",
        "LoD/1.11b": "0x6FBF14F5",
        "LoD/1.12a": "0x6FBF14FD",
        "LoD/1.13c": "0x6FBF14F5",
        "LoD/1.13d": "0x6FBF14FD"
      },
      "rvas": {
        "LoD/1.11": "0x14F5",
        "LoD/1.11b": "0x14F5",
        "LoD/1.12a": "0x14FD",
        "LoD/1.13c": "0x14F5",
        "LoD/1.13d": "0x14FD"
      },
      "sizes": {
        "LoD/1.11": 385,
        "LoD/1.11b": 385,
        "LoD/1.12a": 385,
        "LoD/1.13c": 385,
        "LoD/1.13d": 385
      },
      "name": "__CRT_INIT@12",
      "signature": "undefined4 __CRT_INIT@12(undefined4 param_1, int param_2)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Single Match\n __CRT_INIT@12\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:1c48859ddf90d08dbf4d9d03c0c2a56a",
      "basic_block_counts": {
        "LoD/1.11": 29,
        "LoD/1.11b": 29,
        "LoD/1.12a": 29,
        "LoD/1.13c": 29,
        "LoD/1.13d": 29
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "1c48859ddf90d08dbf4d9d03c0c2a56a",
        "LoD/1.11b": "1c48859ddf90d08dbf4d9d03c0c2a56a",
        "LoD/1.12a": "1c48859ddf90d08dbf4d9d03c0c2a56a",
        "LoD/1.13c": "1c48859ddf90d08dbf4d9d03c0c2a56a",
        "LoD/1.13d": "1c48859ddf90d08dbf4d9d03c0c2a56a"
      }
    },
    "d2net.dll___DllMainCRTStartup@12": {
      "addresses": {
        "LoD/1.11": "0x6FBF1676",
        "LoD/1.11b": "0x6FBF1676",
        "LoD/1.12a": "0x6FBF167E",
        "LoD/1.13c": "0x6FBF1676",
        "LoD/1.13d": "0x6FBF167E"
      },
      "rvas": {
        "LoD/1.11": "0x1676",
        "LoD/1.11b": "0x1676",
        "LoD/1.12a": "0x167E",
        "LoD/1.13c": "0x1676",
        "LoD/1.13d": "0x167E"
      },
      "sizes": {
        "LoD/1.11": 208,
        "LoD/1.11b": 208,
        "LoD/1.12a": 208,
        "LoD/1.13c": 208,
        "LoD/1.13d": 208
      },
      "name": "__DllMainCRTStartup@12",
      "signature": "int __DllMainCRTStartup@12(undefined4 param_1, int param_2, int param_3)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Single Match\n __DllMainCRTStartup@12\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:e12afdedf65b4f2d4ddeab4188a67460",
      "basic_block_counts": {
        "LoD/1.11": 22,
        "LoD/1.11b": 22,
        "LoD/1.12a": 22,
        "LoD/1.13c": 22,
        "LoD/1.13d": 22
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "e12afdedf65b4f2d4ddeab4188a67460",
        "LoD/1.11b": "e12afdedf65b4f2d4ddeab4188a67460",
        "LoD/1.12a": "e12afdedf65b4f2d4ddeab4188a67460",
        "LoD/1.13c": "e12afdedf65b4f2d4ddeab4188a67460",
        "LoD/1.13d": "e12afdedf65b4f2d4ddeab4188a67460"
      }
    },
    "d2net.dll___mtinitlocks": {
      "addresses": {
        "LoD/1.11": "0x6FBF178D",
        "LoD/1.11b": "0x6FBF178D",
        "LoD/1.12a": "0x6FBF1795",
        "LoD/1.13c": "0x6FBF178D",
        "LoD/1.13d": "0x6FBF1795"
      },
      "rvas": {
        "LoD/1.11": "0x178D",
        "LoD/1.11b": "0x178D",
        "LoD/1.12a": "0x1795",
        "LoD/1.13c": "0x178D",
        "LoD/1.13d": "0x1795"
      },
      "sizes": {
        "LoD/1.11": 73,
        "LoD/1.11b": 73,
        "LoD/1.12a": 73,
        "LoD/1.13c": 73,
        "LoD/1.13d": 73
      },
      "name": "__mtinitlocks",
      "signature": "int __mtinitlocks(void)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __mtinitlocks\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:921d14ea2db8ace7085d489017738fb1",
      "basic_block_counts": {
        "LoD/1.11": 7,
        "LoD/1.11b": 7,
        "LoD/1.12a": 7,
        "LoD/1.13c": 7,
        "LoD/1.13d": 7
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "921d14ea2db8ace7085d489017738fb1",
        "LoD/1.11b": "921d14ea2db8ace7085d489017738fb1",
        "LoD/1.12a": "921d14ea2db8ace7085d489017738fb1",
        "LoD/1.13c": "921d14ea2db8ace7085d489017738fb1",
        "LoD/1.13d": "921d14ea2db8ace7085d489017738fb1"
      }
    },
    "d2net.dll___mtdeletelocks": {
      "addresses": {
        "LoD/1.11": "0x6FBF17D6",
        "LoD/1.11b": "0x6FBF17D6",
        "LoD/1.12a": "0x6FBF17DE",
        "LoD/1.13c": "0x6FBF17D6",
        "LoD/1.13d": "0x6FBF17DE"
      },
      "rvas": {
        "LoD/1.11": "0x17D6",
        "LoD/1.11b": "0x17D6",
        "LoD/1.12a": "0x17DE",
        "LoD/1.13c": "0x17D6",
        "LoD/1.13d": "0x17DE"
      },
      "sizes": {
        "LoD/1.11": 85,
        "LoD/1.11b": 85,
        "LoD/1.12a": 85,
        "LoD/1.13c": 85,
        "LoD/1.13d": 85
      },
      "name": "__mtdeletelocks",
      "signature": "void __mtdeletelocks(void)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __mtdeletelocks\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:3d673ff0fb622876ea58c1a43b2af6a0",
      "basic_block_counts": {
        "LoD/1.11": 11,
        "LoD/1.11b": 11,
        "LoD/1.12a": 11,
        "LoD/1.13c": 11,
        "LoD/1.13d": 11
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "3d673ff0fb622876ea58c1a43b2af6a0",
        "LoD/1.11b": "3d673ff0fb622876ea58c1a43b2af6a0",
        "LoD/1.12a": "3d673ff0fb622876ea58c1a43b2af6a0",
        "LoD/1.13c": "3d673ff0fb622876ea58c1a43b2af6a0",
        "LoD/1.13d": "3d673ff0fb622876ea58c1a43b2af6a0"
      }
    },
    "d2net.dll___mtinitlocknum": {
      "addresses": {
        "LoD/1.11": "0x6FBF1840",
        "LoD/1.11b": "0x6FBF1840",
        "LoD/1.12a": "0x6FBF1848",
        "LoD/1.13c": "0x6FBF1840",
        "LoD/1.13d": "0x6FBF1848"
      },
      "rvas": {
        "LoD/1.11": "0x1840",
        "LoD/1.11b": "0x1840",
        "LoD/1.12a": "0x1848",
        "LoD/1.13c": "0x1840",
        "LoD/1.13d": "0x1848"
      },
      "sizes": {
        "LoD/1.11": 151,
        "LoD/1.11b": 151,
        "LoD/1.12a": 151,
        "LoD/1.13c": 151,
        "LoD/1.13d": 151
      },
      "name": "__mtinitlocknum",
      "signature": "int __mtinitlocknum(int _LockNum)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __mtinitlocknum\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:a51a9a5e7ceb2fab96b937dc9f784c13",
      "basic_block_counts": {
        "LoD/1.11": 12,
        "LoD/1.11b": 12,
        "LoD/1.12a": 12,
        "LoD/1.13c": 12,
        "LoD/1.13d": 12
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "a51a9a5e7ceb2fab96b937dc9f784c13",
        "LoD/1.11b": "a51a9a5e7ceb2fab96b937dc9f784c13",
        "LoD/1.12a": "a51a9a5e7ceb2fab96b937dc9f784c13",
        "LoD/1.13c": "a51a9a5e7ceb2fab96b937dc9f784c13",
        "LoD/1.13d": "a51a9a5e7ceb2fab96b937dc9f784c13"
      }
    },
    "d2net.dll___lock": {
      "addresses": {
        "LoD/1.11": "0x6FBF18E0",
        "LoD/1.11b": "0x6FBF18E0",
        "LoD/1.12a": "0x6FBF18E8",
        "LoD/1.13c": "0x6FBF18E0",
        "LoD/1.13d": "0x6FBF18E8"
      },
      "rvas": {
        "LoD/1.11": "0x18E0",
        "LoD/1.11b": "0x18E0",
        "LoD/1.12a": "0x18E8",
        "LoD/1.13c": "0x18E0",
        "LoD/1.13d": "0x18E8"
      },
      "sizes": {
        "LoD/1.11": 49,
        "LoD/1.11b": 49,
        "LoD/1.12a": 49,
        "LoD/1.13c": 49,
        "LoD/1.13d": 49
      },
      "name": "__lock",
      "signature": "void __lock(int _File)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __lock\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:a62c5e213216063061d4d1c8c7db89e8",
      "basic_block_counts": {
        "LoD/1.11": 4,
        "LoD/1.11b": 4,
        "LoD/1.12a": 4,
        "LoD/1.13c": 4,
        "LoD/1.13d": 4
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "a62c5e213216063061d4d1c8c7db89e8",
        "LoD/1.11b": "a62c5e213216063061d4d1c8c7db89e8",
        "LoD/1.12a": "a62c5e213216063061d4d1c8c7db89e8",
        "LoD/1.13c": "a62c5e213216063061d4d1c8c7db89e8",
        "LoD/1.13d": "a62c5e213216063061d4d1c8c7db89e8"
      }
    },
    "d2net.dll___onexit_lk": {
      "addresses": {
        "LoD/1.11": "0x6FBF1911",
        "LoD/1.11b": "0x6FBF1911",
        "LoD/1.12a": "0x6FBF1919",
        "LoD/1.13c": "0x6FBF1911",
        "LoD/1.13d": "0x6FBF1919"
      },
      "rvas": {
        "LoD/1.11": "0x1911",
        "LoD/1.11b": "0x1911",
        "LoD/1.12a": "0x1919",
        "LoD/1.13c": "0x1911",
        "LoD/1.13d": "0x1919"
      },
      "sizes": {
        "LoD/1.11": 128,
        "LoD/1.11b": 128,
        "LoD/1.12a": 128,
        "LoD/1.13c": 128,
        "LoD/1.13d": 128
      },
      "name": "__onexit_lk",
      "signature": "undefined __onexit_lk(void)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Single Match\n __onexit_lk\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:7a09c5a73235698eb35bf1fa40abce3a",
      "basic_block_counts": {
        "LoD/1.11": 8,
        "LoD/1.11b": 8,
        "LoD/1.12a": 8,
        "LoD/1.13c": 8,
        "LoD/1.13d": 8
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "7a09c5a73235698eb35bf1fa40abce3a",
        "LoD/1.11b": "7a09c5a73235698eb35bf1fa40abce3a",
        "LoD/1.12a": "7a09c5a73235698eb35bf1fa40abce3a",
        "LoD/1.13c": "7a09c5a73235698eb35bf1fa40abce3a",
        "LoD/1.13d": "7a09c5a73235698eb35bf1fa40abce3a"
      }
    },
    "d2net.dll____onexitinit": {
      "addresses": {
        "LoD/1.11": "0x6FBF1991",
        "LoD/1.11b": "0x6FBF1991",
        "LoD/1.12a": "0x6FBF1999",
        "LoD/1.13c": "0x6FBF1991",
        "LoD/1.13d": "0x6FBF1999"
      },
      "rvas": {
        "LoD/1.11": "0x1991",
        "LoD/1.11b": "0x1991",
        "LoD/1.12a": "0x1999",
        "LoD/1.13c": "0x1991",
        "LoD/1.13d": "0x1999"
      },
      "sizes": {
        "LoD/1.11": 40,
        "LoD/1.11b": 40,
        "LoD/1.12a": 40,
        "LoD/1.13c": 40,
        "LoD/1.13d": 40
      },
      "name": "___onexitinit",
      "signature": "undefined4 ___onexitinit(void)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Single Match\n ___onexitinit\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:266baaaf79f230c6a6856a4a53b42d70",
      "basic_block_counts": {
        "LoD/1.11": 3,
        "LoD/1.11b": 3,
        "LoD/1.12a": 3,
        "LoD/1.13c": 3,
        "LoD/1.13d": 3
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "266baaaf79f230c6a6856a4a53b42d70",
        "LoD/1.11b": "266baaaf79f230c6a6856a4a53b42d70",
        "LoD/1.12a": "266baaaf79f230c6a6856a4a53b42d70",
        "LoD/1.13c": "266baaaf79f230c6a6856a4a53b42d70",
        "LoD/1.13d": "266baaaf79f230c6a6856a4a53b42d70"
      }
    },
    "d2net.dll___onexit": {
      "addresses": {
        "LoD/1.11": "0x6FBF19B9",
        "LoD/1.11b": "0x6FBF19B9",
        "LoD/1.12a": "0x6FBF19C1",
        "LoD/1.13c": "0x6FBF19B9",
        "LoD/1.13d": "0x6FBF19C1"
      },
      "rvas": {
        "LoD/1.11": "0x19B9",
        "LoD/1.11b": "0x19B9",
        "LoD/1.12a": "0x19C1",
        "LoD/1.13c": "0x19B9",
        "LoD/1.13d": "0x19C1"
      },
      "sizes": {
        "LoD/1.11": 50,
        "LoD/1.11b": 50,
        "LoD/1.12a": 50,
        "LoD/1.13c": 50,
        "LoD/1.13d": 50
      },
      "name": "__onexit",
      "signature": "_onexit_t __onexit(_onexit_t _Func)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __onexit\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:5d2d40297dfe2be53beef9d63f51ef80",
      "basic_block_counts": {
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "5d2d40297dfe2be53beef9d63f51ef80",
        "LoD/1.11b": "5d2d40297dfe2be53beef9d63f51ef80",
        "LoD/1.12a": "5d2d40297dfe2be53beef9d63f51ef80",
        "LoD/1.13c": "5d2d40297dfe2be53beef9d63f51ef80",
        "LoD/1.13d": "5d2d40297dfe2be53beef9d63f51ef80"
      }
    },
    "d2net.dll_ExitHandlerCleanup": {
      "addresses": {
        "LoD/1.11": "0x6FBF19EB",
        "LoD/1.11b": "0x6FBF19EB",
        "LoD/1.12a": "0x6FBF19F3",
        "LoD/1.13c": "0x6FBF19EB",
        "LoD/1.13d": "0x6FBF19F3"
      },
      "rvas": {
        "LoD/1.11": "0x19EB",
        "LoD/1.11b": "0x19EB",
        "LoD/1.12a": "0x19F3",
        "LoD/1.13c": "0x19EB",
        "LoD/1.13d": "0x19F3"
      },
      "sizes": {
        "LoD/1.11": 6,
        "LoD/1.11b": 6,
        "LoD/1.12a": 6,
        "LoD/1.13c": 6,
        "LoD/1.13d": 6
      },
      "name": "ExitHandlerCleanup",
      "signature": "void ExitHandlerCleanup(void)",
      "calling_convention": "__stdcall",
      "comment": "Exit handler cleanup routine registered with __onexit() for program termination.\n\nAlgorithm:\n1. Call ReleaseCriticalSectionEight() to release critical section resource #8\n2. Return to exit handler chain\n\nParameters:\nNone\n\nReturns:\nvoid - Performs cleanup operations but returns no value\n\nSpecial Cases:\n- Registered as exit handler, called automatically during program termination\n- Delegates cleanup work to ReleaseCriticalSectionEight()\n- Part of program shutdown sequence\n\nContext:\nThis function serves as an exit handler callback that ensures critical section #8\nis properly released when the program terminates. Exit handlers are registered\ncallbacks that execute in LIFO order (last registered, first called) as part of\nthe C runtime shutdown sequence. This specific handler ensures that a global\ncritical section resource is cleanly released.",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:e7313d19d2f1b94221ec63dffd5562f1",
      "basic_block_counts": {
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "e7313d19d2f1b94221ec63dffd5562f1",
        "LoD/1.11b": "e7313d19d2f1b94221ec63dffd5562f1",
        "LoD/1.12a": "e7313d19d2f1b94221ec63dffd5562f1",
        "LoD/1.13c": "e7313d19d2f1b94221ec63dffd5562f1",
        "LoD/1.13d": "e7313d19d2f1b94221ec63dffd5562f1"
      }
    },
    "d2net.dll__atexit": {
      "addresses": {
        "LoD/1.11": "0x6FBF19F1",
        "LoD/1.11b": "0x6FBF19F1",
        "LoD/1.12a": "0x6FBF19F9",
        "LoD/1.13c": "0x6FBF19F1",
        "LoD/1.13d": "0x6FBF19F9"
      },
      "rvas": {
        "LoD/1.11": "0x19F1",
        "LoD/1.11b": "0x19F1",
        "LoD/1.12a": "0x19F9",
        "LoD/1.13c": "0x19F1",
        "LoD/1.13d": "0x19F9"
      },
      "sizes": {
        "LoD/1.11": 18,
        "LoD/1.11b": 18,
        "LoD/1.12a": 18,
        "LoD/1.13c": 18,
        "LoD/1.13d": 18
      },
      "name": "_atexit",
      "signature": "int _atexit(_func_4879 * param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n _atexit\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:2544af1d7a0712444106eb929de8e62d",
      "basic_block_counts": {
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "2544af1d7a0712444106eb929de8e62d",
        "LoD/1.11b": "2544af1d7a0712444106eb929de8e62d",
        "LoD/1.12a": "2544af1d7a0712444106eb929de8e62d",
        "LoD/1.13c": "2544af1d7a0712444106eb929de8e62d",
        "LoD/1.13d": "2544af1d7a0712444106eb929de8e62d"
      }
    },
    "d2net.dll___RTC_Initialize": {
      "addresses": {
        "LoD/1.11": "0x6FBF1A03",
        "LoD/1.11b": "0x6FBF1A03",
        "LoD/1.12a": "0x6FBF1A4F",
        "LoD/1.13c": "0x6FBF1A47",
        "LoD/1.13d": "0x6FBF1A4F"
      },
      "rvas": {
        "LoD/1.11": "0x1A03",
        "LoD/1.11b": "0x1A03",
        "LoD/1.12a": "0x1A4F",
        "LoD/1.13c": "0x1A47",
        "LoD/1.13d": "0x1A4F"
      },
      "sizes": {
        "LoD/1.11": 61,
        "LoD/1.11b": 61,
        "LoD/1.12a": 61,
        "LoD/1.13c": 61,
        "LoD/1.13d": 61
      },
      "name": "__RTC_Initialize",
      "signature": "undefined __RTC_Initialize(void)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Single Match\n __RTC_Initialize\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:9882f49b46164551a852d0e5558c3763",
      "basic_block_counts": {
        "LoD/1.11": 6,
        "LoD/1.11b": 6,
        "LoD/1.12a": 6,
        "LoD/1.13c": 6,
        "LoD/1.13d": 6
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "9882f49b46164551a852d0e5558c3763",
        "LoD/1.11b": "9882f49b46164551a852d0e5558c3763",
        "LoD/1.12a": "9882f49b46164551a852d0e5558c3763",
        "LoD/1.13c": "9882f49b46164551a852d0e5558c3763",
        "LoD/1.13d": "9882f49b46164551a852d0e5558c3763"
      }
    },
    "d2net.dll_MNE_9882f49b4616": {
      "addresses": {
        "LoD/1.11": "0x6FBF1A47",
        "LoD/1.11b": "0x6FBF1A47",
        "LoD/1.12a": "0x6FBF1A0B",
        "LoD/1.13c": "0x6FBF1A03",
        "LoD/1.13d": "0x6FBF1A0B"
      },
      "rvas": {
        "LoD/1.11": "0x1A47",
        "LoD/1.11b": "0x1A47",
        "LoD/1.12a": "0x1A0B",
        "LoD/1.13c": "0x1A03",
        "LoD/1.13d": "0x1A0B"
      },
      "sizes": {
        "LoD/1.11": 61,
        "LoD/1.11b": 61,
        "LoD/1.12a": 61,
        "LoD/1.13c": 61,
        "LoD/1.13d": 61
      },
      "signature": "undefined __RTC_Initialize(void)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Single Match\n __RTC_Initialize\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.12a",
      "method": "MNE",
      "index": "MNE:9882f49b46164551a852d0e5558c3763",
      "basic_block_counts": {
        "LoD/1.11": 6,
        "LoD/1.11b": 6,
        "LoD/1.12a": 6,
        "LoD/1.13c": 6,
        "LoD/1.13d": 6
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "9882f49b46164551a852d0e5558c3763",
        "LoD/1.11b": "9882f49b46164551a852d0e5558c3763",
        "LoD/1.12a": "9882f49b46164551a852d0e5558c3763",
        "LoD/1.13c": "9882f49b46164551a852d0e5558c3763",
        "LoD/1.13d": "9882f49b46164551a852d0e5558c3763"
      }
    },
    "d2net.dll___SEH_prolog": {
      "addresses": {
        "LoD/1.11": "0x6FBF1A8C",
        "LoD/1.11b": "0x6FBF1A8C",
        "LoD/1.12a": "0x6FBF1A94",
        "LoD/1.13c": "0x6FBF1A8C",
        "LoD/1.13d": "0x6FBF1A94"
      },
      "rvas": {
        "LoD/1.11": "0x1A8C",
        "LoD/1.11b": "0x1A8C",
        "LoD/1.12a": "0x1A94",
        "LoD/1.13c": "0x1A8C",
        "LoD/1.13d": "0x1A94"
      },
      "sizes": {
        "LoD/1.11": 59,
        "LoD/1.11b": 59,
        "LoD/1.12a": 59,
        "LoD/1.13c": 59,
        "LoD/1.13d": 59
      },
      "name": "__SEH_prolog",
      "signature": "undefined __SEH_prolog(undefined4 param_1, int param_2)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __SEH_prolog\n\nLibrary: Visual Studio",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:aef9935d5818b16bbad0952f5da65380",
      "basic_block_counts": {
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "aef9935d5818b16bbad0952f5da65380",
        "LoD/1.11b": "aef9935d5818b16bbad0952f5da65380",
        "LoD/1.12a": "aef9935d5818b16bbad0952f5da65380",
        "LoD/1.13c": "aef9935d5818b16bbad0952f5da65380",
        "LoD/1.13d": "aef9935d5818b16bbad0952f5da65380"
      }
    },
    "d2net.dll___SEH_epilog": {
      "addresses": {
        "LoD/1.11": "0x6FBF1AC7",
        "LoD/1.11b": "0x6FBF1AC7",
        "LoD/1.12a": "0x6FBF1ACF",
        "LoD/1.13c": "0x6FBF1AC7",
        "LoD/1.13d": "0x6FBF1ACF"
      },
      "rvas": {
        "LoD/1.11": "0x1AC7",
        "LoD/1.11b": "0x1AC7",
        "LoD/1.12a": "0x1ACF",
        "LoD/1.13c": "0x1AC7",
        "LoD/1.13d": "0x1ACF"
      },
      "sizes": {
        "LoD/1.11": 17,
        "LoD/1.11b": 17,
        "LoD/1.12a": 17,
        "LoD/1.13c": 17,
        "LoD/1.13d": 17
      },
      "name": "__SEH_epilog",
      "signature": "undefined __SEH_epilog(void)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Single Match\n __SEH_epilog\n\nLibrary: Visual Studio",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:bb6caf8fa91f28d8c9b4f7822655fe6b",
      "basic_block_counts": {
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "bb6caf8fa91f28d8c9b4f7822655fe6b",
        "LoD/1.11b": "bb6caf8fa91f28d8c9b4f7822655fe6b",
        "LoD/1.12a": "bb6caf8fa91f28d8c9b4f7822655fe6b",
        "LoD/1.13c": "bb6caf8fa91f28d8c9b4f7822655fe6b",
        "LoD/1.13d": "bb6caf8fa91f28d8c9b4f7822655fe6b"
      }
    },
    "d2net.dll_AllocateTlsSlot": {
      "addresses": {
        "LoD/1.11": "0x6FBF1BE1",
        "LoD/1.11b": "0x6FBF1BE1",
        "LoD/1.12a": "0x6FBF1BE9",
        "LoD/1.13c": "0x6FBF1BE1",
        "LoD/1.13d": "0x6FBF1BE9"
      },
      "rvas": {
        "LoD/1.11": "0x1BE1",
        "LoD/1.11b": "0x1BE1",
        "LoD/1.12a": "0x1BE9",
        "LoD/1.13c": "0x1BE1",
        "LoD/1.13d": "0x1BE9"
      },
      "sizes": {
        "LoD/1.11": 9,
        "LoD/1.11b": 9,
        "LoD/1.12a": 9,
        "LoD/1.13c": 9,
        "LoD/1.13d": 9
      },
      "name": "AllocateTlsSlot",
      "signature": "DWORD AllocateTlsSlot(void)",
      "calling_convention": "__stdcall",
      "comment": "Allocates a Thread Local Storage (TLS) slot via Win32 TlsAlloc API.\n\nAlgorithm:\n1. Call TlsAlloc through indirect function pointer at g_dwTlsSlotIndex reference\n2. Return the allocated TLS slot index (0-1087 on success, TLS_OUT_OF_INDEXES on failure)\n\nParameters:\nNone - This is a simple wrapper function with no parameters.\n\nReturns:\nDWORD - TLS slot index (valid range 0-1087) on success, or TLS_OUT_OF_INDEXES (0xFFFFFFFF / -1) on failure indicating all 1088 TLS slots are exhausted.\n\nContext:\nCalled by __mtinit during C runtime initialization as a fallback mechanism when Fiber Local Storage (FlsAlloc) is unavailable. The allocated TLS index is stored in g_dwTlsSlotIndex and subsequently used with TlsGetValue/TlsSetValue for managing per-thread state throughout the runtime lifecycle.\n\nSpecial Cases:\n- TLS_OUT_OF_INDEXES returned only when all 1088 available slots are allocated\n- Calling convention is __stdcall (callee pops return address)",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:03ce6e557a60cad10c5f167fdc7f4b70",
      "basic_block_counts": {
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "03ce6e557a60cad10c5f167fdc7f4b70",
        "LoD/1.11b": "03ce6e557a60cad10c5f167fdc7f4b70",
        "LoD/1.12a": "03ce6e557a60cad10c5f167fdc7f4b70",
        "LoD/1.13c": "03ce6e557a60cad10c5f167fdc7f4b70",
        "LoD/1.13d": "03ce6e557a60cad10c5f167fdc7f4b70"
      }
    },
    "d2net.dll___mtterm": {
      "addresses": {
        "LoD/1.11": "0x6FBF1BEA",
        "LoD/1.11b": "0x6FBF1BEA",
        "LoD/1.12a": "0x6FBF1BF2",
        "LoD/1.13c": "0x6FBF1BEA",
        "LoD/1.13d": "0x6FBF1BF2"
      },
      "rvas": {
        "LoD/1.11": "0x1BEA",
        "LoD/1.11b": "0x1BEA",
        "LoD/1.12a": "0x1BF2",
        "LoD/1.13c": "0x1BEA",
        "LoD/1.13d": "0x1BF2"
      },
      "sizes": {
        "LoD/1.11": 29,
        "LoD/1.11b": 29,
        "LoD/1.12a": 29,
        "LoD/1.13c": 29,
        "LoD/1.13d": 29
      },
      "name": "__mtterm",
      "signature": "void __mtterm(void)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __mtterm\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:aff5ecc933020ea9f6660ca70cb9d16a",
      "basic_block_counts": {
        "LoD/1.11": 3,
        "LoD/1.11b": 3,
        "LoD/1.12a": 3,
        "LoD/1.13c": 3,
        "LoD/1.13d": 3
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "aff5ecc933020ea9f6660ca70cb9d16a",
        "LoD/1.11b": "aff5ecc933020ea9f6660ca70cb9d16a",
        "LoD/1.12a": "aff5ecc933020ea9f6660ca70cb9d16a",
        "LoD/1.13c": "aff5ecc933020ea9f6660ca70cb9d16a",
        "LoD/1.13d": "aff5ecc933020ea9f6660ca70cb9d16a"
      }
    },
    "d2net.dll___freefls@4": {
      "addresses": {
        "LoD/1.11": "0x6FBF1C8B",
        "LoD/1.11b": "0x6FBF1C8B",
        "LoD/1.12a": "0x6FBF1C93",
        "LoD/1.13c": "0x6FBF1C8B",
        "LoD/1.13d": "0x6FBF1C93"
      },
      "rvas": {
        "LoD/1.11": "0x1C8B",
        "LoD/1.11b": "0x1C8B",
        "LoD/1.12a": "0x1C93",
        "LoD/1.13c": "0x1C8B",
        "LoD/1.13d": "0x1C93"
      },
      "sizes": {
        "LoD/1.11": 301,
        "LoD/1.11b": 301,
        "LoD/1.12a": 301,
        "LoD/1.13c": 301,
        "LoD/1.13d": 301
      },
      "name": "__freefls@4",
      "signature": "undefined __freefls@4(void * param_1)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Single Match\n __freefls@4\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:adafedc33ce199c85ef6d812cf9b5974",
      "basic_block_counts": {
        "LoD/1.11": 34,
        "LoD/1.11b": 34,
        "LoD/1.12a": 34,
        "LoD/1.13c": 34,
        "LoD/1.13d": 34
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "adafedc33ce199c85ef6d812cf9b5974",
        "LoD/1.11b": "adafedc33ce199c85ef6d812cf9b5974",
        "LoD/1.12a": "adafedc33ce199c85ef6d812cf9b5974",
        "LoD/1.13c": "adafedc33ce199c85ef6d812cf9b5974",
        "LoD/1.13d": "adafedc33ce199c85ef6d812cf9b5974"
      }
    },
    "d2net.dll___freeptd": {
      "addresses": {
        "LoD/1.11": "0x6FBF1DD2",
        "LoD/1.11b": "0x6FBF1DD2",
        "LoD/1.12a": "0x6FBF1DDA",
        "LoD/1.13c": "0x6FBF1DD2",
        "LoD/1.13d": "0x6FBF1DDA"
      },
      "rvas": {
        "LoD/1.11": "0x1DD2",
        "LoD/1.11b": "0x1DD2",
        "LoD/1.12a": "0x1DDA",
        "LoD/1.13c": "0x1DD2",
        "LoD/1.13d": "0x1DDA"
      },
      "sizes": {
        "LoD/1.11": 47,
        "LoD/1.11b": 47,
        "LoD/1.12a": 47,
        "LoD/1.13c": 47,
        "LoD/1.13d": 47
      },
      "name": "__freeptd",
      "signature": "void __freeptd(_ptiddata _Ptd)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __freeptd\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:c0a536e0e6dadcb5b945a8303814ecb3",
      "basic_block_counts": {
        "LoD/1.11": 5,
        "LoD/1.11b": 5,
        "LoD/1.12a": 5,
        "LoD/1.13c": 5,
        "LoD/1.13d": 5
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "c0a536e0e6dadcb5b945a8303814ecb3",
        "LoD/1.11b": "c0a536e0e6dadcb5b945a8303814ecb3",
        "LoD/1.12a": "c0a536e0e6dadcb5b945a8303814ecb3",
        "LoD/1.13c": "c0a536e0e6dadcb5b945a8303814ecb3",
        "LoD/1.13d": "c0a536e0e6dadcb5b945a8303814ecb3"
      }
    },
    "d2net.dll___mtinit": {
      "addresses": {
        "LoD/1.11": "0x6FBF1E01",
        "LoD/1.11b": "0x6FBF1E01",
        "LoD/1.12a": "0x6FBF1E09",
        "LoD/1.13c": "0x6FBF1E01",
        "LoD/1.13d": "0x6FBF1E09"
      },
      "rvas": {
        "LoD/1.11": "0x1E01",
        "LoD/1.11b": "0x1E01",
        "LoD/1.12a": "0x1E09",
        "LoD/1.13c": "0x1E01",
        "LoD/1.13d": "0x1E09"
      },
      "sizes": {
        "LoD/1.11": 239,
        "LoD/1.11b": 239,
        "LoD/1.12a": 239,
        "LoD/1.13c": 239,
        "LoD/1.13d": 239
      },
      "name": "__mtinit",
      "signature": "int __mtinit(void)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __mtinit\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "STR",
      "index": "STR:304d598e6d0a621c9e3544e6fb22e61e",
      "callees": {
        "LoD/1.11": [
          "TlsAlloc"
        ],
        "LoD/1.11b": [
          "TlsAlloc"
        ],
        "LoD/1.12a": [
          "TlsAlloc"
        ],
        "LoD/1.13c": [
          "TlsAlloc"
        ],
        "LoD/1.13d": [
          "TlsAlloc"
        ]
      },
      "strings": {
        "LoD/1.11": [
          "\"kernel32.dll\"",
          "\"FlsAlloc\"",
          "\"FlsFree\"",
          "\"FlsGetValue\"",
          "\"FlsSetValue\""
        ],
        "LoD/1.11b": [
          "\"kernel32.dll\"",
          "\"FlsAlloc\"",
          "\"FlsFree\"",
          "\"FlsGetValue\"",
          "\"FlsSetValue\""
        ],
        "LoD/1.12a": [
          "\"kernel32.dll\"",
          "\"FlsAlloc\"",
          "\"FlsFree\"",
          "\"FlsGetValue\"",
          "\"FlsSetValue\""
        ],
        "LoD/1.13c": [
          "\"kernel32.dll\"",
          "\"FlsAlloc\"",
          "\"FlsFree\"",
          "\"FlsGetValue\"",
          "\"FlsSetValue\""
        ],
        "LoD/1.13d": [
          "\"kernel32.dll\"",
          "\"FlsAlloc\"",
          "\"FlsFree\"",
          "\"FlsGetValue\"",
          "\"FlsSetValue\""
        ]
      },
      "basic_block_counts": {
        "LoD/1.11": 11,
        "LoD/1.11b": 11,
        "LoD/1.12a": 11,
        "LoD/1.13c": 11,
        "LoD/1.13d": 11
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "bcce8ed29924bac295ff5cc0516a2419",
        "LoD/1.11b": "bcce8ed29924bac295ff5cc0516a2419",
        "LoD/1.12a": "bcce8ed29924bac295ff5cc0516a2419",
        "LoD/1.13c": "bcce8ed29924bac295ff5cc0516a2419",
        "LoD/1.13d": "bcce8ed29924bac295ff5cc0516a2419"
      }
    },
    "d2net.dll__free": {
      "addresses": {
        "LoD/1.11": "0x6FBF1EF0",
        "LoD/1.11b": "0x6FBF1EF0",
        "LoD/1.12a": "0x6FBF1EF8",
        "LoD/1.13c": "0x6FBF1EF0",
        "LoD/1.13d": "0x6FBF1EF8"
      },
      "rvas": {
        "LoD/1.11": "0x1EF0",
        "LoD/1.11b": "0x1EF0",
        "LoD/1.12a": "0x1EF8",
        "LoD/1.13c": "0x1EF0",
        "LoD/1.13d": "0x1EF8"
      },
      "sizes": {
        "LoD/1.11": 104,
        "LoD/1.11b": 104,
        "LoD/1.12a": 104,
        "LoD/1.13c": 104,
        "LoD/1.13d": 104
      },
      "name": "_free",
      "signature": "void _free(void * _Memory)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n _free\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:d5c8453c3e2bb4ff6f437d3d747d2c97",
      "basic_block_counts": {
        "LoD/1.11": 9,
        "LoD/1.11b": 9,
        "LoD/1.12a": 9,
        "LoD/1.13c": 9,
        "LoD/1.13d": 9
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "d5c8453c3e2bb4ff6f437d3d747d2c97",
        "LoD/1.11b": "d5c8453c3e2bb4ff6f437d3d747d2c97",
        "LoD/1.12a": "d5c8453c3e2bb4ff6f437d3d747d2c97",
        "LoD/1.13c": "d5c8453c3e2bb4ff6f437d3d747d2c97",
        "LoD/1.13d": "d5c8453c3e2bb4ff6f437d3d747d2c97"
      }
    },
    "d2net.dll_LeaveCriticalSectionForMemoryF": {
      "addresses": {
        "LoD/1.11": "0x6FBF1F43",
        "LoD/1.11b": "0x6FBF1F43",
        "LoD/1.12a": "0x6FBF1F4B",
        "LoD/1.13c": "0x6FBF1F43",
        "LoD/1.13d": "0x6FBF1F4B"
      },
      "rvas": {
        "LoD/1.11": "0x1F43",
        "LoD/1.11b": "0x1F43",
        "LoD/1.12a": "0x1F4B",
        "LoD/1.13c": "0x1F43",
        "LoD/1.13d": "0x1F4B"
      },
      "sizes": {
        "LoD/1.11": 9,
        "LoD/1.11b": 9,
        "LoD/1.12a": 9,
        "LoD/1.13c": 9,
        "LoD/1.13d": 9
      },
      "name": "LeaveCriticalSectionForMemoryFree",
      "signature": "void LeaveCriticalSectionForMemoryFree(void)",
      "calling_convention": "__stdcall",
      "comment": "Releases a critical section lock used for memory management operations.\n\nAlgorithm:\n1. Push critical section index 4 (memory allocation/deallocation lock) onto stack\n2. Call LeaveCriticalSectionByIndex(4) to release the critical section at index 4\n3. Return to caller\n\nParameters:\nNone - critical section index is hardcoded to 4\n\nReturns:\nvoid - No return value. The critical section is released atomically.\n\nSpecial Cases:\n- Critical section index 4 is reserved for memory allocation/deallocation synchronization\n- Called during memory free operations to release the lock before returning memory to the heap\n- Uses __stdcall convention: callee cleans up the stack parameter",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:f23ef2b3a6cfdeb1f35221d5fc7b15e0",
      "basic_block_counts": {
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.11b": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.12a": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.13c": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.13d": "f23ef2b3a6cfdeb1f35221d5fc7b15e0"
      }
    },
    "d2net.dll__calloc": {
      "addresses": {
        "LoD/1.11": "0x6FBF1F61",
        "LoD/1.11b": "0x6FBF1F61"
      },
      "rvas": {
        "LoD/1.11": "0x1F61",
        "LoD/1.11b": "0x1F61"
      },
      "sizes": {
        "LoD/1.11": 175,
        "LoD/1.11b": 175
      },
      "name": "_calloc",
      "signature": "void * _calloc(size_t _Count, size_t _Size)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n _calloc\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:91411ab4247869eeb28238e92930a4a5",
      "basic_block_counts": {
        "LoD/1.11": 15,
        "LoD/1.11b": 15
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "91411ab4247869eeb28238e92930a4a5",
        "LoD/1.11b": "91411ab4247869eeb28238e92930a4a5"
      }
    },
    "d2net.dll_LeaveCriticalSectionForMemoryF_200B": {
      "addresses": {
        "LoD/1.11": "0x6FBF200B",
        "LoD/1.11b": "0x6FBF200B",
        "LoD/1.12a": "0x6FBF2F49",
        "LoD/1.13c": "0x6FBF2E92",
        "LoD/1.13d": "0x6FBF2F24"
      },
      "rvas": {
        "LoD/1.11": "0x200B",
        "LoD/1.11b": "0x200B",
        "LoD/1.12a": "0x2F49",
        "LoD/1.13c": "0x2E92",
        "LoD/1.13d": "0x2F24"
      },
      "sizes": {
        "LoD/1.11": 9,
        "LoD/1.11b": 9,
        "LoD/1.12a": 9,
        "LoD/1.13c": 9,
        "LoD/1.13d": 9
      },
      "name": "LeaveCriticalSectionForMemoryFree",
      "signature": "void LeaveCriticalSectionForMemoryFree(void)",
      "calling_convention": "__stdcall",
      "comment": "Releases a critical section lock used for memory management operations.\n\nAlgorithm:\n1. Push critical section index 4 (memory allocation/deallocation lock) onto stack\n2. Call LeaveCriticalSectionByIndex(4) to release the critical section at index 4\n3. Return to caller\n\nParameters:\nNone - critical section index is hardcoded to 4\n\nReturns:\nvoid - No return value. The critical section is released atomically.\n\nSpecial Cases:\n- Critical section index 4 is reserved for memory allocation/deallocation synchronization\n- Called during memory free operations to release the lock before returning memory to the heap\n- Uses __stdcall convention: callee cleans up the stack parameter",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:f23ef2b3a6cfdeb1f35221d5fc7b15e0",
      "basic_block_counts": {
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.11b": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.12a": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.13c": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.13d": "f23ef2b3a6cfdeb1f35221d5fc7b15e0"
      }
    },
    "d2net.dll___ioinit": {
      "addresses": {
        "LoD/1.11": "0x6FBF201C",
        "LoD/1.11b": "0x6FBF201C",
        "LoD/1.12a": "0x6FBF2040",
        "LoD/1.13c": "0x6FBF2038",
        "LoD/1.13d": "0x6FBF2024"
      },
      "rvas": {
        "LoD/1.11": "0x201C",
        "LoD/1.11b": "0x201C",
        "LoD/1.12a": "0x2040",
        "LoD/1.13c": "0x2038",
        "LoD/1.13d": "0x2024"
      },
      "sizes": {
        "LoD/1.11": 510,
        "LoD/1.11b": 510,
        "LoD/1.12a": 510,
        "LoD/1.13c": 510,
        "LoD/1.13d": 510
      },
      "name": "__ioinit",
      "signature": "int __ioinit(void)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __ioinit\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:124a050f7896343631e89fc5722f0cb0",
      "basic_block_counts": {
        "LoD/1.11": 46,
        "LoD/1.11b": 46,
        "LoD/1.12a": 46,
        "LoD/1.13c": 46,
        "LoD/1.13d": 46
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "124a050f7896343631e89fc5722f0cb0",
        "LoD/1.11b": "124a050f7896343631e89fc5722f0cb0",
        "LoD/1.12a": "124a050f7896343631e89fc5722f0cb0",
        "LoD/1.13c": "124a050f7896343631e89fc5722f0cb0",
        "LoD/1.13d": "124a050f7896343631e89fc5722f0cb0"
      }
    },
    "d2net.dll___ioterm": {
      "addresses": {
        "LoD/1.11": "0x6FBF221A",
        "LoD/1.11b": "0x6FBF221A",
        "LoD/1.12a": "0x6FBF223E",
        "LoD/1.13c": "0x6FBF2236",
        "LoD/1.13d": "0x6FBF2222"
      },
      "rvas": {
        "LoD/1.11": "0x221A",
        "LoD/1.11b": "0x221A",
        "LoD/1.12a": "0x223E",
        "LoD/1.13c": "0x2236",
        "LoD/1.13d": "0x2222"
      },
      "sizes": {
        "LoD/1.11": 76,
        "LoD/1.11b": 76,
        "LoD/1.12a": 76,
        "LoD/1.13c": 76,
        "LoD/1.13d": 76
      },
      "name": "__ioterm",
      "signature": "void __ioterm(void)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __ioterm\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:5c819fccbe8be253acb13e92783cc438",
      "basic_block_counts": {
        "LoD/1.11": 10,
        "LoD/1.11b": 10,
        "LoD/1.12a": 10,
        "LoD/1.13c": 10,
        "LoD/1.13d": 10
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "5c819fccbe8be253acb13e92783cc438",
        "LoD/1.11b": "5c819fccbe8be253acb13e92783cc438",
        "LoD/1.12a": "5c819fccbe8be253acb13e92783cc438",
        "LoD/1.13c": "5c819fccbe8be253acb13e92783cc438",
        "LoD/1.13d": "5c819fccbe8be253acb13e92783cc438"
      }
    },
    "d2net.dll___setenvp": {
      "addresses": {
        "LoD/1.11": "0x6FBF2266",
        "LoD/1.11b": "0x6FBF2266",
        "LoD/1.12a": "0x6FBF228A",
        "LoD/1.13c": "0x6FBF2282",
        "LoD/1.13d": "0x6FBF226E"
      },
      "rvas": {
        "LoD/1.11": "0x2266",
        "LoD/1.11b": "0x2266",
        "LoD/1.12a": "0x228A",
        "LoD/1.13c": "0x2282",
        "LoD/1.13d": "0x226E"
      },
      "sizes": {
        "LoD/1.11": 199,
        "LoD/1.11b": 199,
        "LoD/1.12a": 199,
        "LoD/1.13c": 199,
        "LoD/1.13d": 199
      },
      "name": "__setenvp",
      "signature": "int __setenvp(void)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __setenvp\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:d286a589c48283a2eda13c52495cb951",
      "basic_block_counts": {
        "LoD/1.11": 20,
        "LoD/1.11b": 20,
        "LoD/1.12a": 20,
        "LoD/1.13c": 20,
        "LoD/1.13d": 20
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "d286a589c48283a2eda13c52495cb951",
        "LoD/1.11b": "d286a589c48283a2eda13c52495cb951",
        "LoD/1.12a": "d286a589c48283a2eda13c52495cb951",
        "LoD/1.13c": "d286a589c48283a2eda13c52495cb951",
        "LoD/1.13d": "d286a589c48283a2eda13c52495cb951"
      }
    },
    "d2net.dll_ParseCommandLine": {
      "addresses": {
        "LoD/1.11": "0x6FBF232D",
        "LoD/1.11b": "0x6FBF232D",
        "LoD/1.12a": "0x6FBF2351",
        "LoD/1.13c": "0x6FBF2349",
        "LoD/1.13d": "0x6FBF2335"
      },
      "rvas": {
        "LoD/1.11": "0x232D",
        "LoD/1.11b": "0x232D",
        "LoD/1.12a": "0x2351",
        "LoD/1.13c": "0x2349",
        "LoD/1.13d": "0x2335"
      },
      "sizes": {
        "LoD/1.11": 364,
        "LoD/1.11b": 364,
        "LoD/1.12a": 364,
        "LoD/1.13c": 364,
        "LoD/1.13d": 364
      },
      "name": "ParseCommandLine",
      "signature": "void ParseCommandLine(char * * ppszArgv, int * pnArgc)",
      "calling_convention": "__cdecl",
      "comment": "Parse command-line arguments from a raw command string into argv/argc format.\n\nAlgorithm:\n1. Parse first argument from raw command string, handling quoted strings and escape sequences\n2. Store count of output characters in pCharCount parameter\n3. Skip leading whitespace, then iterate through remaining arguments\n4. For each argument: count backslashes before quotes, handle quote toggling and escape processing\n5. Copy non-whitespace characters to output buffer, handle Windows escape sequences (backslash rules)\n6. Null-terminate each argument and increment argument count\n7. Finalize output with sentinel null pointer if ppArgv provided\n\nParameters:\nppArgv - Pointer to array of char pointers for storing argument addresses (can be NULL to just count chars)\npArgc - Pointer to int for storing argument count (initially set to 1, incremented per arg found)\n\nReturns:\nvoid - Arguments stored in ppArgv array and count in pArgc\n\nSpecial Cases:\n- Handles quoted strings with proper quote escaping\n- Processes Windows-style backslash escaping (odd backslashes before quotes are escape chars)\n- Counts and outputs all characters in pCharCount\n- Supports wide character sets via locale character classification table",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:5309cc011f4489e83a895a5a05ecc215",
      "basic_block_counts": {
        "LoD/1.11": 60,
        "LoD/1.11b": 60,
        "LoD/1.12a": 60,
        "LoD/1.13c": 60,
        "LoD/1.13d": 60
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "5309cc011f4489e83a895a5a05ecc215",
        "LoD/1.11b": "5309cc011f4489e83a895a5a05ecc215",
        "LoD/1.12a": "5309cc011f4489e83a895a5a05ecc215",
        "LoD/1.13c": "5309cc011f4489e83a895a5a05ecc215",
        "LoD/1.13d": "5309cc011f4489e83a895a5a05ecc215"
      }
    },
    "d2net.dll___setargv": {
      "addresses": {
        "LoD/1.11": "0x6FBF2499",
        "LoD/1.11b": "0x6FBF2499",
        "LoD/1.12a": "0x6FBF24BD",
        "LoD/1.13c": "0x6FBF24B5",
        "LoD/1.13d": "0x6FBF24A1"
      },
      "rvas": {
        "LoD/1.11": "0x2499",
        "LoD/1.11b": "0x2499",
        "LoD/1.12a": "0x24BD",
        "LoD/1.13c": "0x24B5",
        "LoD/1.13d": "0x24A1"
      },
      "sizes": {
        "LoD/1.11": 162,
        "LoD/1.11b": 162,
        "LoD/1.12a": 162,
        "LoD/1.13c": 162,
        "LoD/1.13d": 162
      },
      "name": "__setargv",
      "signature": "int __setargv(void)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __setargv\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:457ecf3d8055d8e00a172b3d901a03ca",
      "basic_block_counts": {
        "LoD/1.11": 9,
        "LoD/1.11b": 9,
        "LoD/1.12a": 9,
        "LoD/1.13c": 9,
        "LoD/1.13d": 9
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "457ecf3d8055d8e00a172b3d901a03ca",
        "LoD/1.11b": "457ecf3d8055d8e00a172b3d901a03ca",
        "LoD/1.12a": "457ecf3d8055d8e00a172b3d901a03ca",
        "LoD/1.13c": "457ecf3d8055d8e00a172b3d901a03ca",
        "LoD/1.13d": "457ecf3d8055d8e00a172b3d901a03ca"
      }
    },
    "d2net.dll____crtGetEnvironmentStringsA": {
      "addresses": {
        "LoD/1.11": "0x6FBF253B",
        "LoD/1.11b": "0x6FBF253B",
        "LoD/1.12a": "0x6FBF255F",
        "LoD/1.13c": "0x6FBF2557",
        "LoD/1.13d": "0x6FBF2543"
      },
      "rvas": {
        "LoD/1.11": "0x253B",
        "LoD/1.11b": "0x253B",
        "LoD/1.12a": "0x255F",
        "LoD/1.13c": "0x2557",
        "LoD/1.13d": "0x2543"
      },
      "sizes": {
        "LoD/1.11": 290,
        "LoD/1.11b": 290,
        "LoD/1.12a": 290,
        "LoD/1.13c": 290,
        "LoD/1.13d": 290
      },
      "name": "___crtGetEnvironmentStringsA",
      "signature": "LPVOID ___crtGetEnvironmentStringsA(void)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___crtGetEnvironmentStringsA\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:ba896e89d5b4e319d02dcd31648ce3d9",
      "basic_block_counts": {
        "LoD/1.11": 30,
        "LoD/1.11b": 30,
        "LoD/1.12a": 30,
        "LoD/1.13c": 30,
        "LoD/1.13d": 30
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "ba896e89d5b4e319d02dcd31648ce3d9",
        "LoD/1.11b": "ba896e89d5b4e319d02dcd31648ce3d9",
        "LoD/1.12a": "ba896e89d5b4e319d02dcd31648ce3d9",
        "LoD/1.13c": "ba896e89d5b4e319d02dcd31648ce3d9",
        "LoD/1.13d": "ba896e89d5b4e319d02dcd31648ce3d9"
      }
    },
    "d2net.dll____heap_select": {
      "addresses": {
        "LoD/1.11": "0x6FBF265D",
        "LoD/1.11b": "0x6FBF265D",
        "LoD/1.12a": "0x6FBF2681",
        "LoD/1.13c": "0x6FBF2679",
        "LoD/1.13d": "0x6FBF2665"
      },
      "rvas": {
        "LoD/1.11": "0x265D",
        "LoD/1.11b": "0x265D",
        "LoD/1.12a": "0x2681",
        "LoD/1.13c": "0x2679",
        "LoD/1.13d": "0x2665"
      },
      "sizes": {
        "LoD/1.11": 26,
        "LoD/1.11b": 26,
        "LoD/1.12a": 26,
        "LoD/1.13c": 26,
        "LoD/1.13d": 26
      },
      "name": "___heap_select",
      "signature": "undefined4 ___heap_select(void)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Single Match\n ___heap_select\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:02783607761bb7b7f3ed068e856f0ca2",
      "basic_block_counts": {
        "LoD/1.11": 4,
        "LoD/1.11b": 4,
        "LoD/1.12a": 4,
        "LoD/1.13c": 4,
        "LoD/1.13d": 4
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "02783607761bb7b7f3ed068e856f0ca2",
        "LoD/1.11b": "02783607761bb7b7f3ed068e856f0ca2",
        "LoD/1.12a": "02783607761bb7b7f3ed068e856f0ca2",
        "LoD/1.13c": "02783607761bb7b7f3ed068e856f0ca2",
        "LoD/1.13d": "02783607761bb7b7f3ed068e856f0ca2"
      }
    },
    "d2net.dll___heap_init": {
      "addresses": {
        "LoD/1.11": "0x6FBF2677",
        "LoD/1.11b": "0x6FBF2677",
        "LoD/1.12a": "0x6FBF269B",
        "LoD/1.13c": "0x6FBF2693",
        "LoD/1.13d": "0x6FBF267F"
      },
      "rvas": {
        "LoD/1.11": "0x2677",
        "LoD/1.11b": "0x2677",
        "LoD/1.12a": "0x269B",
        "LoD/1.13c": "0x2693",
        "LoD/1.13d": "0x267F"
      },
      "sizes": {
        "LoD/1.11": 81,
        "LoD/1.11b": 81,
        "LoD/1.12a": 81,
        "LoD/1.13c": 81,
        "LoD/1.13d": 81
      },
      "name": "__heap_init",
      "signature": "int __heap_init(void)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __heap_init\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:057b2070bbbdb5455d8d4d9018467770",
      "basic_block_counts": {
        "LoD/1.11": 6,
        "LoD/1.11b": 6,
        "LoD/1.12a": 6,
        "LoD/1.13c": 6,
        "LoD/1.13d": 6
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "057b2070bbbdb5455d8d4d9018467770",
        "LoD/1.11b": "057b2070bbbdb5455d8d4d9018467770",
        "LoD/1.12a": "057b2070bbbdb5455d8d4d9018467770",
        "LoD/1.13c": "057b2070bbbdb5455d8d4d9018467770",
        "LoD/1.13d": "057b2070bbbdb5455d8d4d9018467770"
      }
    },
    "d2net.dll___heap_term": {
      "addresses": {
        "LoD/1.11": "0x6FBF26C8",
        "LoD/1.11b": "0x6FBF26C8",
        "LoD/1.12a": "0x6FBF26EC",
        "LoD/1.13c": "0x6FBF26E4",
        "LoD/1.13d": "0x6FBF26D0"
      },
      "rvas": {
        "LoD/1.11": "0x26C8",
        "LoD/1.11b": "0x26C8",
        "LoD/1.12a": "0x26EC",
        "LoD/1.13c": "0x26E4",
        "LoD/1.13d": "0x26D0"
      },
      "sizes": {
        "LoD/1.11": 127,
        "LoD/1.11b": 127,
        "LoD/1.12a": 127,
        "LoD/1.13c": 127,
        "LoD/1.13d": 127
      },
      "name": "__heap_term",
      "signature": "void __heap_term(void)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __heap_term\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:43c0a0116a0179cd961980d35fb0c190",
      "basic_block_counts": {
        "LoD/1.11": 7,
        "LoD/1.11b": 7,
        "LoD/1.12a": 7,
        "LoD/1.13c": 7,
        "LoD/1.13d": 7
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "43c0a0116a0179cd961980d35fb0c190",
        "LoD/1.11b": "43c0a0116a0179cd961980d35fb0c190",
        "LoD/1.12a": "43c0a0116a0179cd961980d35fb0c190",
        "LoD/1.13c": "43c0a0116a0179cd961980d35fb0c190",
        "LoD/1.13d": "43c0a0116a0179cd961980d35fb0c190"
      }
    },
    "d2net.dll___chkstk": {
      "addresses": {
        "LoD/1.11": "0x6FBF2750",
        "LoD/1.11b": "0x6FBF2750",
        "LoD/1.12a": "0x6FBF2770",
        "LoD/1.13c": "0x6FBF2770",
        "LoD/1.13d": "0x6FBF2750"
      },
      "rvas": {
        "LoD/1.11": "0x2750",
        "LoD/1.11b": "0x2750",
        "LoD/1.12a": "0x2770",
        "LoD/1.13c": "0x2770",
        "LoD/1.13d": "0x2750"
      },
      "sizes": {
        "LoD/1.11": 61,
        "LoD/1.11b": 61,
        "LoD/1.12a": 61,
        "LoD/1.13c": 61,
        "LoD/1.13d": 61
      },
      "name": "__chkstk",
      "signature": "undefined __chkstk(void)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Single Match\n __chkstk\n\nLibraries: Visual Studio 2003 Debug, Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:f17bdc134d984988a231baad11399d03",
      "basic_block_counts": {
        "LoD/1.11": 5,
        "LoD/1.11b": 5,
        "LoD/1.12a": 5,
        "LoD/1.13c": 5,
        "LoD/1.13d": 5
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "f17bdc134d984988a231baad11399d03",
        "LoD/1.11b": "f17bdc134d984988a231baad11399d03",
        "LoD/1.12a": "f17bdc134d984988a231baad11399d03",
        "LoD/1.13c": "f17bdc134d984988a231baad11399d03",
        "LoD/1.13d": "f17bdc134d984988a231baad11399d03"
      }
    },
    "d2net.dll___XcptFilter": {
      "addresses": {
        "LoD/1.11": "0x6FBF278D",
        "LoD/1.11b": "0x6FBF278D",
        "LoD/1.12a": "0x6FBF27AD",
        "LoD/1.13c": "0x6FBF27AD",
        "LoD/1.13d": "0x6FBF278D"
      },
      "rvas": {
        "LoD/1.11": "0x278D",
        "LoD/1.11b": "0x278D",
        "LoD/1.12a": "0x27AD",
        "LoD/1.13c": "0x27AD",
        "LoD/1.13d": "0x278D"
      },
      "sizes": {
        "LoD/1.11": 356,
        "LoD/1.11b": 356,
        "LoD/1.12a": 356,
        "LoD/1.13c": 356,
        "LoD/1.13d": 356
      },
      "name": "__XcptFilter",
      "signature": "int __XcptFilter(ulong _ExceptionNum, _EXCEPTION_POINTERS * _ExceptionPtr)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __XcptFilter\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:79c576ae79b525f94550b7e17b8f3e0b",
      "basic_block_counts": {
        "LoD/1.11": 36,
        "LoD/1.11b": 36,
        "LoD/1.12a": 36,
        "LoD/1.13c": 36,
        "LoD/1.13d": 36
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "79c576ae79b525f94550b7e17b8f3e0b",
        "LoD/1.11b": "79c576ae79b525f94550b7e17b8f3e0b",
        "LoD/1.12a": "79c576ae79b525f94550b7e17b8f3e0b",
        "LoD/1.13c": "79c576ae79b525f94550b7e17b8f3e0b",
        "LoD/1.13d": "79c576ae79b525f94550b7e17b8f3e0b"
      }
    },
    "d2net.dll_FilterCppException": {
      "addresses": {
        "LoD/1.11": "0x6FBF28F1",
        "LoD/1.11b": "0x6FBF28F1",
        "LoD/1.12a": "0x6FBF2911",
        "LoD/1.13c": "0x6FBF2911",
        "LoD/1.13d": "0x6FBF28F1"
      },
      "rvas": {
        "LoD/1.11": "0x28F1",
        "LoD/1.11b": "0x28F1",
        "LoD/1.12a": "0x2911",
        "LoD/1.13c": "0x2911",
        "LoD/1.13d": "0x28F1"
      },
      "sizes": {
        "LoD/1.11": 27,
        "LoD/1.11b": 27,
        "LoD/1.12a": 27,
        "LoD/1.13c": 27,
        "LoD/1.13d": 27
      },
      "name": "FilterCppException",
      "signature": "int FilterCppException(int nExceptionCode, _EXCEPTION_POINTERS * pExceptionInfo)",
      "calling_convention": "__cdecl",
      "comment": "C++ exception filter for Structured Exception Handling (SEH) interop.\n\nAlgorithm:\n1. Load C++ exception code constant (0xe06d7363, the EH_EXCEPTION_NUMBER)\n2. Compare the passed exception code against the C++ exception constant\n3. If exception code matches, push exception info and code as parameters\n4. Call __XcptFilter handler to process the C++ exception and return its result\n5. If exception code doesn't match, return 0 (EXCEPTION_CONTINUE_SEARCH)\n\nParameters:\n- exceptionCode: Windows exception code from SEH handler. C++ exceptions use 0xe06d7363\n- pExceptionInfo: Pointer to EXCEPTION_POINTERS structure with exception record and context\n\nReturns:\n- Result from __XcptFilter if exception is C++ (EXCEPTION_EXECUTE_HANDLER=1 or EXCEPTION_CONTINUE_SEARCH=0)\n- 0 (EXCEPTION_CONTINUE_SEARCH) if exception is not C++\n\nSpecial Cases:\n- Magic number 0xe06d7363 is the Microsoft C++ runtime exception code\n- This function bridges Windows SEH and C++ exception handling\n- Part of exception dispatch chain in __CxxFrameHandler3\n- Used when C++ code runs with SEH (/EHc compiler flag)",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:179c969cc717d22841f18b89d2acdead",
      "basic_block_counts": {
        "LoD/1.11": 3,
        "LoD/1.11b": 3,
        "LoD/1.12a": 3,
        "LoD/1.13c": 3,
        "LoD/1.13d": 3
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "179c969cc717d22841f18b89d2acdead",
        "LoD/1.11b": "179c969cc717d22841f18b89d2acdead",
        "LoD/1.12a": "179c969cc717d22841f18b89d2acdead",
        "LoD/1.13c": "179c969cc717d22841f18b89d2acdead",
        "LoD/1.13d": "179c969cc717d22841f18b89d2acdead"
      }
    },
    "d2net.dll____crtInitCritSecNoSpinCount@8": {
      "addresses": {
        "LoD/1.11": "0x6FBF2ABC",
        "LoD/1.11b": "0x6FBF2ABC",
        "LoD/1.12a": "0x6FBF2ADD",
        "LoD/1.13c": "0x6FBF2ADD",
        "LoD/1.13d": "0x6FBF2ABC"
      },
      "rvas": {
        "LoD/1.11": "0x2ABC",
        "LoD/1.11b": "0x2ABC",
        "LoD/1.12a": "0x2ADD",
        "LoD/1.13c": "0x2ADD",
        "LoD/1.13d": "0x2ABC"
      },
      "sizes": {
        "LoD/1.11": 16,
        "LoD/1.11b": 16,
        "LoD/1.12a": 16,
        "LoD/1.13c": 16,
        "LoD/1.13d": 16
      },
      "name": "___crtInitCritSecNoSpinCount@8",
      "signature": "undefined4 ___crtInitCritSecNoSpinCount@8(LPCRITICAL_SECTION param_1)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Single Match\n ___crtInitCritSecNoSpinCount@8\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:b2a8f1a86586c795d4e7ef4b4053c58e",
      "basic_block_counts": {
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "b2a8f1a86586c795d4e7ef4b4053c58e",
        "LoD/1.11b": "b2a8f1a86586c795d4e7ef4b4053c58e",
        "LoD/1.12a": "b2a8f1a86586c795d4e7ef4b4053c58e",
        "LoD/1.13c": "b2a8f1a86586c795d4e7ef4b4053c58e",
        "LoD/1.13d": "b2a8f1a86586c795d4e7ef4b4053c58e"
      }
    },
    "d2net.dll____crtInitCritSecAndSpinCount": {
      "addresses": {
        "LoD/1.11": "0x6FBF2ACC",
        "LoD/1.11b": "0x6FBF2ACC",
        "LoD/1.12a": "0x6FBF2AED",
        "LoD/1.13c": "0x6FBF2AED",
        "LoD/1.13d": "0x6FBF2ACC"
      },
      "rvas": {
        "LoD/1.11": "0x2ACC",
        "LoD/1.11b": "0x2ACC",
        "LoD/1.12a": "0x2AED",
        "LoD/1.13c": "0x2AED",
        "LoD/1.13d": "0x2ACC"
      },
      "sizes": {
        "LoD/1.11": 103,
        "LoD/1.11b": 103,
        "LoD/1.12a": 103,
        "LoD/1.13c": 103,
        "LoD/1.13d": 103
      },
      "name": "___crtInitCritSecAndSpinCount",
      "signature": "undefined ___crtInitCritSecAndSpinCount(undefined4 param_1, undefined4 param_2)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___crtInitCritSecAndSpinCount\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "STR",
      "index": "STR:5fd0e2b0faef558a78531f73f4d372dd",
      "strings": {
        "LoD/1.11": [
          "\"InitializeCriticalSectionAndSpinCount\"",
          "\"kernel32.dll\""
        ],
        "LoD/1.11b": [
          "\"InitializeCriticalSectionAndSpinCount\"",
          "\"kernel32.dll\""
        ],
        "LoD/1.12a": [
          "\"InitializeCriticalSectionAndSpinCount\"",
          "\"kernel32.dll\""
        ],
        "LoD/1.13c": [
          "\"InitializeCriticalSectionAndSpinCount\"",
          "\"kernel32.dll\""
        ],
        "LoD/1.13d": [
          "\"InitializeCriticalSectionAndSpinCount\"",
          "\"kernel32.dll\""
        ]
      },
      "basic_block_counts": {
        "LoD/1.11": 7,
        "LoD/1.11b": 7,
        "LoD/1.12a": 7,
        "LoD/1.13c": 7,
        "LoD/1.13d": 7
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "3f585ab7136accb11659a7703e402a24",
        "LoD/1.11b": "3f585ab7136accb11659a7703e402a24",
        "LoD/1.12a": "3f585ab7136accb11659a7703e402a24",
        "LoD/1.13c": "3f585ab7136accb11659a7703e402a24",
        "LoD/1.13d": "3f585ab7136accb11659a7703e402a24"
      }
    },
    "d2net.dll_AllocateMemoryWithCache": {
      "addresses": {
        "LoD/1.11": "0x6FBF2B60",
        "LoD/1.11b": "0x6FBF2B60",
        "LoD/1.12a": "0x6FBF2B81",
        "LoD/1.13c": "0x6FBF2B81",
        "LoD/1.13d": "0x6FBF2B60"
      },
      "rvas": {
        "LoD/1.11": "0x2B60",
        "LoD/1.11b": "0x2B60",
        "LoD/1.12a": "0x2B81",
        "LoD/1.13c": "0x2B81",
        "LoD/1.13d": "0x2B60"
      },
      "sizes": {
        "LoD/1.11": 111,
        "LoD/1.11b": 111,
        "LoD/1.12a": 111,
        "LoD/1.13c": 111,
        "LoD/1.13d": 111
      },
      "name": "AllocateMemoryWithCache",
      "signature": "void * AllocateMemoryWithCache(size_t _Size)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __heap_alloc\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:8ac92c76a51a8b065a1fac94d719ae1f",
      "basic_block_counts": {
        "LoD/1.11": 9,
        "LoD/1.11b": 9,
        "LoD/1.12a": 9,
        "LoD/1.13c": 9,
        "LoD/1.13d": 9
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "8ac92c76a51a8b065a1fac94d719ae1f",
        "LoD/1.11b": "8ac92c76a51a8b065a1fac94d719ae1f",
        "LoD/1.12a": "8ac92c76a51a8b065a1fac94d719ae1f",
        "LoD/1.13c": "8ac92c76a51a8b065a1fac94d719ae1f",
        "LoD/1.13d": "8ac92c76a51a8b065a1fac94d719ae1f"
      }
    },
    "d2net.dll__realloc": {
      "addresses": {
        "LoD/1.11": "0x6FBF2D0A",
        "LoD/1.11b": "0x6FBF2D0A"
      },
      "rvas": {
        "LoD/1.11": "0x2D0A",
        "LoD/1.11b": "0x2D0A"
      },
      "sizes": {
        "LoD/1.11": 412,
        "LoD/1.11b": 412
      },
      "name": "_realloc",
      "signature": "void * _realloc(void * _Memory, size_t _NewSize)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n _realloc\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:8c4228500987c1daeeb1fa9fd68f17a9",
      "basic_block_counts": {
        "LoD/1.11": 38,
        "LoD/1.11b": 38
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "8c4228500987c1daeeb1fa9fd68f17a9",
        "LoD/1.11b": "8c4228500987c1daeeb1fa9fd68f17a9"
      }
    },
    "d2net.dll___msize": {
      "addresses": {
        "LoD/1.11": "0x6FBF2EB7",
        "LoD/1.11b": "0x6FBF2EB7",
        "LoD/1.12a": "0x6FBF2EDC",
        "LoD/1.13c": "0x6FBF2EDC",
        "LoD/1.13d": "0x6FBF2EB7"
      },
      "rvas": {
        "LoD/1.11": "0x2EB7",
        "LoD/1.11b": "0x2EB7",
        "LoD/1.12a": "0x2EDC",
        "LoD/1.13c": "0x2EDC",
        "LoD/1.13d": "0x2EB7"
      },
      "sizes": {
        "LoD/1.11": 106,
        "LoD/1.11b": 106,
        "LoD/1.12a": 106,
        "LoD/1.13c": 106,
        "LoD/1.13d": 106
      },
      "name": "__msize",
      "signature": "size_t __msize(void * _Memory)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __msize\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:7fa238a0d1fe5549fc522252a2120d78",
      "basic_block_counts": {
        "LoD/1.11": 7,
        "LoD/1.11b": 7,
        "LoD/1.12a": 7,
        "LoD/1.13c": 7,
        "LoD/1.13d": 7
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "7fa238a0d1fe5549fc522252a2120d78",
        "LoD/1.11b": "7fa238a0d1fe5549fc522252a2120d78",
        "LoD/1.12a": "7fa238a0d1fe5549fc522252a2120d78",
        "LoD/1.13c": "7fa238a0d1fe5549fc522252a2120d78",
        "LoD/1.13d": "7fa238a0d1fe5549fc522252a2120d78"
      }
    },
    "d2net.dll_LeaveCriticalSectionForMemoryF_2F24": {
      "addresses": {
        "LoD/1.11": "0x6FBF2F24",
        "LoD/1.11b": "0x6FBF2F24",
        "LoD/1.12a": "0x6FBF2E92",
        "LoD/1.13c": "0x6FBF2BF3",
        "LoD/1.13d": "0x6FBF2BD2"
      },
      "rvas": {
        "LoD/1.11": "0x2F24",
        "LoD/1.11b": "0x2F24",
        "LoD/1.12a": "0x2E92",
        "LoD/1.13c": "0x2BF3",
        "LoD/1.13d": "0x2BD2"
      },
      "sizes": {
        "LoD/1.11": 9,
        "LoD/1.11b": 9,
        "LoD/1.12a": 9,
        "LoD/1.13c": 9,
        "LoD/1.13d": 9
      },
      "name": "LeaveCriticalSectionForMemoryFree",
      "signature": "void LeaveCriticalSectionForMemoryFree(void)",
      "calling_convention": "__stdcall",
      "comment": "Releases a critical section lock used for memory management operations.\n\nAlgorithm:\n1. Push critical section index 4 (memory allocation/deallocation lock) onto stack\n2. Call LeaveCriticalSectionByIndex(4) to release the critical section at index 4\n3. Return to caller\n\nParameters:\nNone - critical section index is hardcoded to 4\n\nReturns:\nvoid - No return value. The critical section is released atomically.\n\nSpecial Cases:\n- Critical section index 4 is reserved for memory allocation/deallocation synchronization\n- Called during memory free operations to release the lock before returning memory to the heap\n- Uses __stdcall convention: callee cleans up the stack parameter",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:f23ef2b3a6cfdeb1f35221d5fc7b15e0",
      "basic_block_counts": {
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.11b": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.12a": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.13c": "f23ef2b3a6cfdeb1f35221d5fc7b15e0",
        "LoD/1.13d": "f23ef2b3a6cfdeb1f35221d5fc7b15e0"
      }
    },
    "d2net.dll___ValidateEH3RN": {
      "addresses": {
        "LoD/1.11": "0x6FBF2F2D",
        "LoD/1.11b": "0x6FBF2F2D",
        "LoD/1.12a": "0x6FBF2F52",
        "LoD/1.13c": "0x6FBF2F52",
        "LoD/1.13d": "0x6FBF2F2D"
      },
      "rvas": {
        "LoD/1.11": "0x2F2D",
        "LoD/1.11b": "0x2F2D",
        "LoD/1.12a": "0x2F52",
        "LoD/1.13c": "0x2F52",
        "LoD/1.13d": "0x2F2D"
      },
      "sizes": {
        "LoD/1.11": 553,
        "LoD/1.11b": 553,
        "LoD/1.12a": 553,
        "LoD/1.13c": 553,
        "LoD/1.13d": 553
      },
      "name": "__ValidateEH3RN",
      "signature": "undefined4 __ValidateEH3RN(void * param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __ValidateEH3RN\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:81bc6e2827332721bcd73a06db9fcb5a",
      "basic_block_counts": {
        "LoD/1.11": 59,
        "LoD/1.11b": 59,
        "LoD/1.12a": 59,
        "LoD/1.13c": 59,
        "LoD/1.13d": 59
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "81bc6e2827332721bcd73a06db9fcb5a",
        "LoD/1.11b": "81bc6e2827332721bcd73a06db9fcb5a",
        "LoD/1.12a": "81bc6e2827332721bcd73a06db9fcb5a",
        "LoD/1.13c": "81bc6e2827332721bcd73a06db9fcb5a",
        "LoD/1.13d": "81bc6e2827332721bcd73a06db9fcb5a"
      }
    },
    "d2net.dll____freetlocinfo": {
      "addresses": {
        "LoD/1.11": "0x6FBF3156",
        "LoD/1.11b": "0x6FBF3156",
        "LoD/1.12a": "0x6FBF317B",
        "LoD/1.13c": "0x6FBF317B",
        "LoD/1.13d": "0x6FBF3156"
      },
      "rvas": {
        "LoD/1.11": "0x3156",
        "LoD/1.11b": "0x3156",
        "LoD/1.12a": "0x317B",
        "LoD/1.13c": "0x317B",
        "LoD/1.13d": "0x3156"
      },
      "sizes": {
        "LoD/1.11": 208,
        "LoD/1.11b": 208,
        "LoD/1.12a": 208,
        "LoD/1.13c": 208,
        "LoD/1.13d": 208
      },
      "name": "___freetlocinfo",
      "signature": "undefined ___freetlocinfo(void * param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___freetlocinfo\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:1c8e05375765f5055ce29f9161a94626",
      "basic_block_counts": {
        "LoD/1.11": 21,
        "LoD/1.11b": 21,
        "LoD/1.12a": 21,
        "LoD/1.13c": 21,
        "LoD/1.13d": 21
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "1c8e05375765f5055ce29f9161a94626",
        "LoD/1.11b": "1c8e05375765f5055ce29f9161a94626",
        "LoD/1.12a": "1c8e05375765f5055ce29f9161a94626",
        "LoD/1.13c": "1c8e05375765f5055ce29f9161a94626",
        "LoD/1.13d": "1c8e05375765f5055ce29f9161a94626"
      }
    },
    "d2net.dll____updatetlocinfo_lk": {
      "addresses": {
        "LoD/1.11": "0x6FBF3226",
        "LoD/1.11b": "0x6FBF3226",
        "LoD/1.12a": "0x6FBF324B",
        "LoD/1.13c": "0x6FBF324B",
        "LoD/1.13d": "0x6FBF3226"
      },
      "rvas": {
        "LoD/1.11": "0x3226",
        "LoD/1.11b": "0x3226",
        "LoD/1.12a": "0x324B",
        "LoD/1.13c": "0x324B",
        "LoD/1.13d": "0x3226"
      },
      "sizes": {
        "LoD/1.11": 193,
        "LoD/1.11b": 193,
        "LoD/1.12a": 193,
        "LoD/1.13c": 193,
        "LoD/1.13d": 193
      },
      "name": "___updatetlocinfo_lk",
      "signature": "int ___updatetlocinfo_lk(void)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Single Match\n ___updatetlocinfo_lk\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:81fc8ecddc12cc08d3d848c0224bdeb0",
      "basic_block_counts": {
        "LoD/1.11": 24,
        "LoD/1.11b": 24,
        "LoD/1.12a": 24,
        "LoD/1.13c": 24,
        "LoD/1.13d": 24
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "81fc8ecddc12cc08d3d848c0224bdeb0",
        "LoD/1.11b": "81fc8ecddc12cc08d3d848c0224bdeb0",
        "LoD/1.12a": "81fc8ecddc12cc08d3d848c0224bdeb0",
        "LoD/1.13c": "81fc8ecddc12cc08d3d848c0224bdeb0",
        "LoD/1.13d": "81fc8ecddc12cc08d3d848c0224bdeb0"
      }
    },
    "d2net.dll____updatetlocinfo": {
      "addresses": {
        "LoD/1.11": "0x6FBF32E7",
        "LoD/1.11b": "0x6FBF32E7",
        "LoD/1.12a": "0x6FBF330C",
        "LoD/1.13c": "0x6FBF330C",
        "LoD/1.13d": "0x6FBF32E7"
      },
      "rvas": {
        "LoD/1.11": "0x32E7",
        "LoD/1.11b": "0x32E7",
        "LoD/1.12a": "0x330C",
        "LoD/1.13c": "0x330C",
        "LoD/1.13d": "0x32E7"
      },
      "sizes": {
        "LoD/1.11": 50,
        "LoD/1.11b": 50,
        "LoD/1.12a": 50,
        "LoD/1.13c": 50,
        "LoD/1.13d": 50
      },
      "name": "___updatetlocinfo",
      "signature": "pthreadlocinfo ___updatetlocinfo(void)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___updatetlocinfo\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:202d2c66c8a5b404ad3bf64c94b499c1",
      "basic_block_counts": {
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "202d2c66c8a5b404ad3bf64c94b499c1",
        "LoD/1.11b": "202d2c66c8a5b404ad3bf64c94b499c1",
        "LoD/1.12a": "202d2c66c8a5b404ad3bf64c94b499c1",
        "LoD/1.13c": "202d2c66c8a5b404ad3bf64c94b499c1",
        "LoD/1.13d": "202d2c66c8a5b404ad3bf64c94b499c1"
      }
    },
    "d2net.dll_MapMessageIdToCommand": {
      "addresses": {
        "LoD/1.11": "0x6FBF3322",
        "LoD/1.11b": "0x6FBF3322",
        "LoD/1.12a": "0x6FBF3347",
        "LoD/1.13c": "0x6FBF3347",
        "LoD/1.13d": "0x6FBF3322"
      },
      "rvas": {
        "LoD/1.11": "0x3322",
        "LoD/1.11b": "0x3322",
        "LoD/1.12a": "0x3347",
        "LoD/1.13c": "0x3347",
        "LoD/1.13d": "0x3322"
      },
      "sizes": {
        "LoD/1.11": 47,
        "LoD/1.11b": 47,
        "LoD/1.12a": 47,
        "LoD/1.13c": 47,
        "LoD/1.13d": 47
      },
      "name": "MapMessageIdToCommand",
      "signature": "uint MapMessageIdToCommand(void)",
      "calling_convention": "__stdcall",
      "comment": "Maps a network message ID to its corresponding command code.\\\"",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:ef80c025e3831b06764dc8da4f7409c0",
      "basic_block_counts": {
        "LoD/1.11": 9,
        "LoD/1.11b": 9,
        "LoD/1.12a": 9,
        "LoD/1.13c": 9,
        "LoD/1.13d": 9
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "ef80c025e3831b06764dc8da4f7409c0",
        "LoD/1.11b": "ef80c025e3831b06764dc8da4f7409c0",
        "LoD/1.12a": "ef80c025e3831b06764dc8da4f7409c0",
        "LoD/1.13c": "ef80c025e3831b06764dc8da4f7409c0",
        "LoD/1.13d": "ef80c025e3831b06764dc8da4f7409c0"
      }
    },
    "d2net.dll_setSBCS": {
      "addresses": {
        "LoD/1.11": "0x6FBF3351",
        "LoD/1.11b": "0x6FBF3351",
        "LoD/1.12a": "0x6FBF3376",
        "LoD/1.13c": "0x6FBF3376",
        "LoD/1.13d": "0x6FBF3351"
      },
      "rvas": {
        "LoD/1.11": "0x3351",
        "LoD/1.11b": "0x3351",
        "LoD/1.12a": "0x3376",
        "LoD/1.13c": "0x3376",
        "LoD/1.13d": "0x3351"
      },
      "sizes": {
        "LoD/1.11": 41,
        "LoD/1.11b": 41,
        "LoD/1.12a": 41,
        "LoD/1.13c": 41,
        "LoD/1.13d": 41
      },
      "name": "setSBCS",
      "signature": "undefined setSBCS(void)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n _setSBCS\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:3586df3e31dd0bc0a688e61a43024ab7",
      "basic_block_counts": {
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "3586df3e31dd0bc0a688e61a43024ab7",
        "LoD/1.11b": "3586df3e31dd0bc0a688e61a43024ab7",
        "LoD/1.12a": "3586df3e31dd0bc0a688e61a43024ab7",
        "LoD/1.13c": "3586df3e31dd0bc0a688e61a43024ab7",
        "LoD/1.13d": "3586df3e31dd0bc0a688e61a43024ab7"
      }
    },
    "d2net.dll_setSBUpLow": {
      "addresses": {
        "LoD/1.11": "0x6FBF337A",
        "LoD/1.11b": "0x6FBF337A"
      },
      "rvas": {
        "LoD/1.11": "0x337A",
        "LoD/1.11b": "0x337A"
      },
      "sizes": {
        "LoD/1.11": 396,
        "LoD/1.11b": 396
      },
      "name": "setSBUpLow",
      "signature": "undefined setSBUpLow(void)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n _setSBUpLow\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:0c44e947b1ea344017d45b0d6df8c6c5",
      "basic_block_counts": {
        "LoD/1.11": 29,
        "LoD/1.11b": 29
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "0c44e947b1ea344017d45b0d6df8c6c5",
        "LoD/1.11b": "0c44e947b1ea344017d45b0d6df8c6c5"
      }
    },
    "d2net.dll___setmbcp_lk": {
      "addresses": {
        "LoD/1.11": "0x6FBF3506",
        "LoD/1.11b": "0x6FBF3506"
      },
      "rvas": {
        "LoD/1.11": "0x3506",
        "LoD/1.11b": "0x3506"
      },
      "sizes": {
        "LoD/1.11": 400,
        "LoD/1.11b": 400
      },
      "name": "__setmbcp_lk",
      "signature": "undefined __setmbcp_lk(UINT param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __setmbcp_lk\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:aca83c0b308ebe5f47dff9cf83f354c7",
      "basic_block_counts": {
        "LoD/1.11": 33,
        "LoD/1.11b": 33
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "aca83c0b308ebe5f47dff9cf83f354c7",
        "LoD/1.11b": "aca83c0b308ebe5f47dff9cf83f354c7"
      }
    },
    "d2net.dll___setmbcp": {
      "addresses": {
        "LoD/1.11": "0x6FBF3696",
        "LoD/1.11b": "0x6FBF3696",
        "LoD/1.12a": "0x6FBF36CE",
        "LoD/1.13c": "0x6FBF36CE",
        "LoD/1.13d": "0x6FBF3696"
      },
      "rvas": {
        "LoD/1.11": "0x3696",
        "LoD/1.11b": "0x3696",
        "LoD/1.12a": "0x36CE",
        "LoD/1.13c": "0x36CE",
        "LoD/1.13d": "0x3696"
      },
      "sizes": {
        "LoD/1.11": 327,
        "LoD/1.11b": 327,
        "LoD/1.12a": 327,
        "LoD/1.13c": 327,
        "LoD/1.13d": 327
      },
      "name": "__setmbcp",
      "signature": "int __setmbcp(int _CodePage)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __setmbcp\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:3d95938874732b844e73905e6c952bdf",
      "basic_block_counts": {
        "LoD/1.11": 27,
        "LoD/1.11b": 27,
        "LoD/1.12a": 27,
        "LoD/1.13c": 27,
        "LoD/1.13d": 27
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "3d95938874732b844e73905e6c952bdf",
        "LoD/1.11b": "3d95938874732b844e73905e6c952bdf",
        "LoD/1.12a": "3d95938874732b844e73905e6c952bdf",
        "LoD/1.13c": "3d95938874732b844e73905e6c952bdf",
        "LoD/1.13d": "3d95938874732b844e73905e6c952bdf"
      }
    },
    "d2net.dll____sbh_free_block": {
      "addresses": {
        "LoD/1.11": "0x6FBF3877",
        "LoD/1.11b": "0x6FBF3877",
        "LoD/1.12a": "0x6FBF38AF",
        "LoD/1.13c": "0x6FBF38AF",
        "LoD/1.13d": "0x6FBF3877"
      },
      "rvas": {
        "LoD/1.11": "0x3877",
        "LoD/1.11b": "0x3877",
        "LoD/1.12a": "0x38AF",
        "LoD/1.13c": "0x38AF",
        "LoD/1.13d": "0x3877"
      },
      "sizes": {
        "LoD/1.11": 792,
        "LoD/1.11b": 792,
        "LoD/1.12a": 792,
        "LoD/1.13c": 792,
        "LoD/1.13d": 792
      },
      "name": "___sbh_free_block",
      "signature": "undefined ___sbh_free_block(uint * param_1, int param_2)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___sbh_free_block\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:8b97ebec1e2ba4f1376a18655897a974",
      "basic_block_counts": {
        "LoD/1.11": 50,
        "LoD/1.11b": 50,
        "LoD/1.12a": 50,
        "LoD/1.13c": 50,
        "LoD/1.13d": 50
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "8b97ebec1e2ba4f1376a18655897a974",
        "LoD/1.11b": "8b97ebec1e2ba4f1376a18655897a974",
        "LoD/1.12a": "8b97ebec1e2ba4f1376a18655897a974",
        "LoD/1.13c": "8b97ebec1e2ba4f1376a18655897a974",
        "LoD/1.13d": "8b97ebec1e2ba4f1376a18655897a974"
      }
    },
    "d2net.dll____sbh_alloc_new_region": {
      "addresses": {
        "LoD/1.11": "0x6FBF3B8F",
        "LoD/1.11b": "0x6FBF3B8F",
        "LoD/1.12a": "0x6FBF3BC7",
        "LoD/1.13c": "0x6FBF3BC7",
        "LoD/1.13d": "0x6FBF3B8F"
      },
      "rvas": {
        "LoD/1.11": "0x3B8F",
        "LoD/1.11b": "0x3B8F",
        "LoD/1.12a": "0x3BC7",
        "LoD/1.13c": "0x3BC7",
        "LoD/1.13d": "0x3B8F"
      },
      "sizes": {
        "LoD/1.11": 183,
        "LoD/1.11b": 183,
        "LoD/1.12a": 183,
        "LoD/1.13c": 183,
        "LoD/1.13d": 183
      },
      "name": "___sbh_alloc_new_region",
      "signature": "undefined4 * ___sbh_alloc_new_region(void)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Single Match\n ___sbh_alloc_new_region\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:8f7df14e6456cd93f8028b09582e6071",
      "basic_block_counts": {
        "LoD/1.11": 10,
        "LoD/1.11b": 10,
        "LoD/1.12a": 10,
        "LoD/1.13c": 10,
        "LoD/1.13d": 10
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "8f7df14e6456cd93f8028b09582e6071",
        "LoD/1.11b": "8f7df14e6456cd93f8028b09582e6071",
        "LoD/1.12a": "8f7df14e6456cd93f8028b09582e6071",
        "LoD/1.13c": "8f7df14e6456cd93f8028b09582e6071",
        "LoD/1.13d": "8f7df14e6456cd93f8028b09582e6071"
      }
    },
    "d2net.dll____sbh_alloc_new_group": {
      "addresses": {
        "LoD/1.11": "0x6FBF3C46",
        "LoD/1.11b": "0x6FBF3C46",
        "LoD/1.12a": "0x6FBF3C7E",
        "LoD/1.13c": "0x6FBF3C7E",
        "LoD/1.13d": "0x6FBF3C46"
      },
      "rvas": {
        "LoD/1.11": "0x3C46",
        "LoD/1.11b": "0x3C46",
        "LoD/1.12a": "0x3C7E",
        "LoD/1.13c": "0x3C7E",
        "LoD/1.13d": "0x3C46"
      },
      "sizes": {
        "LoD/1.11": 262,
        "LoD/1.11b": 262,
        "LoD/1.12a": 262,
        "LoD/1.13c": 262,
        "LoD/1.13d": 262
      },
      "name": "___sbh_alloc_new_group",
      "signature": "int ___sbh_alloc_new_group(int param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___sbh_alloc_new_group\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:c41f2d1f421c471451958bea4a10fa66",
      "basic_block_counts": {
        "LoD/1.11": 15,
        "LoD/1.11b": 15,
        "LoD/1.12a": 15,
        "LoD/1.13c": 15,
        "LoD/1.13d": 15
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "c41f2d1f421c471451958bea4a10fa66",
        "LoD/1.11b": "c41f2d1f421c471451958bea4a10fa66",
        "LoD/1.12a": "c41f2d1f421c471451958bea4a10fa66",
        "LoD/1.13c": "c41f2d1f421c471451958bea4a10fa66",
        "LoD/1.13d": "c41f2d1f421c471451958bea4a10fa66"
      }
    },
    "d2net.dll____sbh_resize_block": {
      "addresses": {
        "LoD/1.11": "0x6FBF3D4C",
        "LoD/1.11b": "0x6FBF3D4C",
        "LoD/1.12a": "0x6FBF3D84",
        "LoD/1.13c": "0x6FBF3D84",
        "LoD/1.13d": "0x6FBF3D4C"
      },
      "rvas": {
        "LoD/1.11": "0x3D4C",
        "LoD/1.11b": "0x3D4C",
        "LoD/1.12a": "0x3D84",
        "LoD/1.13c": "0x3D84",
        "LoD/1.13d": "0x3D4C"
      },
      "sizes": {
        "LoD/1.11": 735,
        "LoD/1.11b": 735,
        "LoD/1.12a": 735,
        "LoD/1.13c": 735,
        "LoD/1.13d": 735
      },
      "name": "___sbh_resize_block",
      "signature": "undefined4 ___sbh_resize_block(uint * param_1, int param_2, int param_3)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___sbh_resize_block\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:71e3adec86883da683f0e423eb14e485",
      "basic_block_counts": {
        "LoD/1.11": 54,
        "LoD/1.11b": 54,
        "LoD/1.12a": 54,
        "LoD/1.13c": 54,
        "LoD/1.13d": 54
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "71e3adec86883da683f0e423eb14e485",
        "LoD/1.11b": "71e3adec86883da683f0e423eb14e485",
        "LoD/1.12a": "71e3adec86883da683f0e423eb14e485",
        "LoD/1.13c": "71e3adec86883da683f0e423eb14e485",
        "LoD/1.13d": "71e3adec86883da683f0e423eb14e485"
      }
    },
    "d2net.dll____sbh_alloc_block": {
      "addresses": {
        "LoD/1.11": "0x6FBF402B",
        "LoD/1.11b": "0x6FBF402B",
        "LoD/1.12a": "0x6FBF4063",
        "LoD/1.13c": "0x6FBF4063",
        "LoD/1.13d": "0x6FBF402B"
      },
      "rvas": {
        "LoD/1.11": "0x402B",
        "LoD/1.11b": "0x402B",
        "LoD/1.12a": "0x4063",
        "LoD/1.13c": "0x4063",
        "LoD/1.13d": "0x402B"
      },
      "sizes": {
        "LoD/1.11": 764,
        "LoD/1.11b": 764,
        "LoD/1.12a": 764,
        "LoD/1.13c": 764,
        "LoD/1.13d": 764
      },
      "name": "___sbh_alloc_block",
      "signature": "int * ___sbh_alloc_block(uint * param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___sbh_alloc_block\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:fdd552c17b8cb0117d531882b003b7d1",
      "basic_block_counts": {
        "LoD/1.11": 63,
        "LoD/1.11b": 63,
        "LoD/1.12a": 63,
        "LoD/1.13c": 63,
        "LoD/1.13d": 63
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "fdd552c17b8cb0117d531882b003b7d1",
        "LoD/1.11b": "fdd552c17b8cb0117d531882b003b7d1",
        "LoD/1.12a": "fdd552c17b8cb0117d531882b003b7d1",
        "LoD/1.13c": "fdd552c17b8cb0117d531882b003b7d1",
        "LoD/1.13d": "fdd552c17b8cb0117d531882b003b7d1"
      }
    },
    "d2net.dll_StringConcatenate": {
      "addresses": {
        "LoD/1.11": "0x6FBF43C0",
        "LoD/1.11b": "0x6FBF43C0",
        "LoD/1.12a": "0x6FBF43F0",
        "LoD/1.13c": "0x6FBF43F0",
        "LoD/1.13d": "0x6FBF43C0"
      },
      "rvas": {
        "LoD/1.11": "0x43C0",
        "LoD/1.11b": "0x43C0",
        "LoD/1.12a": "0x43F0",
        "LoD/1.13c": "0x43F0",
        "LoD/1.13d": "0x43C0"
      },
      "sizes": {
        "LoD/1.11": 232,
        "LoD/1.11b": 232,
        "LoD/1.12a": 232,
        "LoD/1.13c": 232,
        "LoD/1.13d": 232
      },
      "name": "StringConcatenate",
      "signature": "char * StringConcatenate(char * szDestination, char * szSource)",
      "calling_convention": "__cdecl",
      "comment": "Fast aligned string concatenation using null-byte detection.\n\nAlgorithm:\n1. Align source pointer to 4-byte boundary while processing any unaligned prefix bytes\n2. Find end of destination string using optimized word-wise null detection (magic constant 0x7efefeff)\n3. Align source pointer to 4-byte boundary while copying prefix bytes from source\n4. Process source in aligned 4-byte words using null-byte detection to find string terminator\n5. Determine null position within final word (byte 0, 1, 2, or 3) and write appropriate data\n6. Return pointer to destination string start\n\nThis implementation uses the standard null-byte detection pattern: (value XOR 0xffffffff XOR (value + 0x7efefeff)) AND 0x81010100 detects any null byte in a 32-bit word.\n\nParameters:\n  pDestination: Pointer to destination buffer (null-terminated string where concatenation target resides)\n  pSource: Pointer to source string to append (null-terminated)\n\nReturns:\n  Pointer to destination string (same as pDestination input)\n\nSpecial Cases:\n  - Handles unaligned string pointers by processing byte-by-byte until 4-byte alignment\n  - Uses word-wise operations for bulk copying once aligned\n  - Correctly positions null terminator within final word based on null byte location",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:f1c393de2fac70496494aea734de5675",
      "basic_block_counts": {
        "LoD/1.11": 29,
        "LoD/1.11b": 29,
        "LoD/1.12a": 29,
        "LoD/1.13c": 29,
        "LoD/1.13d": 29
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "f1c393de2fac70496494aea734de5675",
        "LoD/1.11b": "f1c393de2fac70496494aea734de5675",
        "LoD/1.12a": "f1c393de2fac70496494aea734de5675",
        "LoD/1.13c": "f1c393de2fac70496494aea734de5675",
        "LoD/1.13d": "f1c393de2fac70496494aea734de5675"
      }
    },
    "d2net.dll__memmove_4540": {
      "addresses": {
        "LoD/1.11": "0x6FBF4540",
        "LoD/1.11b": "0x6FBF4540",
        "LoD/1.12a": "0x6FBF11C0",
        "LoD/1.13c": "0x6FBF4570",
        "LoD/1.13d": "0x6FBF4540"
      },
      "rvas": {
        "LoD/1.11": "0x4540",
        "LoD/1.11b": "0x4540",
        "LoD/1.12a": "0x11C0",
        "LoD/1.13c": "0x4570",
        "LoD/1.13d": "0x4540"
      },
      "sizes": {
        "LoD/1.11": 672,
        "LoD/1.11b": 672,
        "LoD/1.12a": 672,
        "LoD/1.13c": 672,
        "LoD/1.13d": 672
      },
      "name": "_memmove",
      "signature": "void * _memmove(void * _Dst, void * _Src, size_t _Size)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n _memmove\n\nLibraries: Visual Studio 2003 Debug, Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:378e464c38840f3332fec8fa0fd86d30",
      "basic_block_counts": {
        "LoD/1.11": 63,
        "LoD/1.11b": 63,
        "LoD/1.12a": 63,
        "LoD/1.13c": 63,
        "LoD/1.13d": 63
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "378e464c38840f3332fec8fa0fd86d30",
        "LoD/1.11b": "378e464c38840f3332fec8fa0fd86d30",
        "LoD/1.12a": "378e464c38840f3332fec8fa0fd86d30",
        "LoD/1.13c": "378e464c38840f3332fec8fa0fd86d30",
        "LoD/1.13d": "378e464c38840f3332fec8fa0fd86d30"
      }
    },
    "d2net.dll____crtMessageBoxA": {
      "addresses": {
        "LoD/1.11": "0x6FBF487D",
        "LoD/1.11b": "0x6FBF487D",
        "LoD/1.12a": "0x6FBF48AD",
        "LoD/1.13c": "0x6FBF48AD",
        "LoD/1.13d": "0x6FBF487D"
      },
      "rvas": {
        "LoD/1.11": "0x487D",
        "LoD/1.11b": "0x487D",
        "LoD/1.12a": "0x48AD",
        "LoD/1.13c": "0x48AD",
        "LoD/1.13d": "0x487D"
      },
      "sizes": {
        "LoD/1.11": 249,
        "LoD/1.11b": 249,
        "LoD/1.12a": 249,
        "LoD/1.13c": 249,
        "LoD/1.13d": 249
      },
      "name": "___crtMessageBoxA",
      "signature": "int ___crtMessageBoxA(LPCSTR _LpText, LPCSTR _LpCaption, uint _UType)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___crtMessageBoxA\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "STR",
      "index": "STR:d73f4455ba8d6ae05bafe5684bccdb5a",
      "strings": {
        "LoD/1.11": [
          "\"GetLastActivePopup\"",
          "\"GetUserObjectInformationA\"",
          "\"user32.dll\"",
          "\"MessageBoxA\"",
          "\"GetActiveWindow\""
        ],
        "LoD/1.11b": [
          "\"GetLastActivePopup\"",
          "\"GetUserObjectInformationA\"",
          "\"user32.dll\"",
          "\"MessageBoxA\"",
          "\"GetActiveWindow\""
        ],
        "LoD/1.12a": [
          "\"GetLastActivePopup\"",
          "\"GetUserObjectInformationA\"",
          "\"user32.dll\"",
          "\"MessageBoxA\"",
          "\"GetActiveWindow\""
        ],
        "LoD/1.13c": [
          "\"GetLastActivePopup\"",
          "\"GetUserObjectInformationA\"",
          "\"user32.dll\"",
          "\"MessageBoxA\"",
          "\"GetActiveWindow\""
        ],
        "LoD/1.13d": [
          "\"GetLastActivePopup\"",
          "\"GetUserObjectInformationA\"",
          "\"user32.dll\"",
          "\"MessageBoxA\"",
          "\"GetActiveWindow\""
        ]
      },
      "basic_block_counts": {
        "LoD/1.11": 20,
        "LoD/1.11b": 20,
        "LoD/1.12a": 20,
        "LoD/1.13c": 20,
        "LoD/1.13d": 20
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "17ea33ac44dc56c9bc7a10bf336c7377",
        "LoD/1.11b": "17ea33ac44dc56c9bc7a10bf336c7377",
        "LoD/1.12a": "17ea33ac44dc56c9bc7a10bf336c7377",
        "LoD/1.13c": "17ea33ac44dc56c9bc7a10bf336c7377",
        "LoD/1.13d": "17ea33ac44dc56c9bc7a10bf336c7377"
      }
    },
    "d2net.dll_ReportSecurityFailure": {
      "addresses": {
        "LoD/1.11": "0x6FBF4AA4",
        "LoD/1.11b": "0x6FBF4AA4",
        "LoD/1.12a": "0x6FBF4AD4",
        "LoD/1.13c": "0x6FBF4AD4",
        "LoD/1.13d": "0x6FBF4AA4"
      },
      "rvas": {
        "LoD/1.11": "0x4AA4",
        "LoD/1.11b": "0x4AA4",
        "LoD/1.12a": "0x4AD4",
        "LoD/1.13c": "0x4AD4",
        "LoD/1.13d": "0x4AA4"
      },
      "sizes": {
        "LoD/1.11": 41,
        "LoD/1.11b": 41,
        "LoD/1.12a": 41,
        "LoD/1.13c": 41,
        "LoD/1.13d": 41
      },
      "name": "ReportSecurityFailure",
      "signature": "void ReportSecurityFailure(void)",
      "calling_convention": "__cdecl",
      "comment": "Terminates application after security validation failure. Called when stack canary verification fails.\nAlgorithm: 1) Initialize SEH frame 2) Clear exception status 3) Display security error dialog 4) Set exception flag 5) Exit with code 3\nParameters: None - function takes no parameters\nReturns: void - function never returns; ExitProcess terminates immediately\nSpecial Cases: SEH exception handler may be triggered if ExitProcess fails; exit code 3 indicates security failure\nSecurity Context: Part of stack canary protection against buffer overflow attacks; called by VerifyStackCanary",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:9fd359b66679d8b6a2f1c57a264fe596",
      "basic_block_counts": {
        "LoD/1.11": 2,
        "LoD/1.11b": 2,
        "LoD/1.12a": 2,
        "LoD/1.13c": 2,
        "LoD/1.13d": 2
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "9fd359b66679d8b6a2f1c57a264fe596",
        "LoD/1.11b": "9fd359b66679d8b6a2f1c57a264fe596",
        "LoD/1.12a": "9fd359b66679d8b6a2f1c57a264fe596",
        "LoD/1.13c": "9fd359b66679d8b6a2f1c57a264fe596",
        "LoD/1.13d": "9fd359b66679d8b6a2f1c57a264fe596"
      }
    },
    "d2net.dll_VerifyStackCanary": {
      "addresses": {
        "LoD/1.11": "0x6FBF4AD5",
        "LoD/1.11b": "0x6FBF4AD5",
        "LoD/1.12a": "0x6FBF4B05",
        "LoD/1.13c": "0x6FBF4B05",
        "LoD/1.13d": "0x6FBF4AD5"
      },
      "rvas": {
        "LoD/1.11": "0x4AD5",
        "LoD/1.11b": "0x4AD5",
        "LoD/1.12a": "0x4B05",
        "LoD/1.13c": "0x4B05",
        "LoD/1.13d": "0x4AD5"
      },
      "sizes": {
        "LoD/1.11": 14,
        "LoD/1.11b": 14,
        "LoD/1.12a": 14,
        "LoD/1.13c": 14,
        "LoD/1.13d": 14
      },
      "name": "VerifyStackCanary",
      "signature": "void VerifyStackCanary(uint dwCanaryValue)",
      "calling_convention": "__fastcall",
      "comment": "Validates stack guard canary against global seed to detect buffer overflow attacks.\nAlgorithm:\n1. Load global master canary value from g_dwStackGuardSeed memory location\n2. Compare received dwCanaryValue parameter (ECX register) with master canary\n3. If equal, canary validation passes - return to caller normally\n4. If not equal, stack buffer overflow detected - jump to error handler\n5. Error handler displays security failure dialog to user\n6. Call ExitProcess(3) to terminate with exit code 3\nParameters:\ndwCanaryValue (uint): Stack guard canary via __fastcall ECX register\nReturns:\nvoid - Returns normally if canary valid, or exits via ExitProcess(3)\nSpecial Cases:\nStack canary typically equals g_dwStackGuardSeed XOR'd with local frame address",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:4efdd923a388be710585d381cbbbfb83",
      "basic_block_counts": {
        "LoD/1.11": 3,
        "LoD/1.11b": 3,
        "LoD/1.12a": 3,
        "LoD/1.13c": 3,
        "LoD/1.13d": 3
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "4efdd923a388be710585d381cbbbfb83",
        "LoD/1.11b": "4efdd923a388be710585d381cbbbfb83",
        "LoD/1.12a": "4efdd923a388be710585d381cbbbfb83",
        "LoD/1.13c": "4efdd923a388be710585d381cbbbfb83",
        "LoD/1.13d": "4efdd923a388be710585d381cbbbfb83"
      }
    },
    "d2net.dll____free_lc_time": {
      "addresses": {
        "LoD/1.11": "0x6FBF4AE3",
        "LoD/1.11b": "0x6FBF4AE3",
        "LoD/1.12a": "0x6FBF4B13",
        "LoD/1.13c": "0x6FBF4B13",
        "LoD/1.13d": "0x6FBF4AE3"
      },
      "rvas": {
        "LoD/1.11": "0x4AE3",
        "LoD/1.11b": "0x4AE3",
        "LoD/1.12a": "0x4B13",
        "LoD/1.13c": "0x4B13",
        "LoD/1.13d": "0x4AE3"
      },
      "sizes": {
        "LoD/1.11": 400,
        "LoD/1.11b": 400,
        "LoD/1.12a": 400,
        "LoD/1.13c": 400,
        "LoD/1.13d": 400
      },
      "name": "___free_lc_time",
      "signature": "undefined ___free_lc_time(undefined4 * param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___free_lc_time\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:6b4ad6d2941b712fcff606229e9dd829",
      "basic_block_counts": {
        "LoD/1.11": 3,
        "LoD/1.11b": 3,
        "LoD/1.12a": 3,
        "LoD/1.13c": 3,
        "LoD/1.13d": 3
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "6b4ad6d2941b712fcff606229e9dd829",
        "LoD/1.11b": "6b4ad6d2941b712fcff606229e9dd829",
        "LoD/1.12a": "6b4ad6d2941b712fcff606229e9dd829",
        "LoD/1.13c": "6b4ad6d2941b712fcff606229e9dd829",
        "LoD/1.13d": "6b4ad6d2941b712fcff606229e9dd829"
      }
    },
    "d2net.dll____free_lconv_num": {
      "addresses": {
        "LoD/1.11": "0x6FBF4C73",
        "LoD/1.11b": "0x6FBF4C73",
        "LoD/1.12a": "0x6FBF4CA3",
        "LoD/1.13c": "0x6FBF4CA3",
        "LoD/1.13d": "0x6FBF4C73"
      },
      "rvas": {
        "LoD/1.11": "0x4C73",
        "LoD/1.11b": "0x4C73",
        "LoD/1.12a": "0x4CA3",
        "LoD/1.13c": "0x4CA3",
        "LoD/1.13d": "0x4C73"
      },
      "sizes": {
        "LoD/1.11": 95,
        "LoD/1.11b": 95,
        "LoD/1.12a": 95,
        "LoD/1.13c": 95,
        "LoD/1.13d": 95
      },
      "name": "___free_lconv_num",
      "signature": "undefined ___free_lconv_num(undefined4 * param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___free_lconv_num\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:f70a35b7fba7d58d54c96ad387278a4c",
      "basic_block_counts": {
        "LoD/1.11": 11,
        "LoD/1.11b": 11,
        "LoD/1.12a": 11,
        "LoD/1.13c": 11,
        "LoD/1.13d": 11
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "f70a35b7fba7d58d54c96ad387278a4c",
        "LoD/1.11b": "f70a35b7fba7d58d54c96ad387278a4c",
        "LoD/1.12a": "f70a35b7fba7d58d54c96ad387278a4c",
        "LoD/1.13c": "f70a35b7fba7d58d54c96ad387278a4c",
        "LoD/1.13d": "f70a35b7fba7d58d54c96ad387278a4c"
      }
    },
    "d2net.dll____free_lconv_mon": {
      "addresses": {
        "LoD/1.11": "0x6FBF4CD2",
        "LoD/1.11b": "0x6FBF4CD2",
        "LoD/1.12a": "0x6FBF4D02",
        "LoD/1.13c": "0x6FBF4D02",
        "LoD/1.13d": "0x6FBF4CD2"
      },
      "rvas": {
        "LoD/1.11": "0x4CD2",
        "LoD/1.11b": "0x4CD2",
        "LoD/1.12a": "0x4D02",
        "LoD/1.13c": "0x4D02",
        "LoD/1.13d": "0x4CD2"
      },
      "sizes": {
        "LoD/1.11": 217,
        "LoD/1.11b": 217,
        "LoD/1.12a": 217,
        "LoD/1.13c": 217,
        "LoD/1.13d": 217
      },
      "name": "___free_lconv_mon",
      "signature": "undefined ___free_lconv_mon(int param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___free_lconv_mon\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:470047ed1f9244aa874a163facc5cee5",
      "basic_block_counts": {
        "LoD/1.11": 23,
        "LoD/1.11b": 23,
        "LoD/1.12a": 23,
        "LoD/1.13c": 23,
        "LoD/1.13d": 23
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "470047ed1f9244aa874a163facc5cee5",
        "LoD/1.11b": "470047ed1f9244aa874a163facc5cee5",
        "LoD/1.12a": "470047ed1f9244aa874a163facc5cee5",
        "LoD/1.13c": "470047ed1f9244aa874a163facc5cee5",
        "LoD/1.13d": "470047ed1f9244aa874a163facc5cee5"
      }
    },
    "d2net.dll__strcspn": {
      "addresses": {
        "LoD/1.11": "0x6FBF4DB0",
        "LoD/1.11b": "0x6FBF4DB0",
        "LoD/1.12a": "0x6FBF4DE0",
        "LoD/1.13c": "0x6FBF4DE0",
        "LoD/1.13d": "0x6FBF4DB0"
      },
      "rvas": {
        "LoD/1.11": "0x4DB0",
        "LoD/1.11b": "0x4DB0",
        "LoD/1.12a": "0x4DE0",
        "LoD/1.13c": "0x4DE0",
        "LoD/1.13d": "0x4DB0"
      },
      "sizes": {
        "LoD/1.11": 70,
        "LoD/1.11b": 70,
        "LoD/1.12a": 70,
        "LoD/1.13c": 70,
        "LoD/1.13d": 70
      },
      "name": "_strcspn",
      "signature": "size_t _strcspn(char * _Str, char * _Control)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n _strcspn\n\nLibrary: Visual Studio",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:5f5a2dadfb6e3cd7b350f3b00225ebe0",
      "basic_block_counts": {
        "LoD/1.11": 7,
        "LoD/1.11b": 7,
        "LoD/1.12a": 7,
        "LoD/1.13c": 7,
        "LoD/1.13d": 7
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "5f5a2dadfb6e3cd7b350f3b00225ebe0",
        "LoD/1.11b": "5f5a2dadfb6e3cd7b350f3b00225ebe0",
        "LoD/1.12a": "5f5a2dadfb6e3cd7b350f3b00225ebe0",
        "LoD/1.13c": "5f5a2dadfb6e3cd7b350f3b00225ebe0",
        "LoD/1.13d": "5f5a2dadfb6e3cd7b350f3b00225ebe0"
      }
    },
    "d2net.dll__strcmp": {
      "addresses": {
        "LoD/1.11": "0x6FBF4E00",
        "LoD/1.11b": "0x6FBF4E00",
        "LoD/1.12a": "0x6FBF4E30",
        "LoD/1.13c": "0x6FBF4E30",
        "LoD/1.13d": "0x6FBF4E00"
      },
      "rvas": {
        "LoD/1.11": "0x4E00",
        "LoD/1.11b": "0x4E00",
        "LoD/1.12a": "0x4E30",
        "LoD/1.13c": "0x4E30",
        "LoD/1.13d": "0x4E00"
      },
      "sizes": {
        "LoD/1.11": 135,
        "LoD/1.11b": 135,
        "LoD/1.12a": 135,
        "LoD/1.13c": 135,
        "LoD/1.13d": 135
      },
      "name": "_strcmp",
      "signature": "int _strcmp(char * _Str1, char * _Str2)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n _strcmp\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:cf6e169535cd0b739256cb2ecfc119ba",
      "basic_block_counts": {
        "LoD/1.11": 21,
        "LoD/1.11b": 21,
        "LoD/1.12a": 21,
        "LoD/1.13c": 21,
        "LoD/1.13d": 21
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "cf6e169535cd0b739256cb2ecfc119ba",
        "LoD/1.11b": "cf6e169535cd0b739256cb2ecfc119ba",
        "LoD/1.12a": "cf6e169535cd0b739256cb2ecfc119ba",
        "LoD/1.13c": "cf6e169535cd0b739256cb2ecfc119ba",
        "LoD/1.13d": "cf6e169535cd0b739256cb2ecfc119ba"
      }
    },
    "d2net.dll__memcmp": {
      "addresses": {
        "LoD/1.11": "0x6FBF4E90",
        "LoD/1.11b": "0x6FBF4E90",
        "LoD/1.12a": "0x6FBF4EC0",
        "LoD/1.13c": "0x6FBF4EC0",
        "LoD/1.13d": "0x6FBF4E90"
      },
      "rvas": {
        "LoD/1.11": "0x4E90",
        "LoD/1.11b": "0x4E90",
        "LoD/1.12a": "0x4EC0",
        "LoD/1.13c": "0x4EC0",
        "LoD/1.13d": "0x4E90"
      },
      "sizes": {
        "LoD/1.11": 184,
        "LoD/1.11b": 184,
        "LoD/1.12a": 184,
        "LoD/1.13c": 184,
        "LoD/1.13d": 184
      },
      "name": "_memcmp",
      "signature": "int _memcmp(void * _Buf1, void * _Buf2, size_t _Size)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n _memcmp\n\nLibraries: Visual Studio 2003 Debug, Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:7cec3aaa3bf000edc30666bb4980e176",
      "basic_block_counts": {
        "LoD/1.11": 26,
        "LoD/1.11b": 26,
        "LoD/1.12a": 26,
        "LoD/1.13c": 26,
        "LoD/1.13d": 26
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "7cec3aaa3bf000edc30666bb4980e176",
        "LoD/1.11b": "7cec3aaa3bf000edc30666bb4980e176",
        "LoD/1.12a": "7cec3aaa3bf000edc30666bb4980e176",
        "LoD/1.13c": "7cec3aaa3bf000edc30666bb4980e176",
        "LoD/1.13d": "7cec3aaa3bf000edc30666bb4980e176"
      }
    },
    "d2net.dll____crtGetStringTypeA": {
      "addresses": {
        "LoD/1.11": "0x6FBF4F48",
        "LoD/1.11b": "0x6FBF4F48",
        "LoD/1.12a": "0x6FBF4F78",
        "LoD/1.13c": "0x6FBF4F78",
        "LoD/1.13d": "0x6FBF4F48"
      },
      "rvas": {
        "LoD/1.11": "0x4F48",
        "LoD/1.11b": "0x4F48",
        "LoD/1.12a": "0x4F78",
        "LoD/1.13c": "0x4F78",
        "LoD/1.13d": "0x4F48"
      },
      "sizes": {
        "LoD/1.11": 421,
        "LoD/1.11b": 421,
        "LoD/1.12a": 421,
        "LoD/1.13c": 421,
        "LoD/1.13d": 421
      },
      "name": "___crtGetStringTypeA",
      "signature": "BOOL ___crtGetStringTypeA(_locale_t _Plocinfo, DWORD _DWInfoType, LPCSTR _LpSrcStr, int _CchSrc, LPWORD _LpCharType, int _Code_page, BOOL _BError)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___crtGetStringTypeA\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:fe7518f9cbcae43d3194d5d079593073",
      "basic_block_counts": {
        "LoD/1.11": 33,
        "LoD/1.11b": 33,
        "LoD/1.12a": 33,
        "LoD/1.13c": 33,
        "LoD/1.13d": 33
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "fe7518f9cbcae43d3194d5d079593073",
        "LoD/1.11b": "fe7518f9cbcae43d3194d5d079593073",
        "LoD/1.12a": "fe7518f9cbcae43d3194d5d079593073",
        "LoD/1.13c": "fe7518f9cbcae43d3194d5d079593073",
        "LoD/1.13d": "fe7518f9cbcae43d3194d5d079593073"
      }
    },
    "d2net.dll__strpbrk": {
      "addresses": {
        "LoD/1.11": "0x6FBF5150",
        "LoD/1.11b": "0x6FBF5150",
        "LoD/1.12a": "0x6FBF5180",
        "LoD/1.13c": "0x6FBF5180",
        "LoD/1.13d": "0x6FBF5150"
      },
      "rvas": {
        "LoD/1.11": "0x5150",
        "LoD/1.11b": "0x5150",
        "LoD/1.12a": "0x5180",
        "LoD/1.13c": "0x5180",
        "LoD/1.13d": "0x5150"
      },
      "sizes": {
        "LoD/1.11": 64,
        "LoD/1.11b": 64,
        "LoD/1.12a": 64,
        "LoD/1.13c": 64,
        "LoD/1.13d": 64
      },
      "name": "_strpbrk",
      "signature": "char * _strpbrk(char * _Str, char * _Control)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n _strpbrk\n\nLibrary: Visual Studio",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:262b55d4b1f21fd166621d0ca2135ed8",
      "basic_block_counts": {
        "LoD/1.11": 8,
        "LoD/1.11b": 8,
        "LoD/1.12a": 8,
        "LoD/1.13c": 8,
        "LoD/1.13d": 8
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "262b55d4b1f21fd166621d0ca2135ed8",
        "LoD/1.11b": "262b55d4b1f21fd166621d0ca2135ed8",
        "LoD/1.12a": "262b55d4b1f21fd166621d0ca2135ed8",
        "LoD/1.13c": "262b55d4b1f21fd166621d0ca2135ed8",
        "LoD/1.13d": "262b55d4b1f21fd166621d0ca2135ed8"
      }
    },
    "d2net.dll____crtLCMapStringA": {
      "addresses": {
        "LoD/1.11": "0x6FBF5190",
        "LoD/1.11b": "0x6FBF5190"
      },
      "rvas": {
        "LoD/1.11": "0x5190",
        "LoD/1.11b": "0x5190"
      },
      "sizes": {
        "LoD/1.11": 886,
        "LoD/1.11b": 886
      },
      "name": "___crtLCMapStringA",
      "signature": "int ___crtLCMapStringA(_locale_t _Plocinfo, LPCWSTR _LocaleName, DWORD _DwMapFlag, LPCSTR _LpSrcStr, int _CchSrc, LPSTR _LpDestStr, int _CchDest, int _Code_page, BOOL _BError)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___crtLCMapStringA\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:40ace89e5da5d434e25a5d26402f71e1",
      "basic_block_counts": {
        "LoD/1.11": 65,
        "LoD/1.11b": 65
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "40ace89e5da5d434e25a5d26402f71e1",
        "LoD/1.11b": "40ace89e5da5d434e25a5d26402f71e1"
      }
    },
    "d2net.dll____security_init_cookie": {
      "addresses": {
        "LoD/1.11": "0x6FBF554C",
        "LoD/1.11b": "0x6FBF554C",
        "LoD/1.12a": "0x6FBF5596",
        "LoD/1.13c": "0x6FBF5596",
        "LoD/1.13d": "0x6FBF554C"
      },
      "rvas": {
        "LoD/1.11": "0x554C",
        "LoD/1.11b": "0x554C",
        "LoD/1.12a": "0x5596",
        "LoD/1.13c": "0x5596",
        "LoD/1.13d": "0x554C"
      },
      "sizes": {
        "LoD/1.11": 102,
        "LoD/1.11b": 102,
        "LoD/1.12a": 102,
        "LoD/1.13c": 102,
        "LoD/1.13d": 102
      },
      "name": "___security_init_cookie",
      "signature": "void ___security_init_cookie(void)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___security_init_cookie\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:4af6f4d1378e3b27617b296b4a2b16cc",
      "basic_block_counts": {
        "LoD/1.11": 6,
        "LoD/1.11b": 6,
        "LoD/1.12a": 6,
        "LoD/1.13c": 6,
        "LoD/1.13d": 6
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "4af6f4d1378e3b27617b296b4a2b16cc",
        "LoD/1.11b": "4af6f4d1378e3b27617b296b4a2b16cc",
        "LoD/1.12a": "4af6f4d1378e3b27617b296b4a2b16cc",
        "LoD/1.13c": "4af6f4d1378e3b27617b296b4a2b16cc",
        "LoD/1.13d": "4af6f4d1378e3b27617b296b4a2b16cc"
      }
    },
    "d2net.dll____security_error_handler": {
      "addresses": {
        "LoD/1.11": "0x6FBF55B2",
        "LoD/1.11b": "0x6FBF55B2",
        "LoD/1.12a": "0x6FBF55FC",
        "LoD/1.13c": "0x6FBF55FC",
        "LoD/1.13d": "0x6FBF55B2"
      },
      "rvas": {
        "LoD/1.11": "0x55B2",
        "LoD/1.11b": "0x55B2",
        "LoD/1.12a": "0x55FC",
        "LoD/1.13c": "0x55FC",
        "LoD/1.13d": "0x55B2"
      },
      "sizes": {
        "LoD/1.11": 318,
        "LoD/1.11b": 318,
        "LoD/1.12a": 321,
        "LoD/1.13c": 321,
        "LoD/1.13d": 318
      },
      "name": "___security_error_handler",
      "signature": "undefined ___security_error_handler(int param_1)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Single Match\n ___security_error_handler\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "STR",
      "index": "STR:9edd5270653ada86eeecdcb3502d3803",
      "strings": {
        "LoD/1.11": [
          "\"Microsoft Visual C++ Runtime Library\"",
          "\"Buffer overrun detected!\"",
          "\"A security error of unknown cause has been detect...",
          "\"Program: \"",
          "\"<program name unknown>\"",
          "...+2 more"
        ],
        "LoD/1.11b": [
          "\"Microsoft Visual C++ Runtime Library\"",
          "\"Buffer overrun detected!\"",
          "\"A security error of unknown cause has been detect...",
          "\"Program: \"",
          "\"<program name unknown>\"",
          "...+2 more"
        ],
        "LoD/1.12a": [
          "\"Microsoft Visual C++ Runtime Library\"",
          "\"Buffer overrun detected!\"",
          "\"A security error of unknown cause has been detect...",
          "\"Program: \"",
          "\"<program name unknown>\"",
          "...+2 more"
        ],
        "LoD/1.13c": [
          "\"Microsoft Visual C++ Runtime Library\"",
          "\"Buffer overrun detected!\"",
          "\"A security error of unknown cause has been detect...",
          "\"Program: \"",
          "\"<program name unknown>\"",
          "...+2 more"
        ],
        "LoD/1.13d": [
          "\"Microsoft Visual C++ Runtime Library\"",
          "\"Buffer overrun detected!\"",
          "\"A security error of unknown cause has been detect...",
          "\"Program: \"",
          "\"<program name unknown>\"",
          "...+2 more"
        ]
      },
      "basic_block_counts": {
        "LoD/1.11": 12,
        "LoD/1.11b": 12,
        "LoD/1.12a": 12,
        "LoD/1.13c": 12,
        "LoD/1.13d": 12
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "4781dfd6adf98cf006c03a20c8d0acaa",
        "LoD/1.11b": "4781dfd6adf98cf006c03a20c8d0acaa",
        "LoD/1.12a": "fb8791c79d0f02127c874f5d44290f32",
        "LoD/1.13c": "fb8791c79d0f02127c874f5d44290f32",
        "LoD/1.13d": "4781dfd6adf98cf006c03a20c8d0acaa"
      }
    },
    "d2net.dll____ascii_stricmp": {
      "addresses": {
        "LoD/1.11": "0x6FBF5700",
        "LoD/1.11b": "0x6FBF5700",
        "LoD/1.12a": "0x6FBF5750",
        "LoD/1.13c": "0x6FBF5750",
        "LoD/1.13d": "0x6FBF5700"
      },
      "rvas": {
        "LoD/1.11": "0x5700",
        "LoD/1.11b": "0x5700",
        "LoD/1.12a": "0x5750",
        "LoD/1.13c": "0x5750",
        "LoD/1.13d": "0x5700"
      },
      "sizes": {
        "LoD/1.11": 78,
        "LoD/1.11b": 78,
        "LoD/1.12a": 78,
        "LoD/1.13c": 78,
        "LoD/1.13d": 78
      },
      "name": "___ascii_stricmp",
      "signature": "int ___ascii_stricmp(char * _Str1, char * _Str2)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___ascii_stricmp\n\nLibraries: Visual Studio 2003 Debug, Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:cb7271f23b18085c633325272e533a6a",
      "basic_block_counts": {
        "LoD/1.11": 6,
        "LoD/1.11b": 6,
        "LoD/1.12a": 6,
        "LoD/1.13c": 6,
        "LoD/1.13d": 6
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "cb7271f23b18085c633325272e533a6a",
        "LoD/1.11b": "cb7271f23b18085c633325272e533a6a",
        "LoD/1.12a": "cb7271f23b18085c633325272e533a6a",
        "LoD/1.13c": "cb7271f23b18085c633325272e533a6a",
        "LoD/1.13d": "cb7271f23b18085c633325272e533a6a"
      }
    },
    "d2net.dll___resetstkoflw": {
      "addresses": {
        "LoD/1.11": "0x6FBF574E",
        "LoD/1.11b": "0x6FBF574E",
        "LoD/1.12a": "0x6FBF579E",
        "LoD/1.13c": "0x6FBF579E",
        "LoD/1.13d": "0x6FBF574E"
      },
      "rvas": {
        "LoD/1.11": "0x574E",
        "LoD/1.11b": "0x574E",
        "LoD/1.12a": "0x579E",
        "LoD/1.13c": "0x579E",
        "LoD/1.13d": "0x574E"
      },
      "sizes": {
        "LoD/1.11": 227,
        "LoD/1.11b": 227,
        "LoD/1.12a": 227,
        "LoD/1.13c": 227,
        "LoD/1.13d": 227
      },
      "name": "__resetstkoflw",
      "signature": "int __resetstkoflw(void)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __resetstkoflw\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:1bacf15d421243740ab5a96b430ce3dc",
      "basic_block_counts": {
        "LoD/1.11": 16,
        "LoD/1.11b": 16,
        "LoD/1.12a": 16,
        "LoD/1.13c": 16,
        "LoD/1.13d": 16
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "1bacf15d421243740ab5a96b430ce3dc",
        "LoD/1.11b": "1bacf15d421243740ab5a96b430ce3dc",
        "LoD/1.12a": "1bacf15d421243740ab5a96b430ce3dc",
        "LoD/1.13c": "1bacf15d421243740ab5a96b430ce3dc",
        "LoD/1.13d": "1bacf15d421243740ab5a96b430ce3dc"
      }
    },
    "d2net.dll__atol": {
      "addresses": {
        "LoD/1.11": "0x6FBF5831",
        "LoD/1.11b": "0x6FBF5831",
        "LoD/1.12a": "0x6FBF5881",
        "LoD/1.13c": "0x6FBF5881",
        "LoD/1.13d": "0x6FBF5831"
      },
      "rvas": {
        "LoD/1.11": "0x5831",
        "LoD/1.11b": "0x5831",
        "LoD/1.12a": "0x5881",
        "LoD/1.13c": "0x5881",
        "LoD/1.13d": "0x5831"
      },
      "sizes": {
        "LoD/1.11": 136,
        "LoD/1.11b": 136,
        "LoD/1.12a": 136,
        "LoD/1.13c": 136,
        "LoD/1.13d": 136
      },
      "name": "_atol",
      "signature": "long _atol(char * _Str)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n _atol\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:78a86de15981e3f1c945cde9fbd4be9b",
      "basic_block_counts": {
        "LoD/1.11": 21,
        "LoD/1.11b": 21,
        "LoD/1.12a": 21,
        "LoD/1.13c": 21,
        "LoD/1.13d": 21
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "78a86de15981e3f1c945cde9fbd4be9b",
        "LoD/1.11b": "78a86de15981e3f1c945cde9fbd4be9b",
        "LoD/1.12a": "78a86de15981e3f1c945cde9fbd4be9b",
        "LoD/1.13c": "78a86de15981e3f1c945cde9fbd4be9b",
        "LoD/1.13d": "78a86de15981e3f1c945cde9fbd4be9b"
      }
    },
    "d2net.dll____ansicp": {
      "addresses": {
        "LoD/1.11": "0x6FBF58B9",
        "LoD/1.11b": "0x6FBF58B9"
      },
      "rvas": {
        "LoD/1.11": "0x58B9",
        "LoD/1.11b": "0x58B9"
      },
      "sizes": {
        "LoD/1.11": 67,
        "LoD/1.11b": 67
      },
      "name": "___ansicp",
      "signature": "undefined ___ansicp(LCID param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___ansicp\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:137dd1f09c34b57b162936229329b15b",
      "basic_block_counts": {
        "LoD/1.11": 4,
        "LoD/1.11b": 4
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "137dd1f09c34b57b162936229329b15b",
        "LoD/1.11b": "137dd1f09c34b57b162936229329b15b"
      }
    },
    "d2net.dll____convertcp": {
      "addresses": {
        "LoD/1.11": "0x6FBF58FC",
        "LoD/1.11b": "0x6FBF58FC"
      },
      "rvas": {
        "LoD/1.11": "0x58FC",
        "LoD/1.11b": "0x58FC"
      },
      "sizes": {
        "LoD/1.11": 434,
        "LoD/1.11b": 434
      },
      "name": "___convertcp",
      "signature": "undefined ___convertcp(UINT param_1, UINT param_2, char * param_3, size_t * param_4, LPSTR param_5, int param_6)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___convertcp\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:2db85971dc36836255f9e9bf407d84c7",
      "basic_block_counts": {
        "LoD/1.11": 35,
        "LoD/1.11b": 35
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "2db85971dc36836255f9e9bf407d84c7",
        "LoD/1.11b": "2db85971dc36836255f9e9bf407d84c7"
      }
    },
    "d2net.dll____isctype_mt": {
      "addresses": {
        "LoD/1.11": "0x6FBF5AC5",
        "LoD/1.11b": "0x6FBF5AC5",
        "LoD/1.12a": "0x6FBF5B2A",
        "LoD/1.13c": "0x6FBF5B2A",
        "LoD/1.13d": "0x6FBF5AC5"
      },
      "rvas": {
        "LoD/1.11": "0x5AC5",
        "LoD/1.11b": "0x5AC5",
        "LoD/1.12a": "0x5B2A",
        "LoD/1.13c": "0x5B2A",
        "LoD/1.13d": "0x5AC5"
      },
      "sizes": {
        "LoD/1.11": 119,
        "LoD/1.11b": 119,
        "LoD/1.12a": 119,
        "LoD/1.13c": 119,
        "LoD/1.13d": 119
      },
      "name": "___isctype_mt",
      "signature": "uint ___isctype_mt(void * this, int param_1, int param_2, uint param_3)",
      "calling_convention": "__thiscall",
      "comment": "Library Function - Single Match\n ___isctype_mt\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:93d0dc9fd8314e8d90414fa46b2e66d4",
      "basic_block_counts": {
        "LoD/1.11": 9,
        "LoD/1.11b": 9,
        "LoD/1.12a": 9,
        "LoD/1.13c": 9,
        "LoD/1.13d": 9
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "93d0dc9fd8314e8d90414fa46b2e66d4",
        "LoD/1.11b": "93d0dc9fd8314e8d90414fa46b2e66d4",
        "LoD/1.12a": "93d0dc9fd8314e8d90414fa46b2e66d4",
        "LoD/1.13c": "93d0dc9fd8314e8d90414fa46b2e66d4",
        "LoD/1.13d": "93d0dc9fd8314e8d90414fa46b2e66d4"
      }
    },
    "d2net.dll___allmul": {
      "addresses": {
        "LoD/1.11": "0x6FBF5B40",
        "LoD/1.11b": "0x6FBF5B40",
        "LoD/1.12a": "0x6FBF5BB0",
        "LoD/1.13c": "0x6FBF5BB0",
        "LoD/1.13d": "0x6FBF5B40"
      },
      "rvas": {
        "LoD/1.11": "0x5B40",
        "LoD/1.11b": "0x5B40",
        "LoD/1.12a": "0x5BB0",
        "LoD/1.13c": "0x5BB0",
        "LoD/1.13d": "0x5B40"
      },
      "sizes": {
        "LoD/1.11": 52,
        "LoD/1.11b": 52,
        "LoD/1.12a": 52,
        "LoD/1.13c": 52,
        "LoD/1.13d": 52
      },
      "name": "__allmul",
      "signature": "longlong __allmul(uint dwLowA, int nHighA, uint dwLowB, int nHighB)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Single Match\n __allmul\n\nLibrary: Visual Studio",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:d54b31472f74b078be31f20f65c7b2d3",
      "basic_block_counts": {
        "LoD/1.11": 3,
        "LoD/1.11b": 3,
        "LoD/1.12a": 3,
        "LoD/1.13c": 3,
        "LoD/1.13d": 3
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "d54b31472f74b078be31f20f65c7b2d3",
        "LoD/1.11b": "d54b31472f74b078be31f20f65c7b2d3",
        "LoD/1.12a": "d54b31472f74b078be31f20f65c7b2d3",
        "LoD/1.13c": "d54b31472f74b078be31f20f65c7b2d3",
        "LoD/1.13d": "d54b31472f74b078be31f20f65c7b2d3"
      }
    },
    "d2net.dll____ascii_strnicmp": {
      "addresses": {
        "LoD/1.11": "0x6FBF5B80",
        "LoD/1.11b": "0x6FBF5B80",
        "LoD/1.12a": "0x6FBF5BF0",
        "LoD/1.13c": "0x6FBF5BF0",
        "LoD/1.13d": "0x6FBF5B80"
      },
      "rvas": {
        "LoD/1.11": "0x5B80",
        "LoD/1.11b": "0x5B80",
        "LoD/1.12a": "0x5BF0",
        "LoD/1.13c": "0x5BF0",
        "LoD/1.13d": "0x5B80"
      },
      "sizes": {
        "LoD/1.11": 97,
        "LoD/1.11b": 97,
        "LoD/1.12a": 97,
        "LoD/1.13c": 97,
        "LoD/1.13d": 97
      },
      "name": "___ascii_strnicmp",
      "signature": "int ___ascii_strnicmp(char * _Str1, char * _Str2, size_t _MaxCount)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___ascii_strnicmp\n\nLibraries: Visual Studio 2003 Debug, Visual Studio 2003 Release",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:ecf4fe5a7e473ceb70f30e35ac316045",
      "basic_block_counts": {
        "LoD/1.11": 16,
        "LoD/1.11b": 16,
        "LoD/1.12a": 16,
        "LoD/1.13c": 16,
        "LoD/1.13d": 16
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "ecf4fe5a7e473ceb70f30e35ac316045",
        "LoD/1.11b": "ecf4fe5a7e473ceb70f30e35ac316045",
        "LoD/1.12a": "ecf4fe5a7e473ceb70f30e35ac316045",
        "LoD/1.13c": "ecf4fe5a7e473ceb70f30e35ac316045",
        "LoD/1.13d": "ecf4fe5a7e473ceb70f30e35ac316045"
      }
    },
    "d2net.dll___aulldvrm": {
      "addresses": {
        "LoD/1.11": "0x6FBF5BF0",
        "LoD/1.11b": "0x6FBF5BF0",
        "LoD/1.12a": "0x6FBF5C60",
        "LoD/1.13c": "0x6FBF5C60",
        "LoD/1.13d": "0x6FBF5BF0"
      },
      "rvas": {
        "LoD/1.11": "0x5BF0",
        "LoD/1.11b": "0x5BF0",
        "LoD/1.12a": "0x5C60",
        "LoD/1.13c": "0x5C60",
        "LoD/1.13d": "0x5BF0"
      },
      "sizes": {
        "LoD/1.11": 149,
        "LoD/1.11b": 149,
        "LoD/1.12a": 149,
        "LoD/1.13c": 149,
        "LoD/1.13d": 149
      },
      "name": "__aulldvrm",
      "signature": "undefined8 __aulldvrm(uint param_1, uint param_2, uint param_3, uint param_4)",
      "calling_convention": "__stdcall",
      "comment": "Library Function - Single Match\n __aulldvrm\n\nLibrary: Visual Studio",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:6b07f716ad39855b07502ac9a8f75c79",
      "basic_block_counts": {
        "LoD/1.11": 11,
        "LoD/1.11b": 11,
        "LoD/1.12a": 11,
        "LoD/1.13c": 11,
        "LoD/1.13d": 11
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "6b07f716ad39855b07502ac9a8f75c79",
        "LoD/1.11b": "6b07f716ad39855b07502ac9a8f75c79",
        "LoD/1.12a": "6b07f716ad39855b07502ac9a8f75c79",
        "LoD/1.13c": "6b07f716ad39855b07502ac9a8f75c79",
        "LoD/1.13d": "6b07f716ad39855b07502ac9a8f75c79"
      }
    },
    "d2net.dll_recv": {
      "addresses": {
        "LoD/1.11": "0x6FBF5D76",
        "LoD/1.11b": "0x6FBF5D7C",
        "LoD/1.12a": "0x6FBF5DE6",
        "LoD/1.13c": "0x6FBF5DE6",
        "LoD/1.13d": "0x6FBF5D76"
      },
      "rvas": {
        "LoD/1.11": "0x5D76",
        "LoD/1.11b": "0x5D7C",
        "LoD/1.12a": "0x5DE6",
        "LoD/1.13c": "0x5DE6",
        "LoD/1.13d": "0x5D76"
      },
      "sizes": {
        "LoD/1.11": 6,
        "LoD/1.11b": 6,
        "LoD/1.12a": 6,
        "LoD/1.13c": 6,
        "LoD/1.13d": 6
      },
      "name": "recv",
      "signature": "int recv(SOCKET s, char * buf, int len, int flags)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:e3e7225badfcf3c2e051c42d71d7237a",
      "basic_block_counts": {
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.12a": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13c": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13d": "e3e7225badfcf3c2e051c42d71d7237a"
      }
    },
    "d2net.dll_htons": {
      "addresses": {
        "LoD/1.11": "0x6FBF5D82",
        "LoD/1.11b": "0x6FBF5D88",
        "LoD/1.12a": "0x6FBF5DF2",
        "LoD/1.13c": "0x6FBF5DF2",
        "LoD/1.13d": "0x6FBF5D82"
      },
      "rvas": {
        "LoD/1.11": "0x5D82",
        "LoD/1.11b": "0x5D88",
        "LoD/1.12a": "0x5DF2",
        "LoD/1.13c": "0x5DF2",
        "LoD/1.13d": "0x5D82"
      },
      "sizes": {
        "LoD/1.11": 6,
        "LoD/1.11b": 6,
        "LoD/1.12a": 6,
        "LoD/1.13c": 6,
        "LoD/1.13d": 6
      },
      "name": "htons",
      "signature": "u_short htons(u_short hostshort)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:e3e7225badfcf3c2e051c42d71d7237a",
      "basic_block_counts": {
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.12a": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13c": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13d": "e3e7225badfcf3c2e051c42d71d7237a"
      }
    },
    "d2net.dll_inet_addr": {
      "addresses": {
        "LoD/1.11": "0x6FBF5D94",
        "LoD/1.11b": "0x6FBF5D94",
        "LoD/1.12a": "0x6FBF5E04",
        "LoD/1.13c": "0x6FBF5E04",
        "LoD/1.13d": "0x6FBF5D94"
      },
      "rvas": {
        "LoD/1.11": "0x5D94",
        "LoD/1.11b": "0x5D94",
        "LoD/1.12a": "0x5E04",
        "LoD/1.13c": "0x5E04",
        "LoD/1.13d": "0x5D94"
      },
      "sizes": {
        "LoD/1.11": 6,
        "LoD/1.11b": 6,
        "LoD/1.12a": 6,
        "LoD/1.13c": 6,
        "LoD/1.13d": 6
      },
      "name": "inet_addr",
      "signature": "ulong inet_addr(char * cp)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:e3e7225badfcf3c2e051c42d71d7237a",
      "basic_block_counts": {
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.12a": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13c": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13d": "e3e7225badfcf3c2e051c42d71d7237a"
      }
    },
    "d2net.dll_inet_ntoa": {
      "addresses": {
        "LoD/1.11": "0x6FBF5DA0",
        "LoD/1.11b": "0x6FBF5DA0",
        "LoD/1.12a": "0x6FBF5E10",
        "LoD/1.13c": "0x6FBF5E10",
        "LoD/1.13d": "0x6FBF5DA0"
      },
      "rvas": {
        "LoD/1.11": "0x5DA0",
        "LoD/1.11b": "0x5DA0",
        "LoD/1.12a": "0x5E10",
        "LoD/1.13c": "0x5E10",
        "LoD/1.13d": "0x5DA0"
      },
      "sizes": {
        "LoD/1.11": 6,
        "LoD/1.11b": 6,
        "LoD/1.12a": 6,
        "LoD/1.13c": 6,
        "LoD/1.13d": 6
      },
      "name": "inet_ntoa",
      "signature": "char * inet_ntoa(in_addr in)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:e3e7225badfcf3c2e051c42d71d7237a",
      "basic_block_counts": {
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.12a": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13c": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13d": "e3e7225badfcf3c2e051c42d71d7237a"
      }
    },
    "d2net.dll_CopyMemoryAndDetectTerminator": {
      "addresses": {
        "LoD/1.11": "0x6FBF5DAC",
        "LoD/1.11b": "0x6FBF5DB2",
        "LoD/1.12a": "0x6FBF5E1C",
        "LoD/1.13c": "0x6FBF5E1C",
        "LoD/1.13d": "0x6FBF5DAC"
      },
      "rvas": {
        "LoD/1.11": "0x5DAC",
        "LoD/1.11b": "0x5DB2",
        "LoD/1.12a": "0x5E1C",
        "LoD/1.13c": "0x5E1C",
        "LoD/1.13d": "0x5DAC"
      },
      "sizes": {
        "LoD/1.11": 6,
        "LoD/1.11b": 6,
        "LoD/1.12a": 6,
        "LoD/1.13c": 6,
        "LoD/1.13d": 6
      },
      "name": "CopyMemoryAndDetectTerminator",
      "signature": "byte * CopyMemoryAndDetectTerminator(byte * pbDestination, byte * pbSource, int nCbLength)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:e3e7225badfcf3c2e051c42d71d7237a",
      "basic_block_counts": {
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.12a": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13c": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13d": "e3e7225badfcf3c2e051c42d71d7237a"
      }
    },
    "d2net.dll_BuildProjectPathThunk": {
      "addresses": {
        "LoD/1.11": "0x6FBF5DCA",
        "LoD/1.11b": "0x6FBF5DD0",
        "LoD/1.12a": "0x6FBF5EEE",
        "LoD/1.13c": "0x6FBF5E3A",
        "LoD/1.13d": "0x6FBF5E7E"
      },
      "rvas": {
        "LoD/1.11": "0x5DCA",
        "LoD/1.11b": "0x5DD0",
        "LoD/1.12a": "0x5EEE",
        "LoD/1.13c": "0x5E3A",
        "LoD/1.13d": "0x5E7E"
      },
      "sizes": {
        "LoD/1.11": 6,
        "LoD/1.11b": 6,
        "LoD/1.12a": 6,
        "LoD/1.13c": 6,
        "LoD/1.13d": 6
      },
      "name": "BuildProjectPathThunk",
      "signature": "void BuildProjectPathThunk(int nPathType)",
      "calling_convention": "__fastcall",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:e3e7225badfcf3c2e051c42d71d7237a",
      "basic_block_counts": {
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.12a": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13c": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13d": "e3e7225badfcf3c2e051c42d71d7237a"
      }
    },
    "d2net.dll_DecodeHuffmanBitStream": {
      "addresses": {
        "LoD/1.11": "0x6FBF5DDC",
        "LoD/1.11b": "0x6FBF5DDC",
        "LoD/1.12a": "0x6FBF5EFA",
        "LoD/1.13c": "0x6FBF5E4C",
        "LoD/1.13d": "0x6FBF5E8A"
      },
      "rvas": {
        "LoD/1.11": "0x5DDC",
        "LoD/1.11b": "0x5DDC",
        "LoD/1.12a": "0x5EFA",
        "LoD/1.13c": "0x5E4C",
        "LoD/1.13d": "0x5E8A"
      },
      "sizes": {
        "LoD/1.11": 6,
        "LoD/1.11b": 6,
        "LoD/1.12a": 6,
        "LoD/1.13c": 6,
        "LoD/1.13d": 6
      },
      "name": "DecodeHuffmanBitStream",
      "signature": "int DecodeHuffmanBitStream(byte * pOutput, int nMaxOutputBytes, byte * pInput, int nInputBytes)",
      "calling_convention": "__fastcall",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:e3e7225badfcf3c2e051c42d71d7237a",
      "basic_block_counts": {
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.12a": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13c": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13d": "e3e7225badfcf3c2e051c42d71d7237a"
      }
    },
    "d2net.dll_DecodeBitStream": {
      "addresses": {
        "LoD/1.11": "0x6FBF5DFA",
        "LoD/1.11b": "0x6FBF5DFA",
        "LoD/1.12a": "0x6FBF5E34",
        "LoD/1.13c": "0x6FBF5E6A",
        "LoD/1.13d": "0x6FBF5DC4"
      },
      "rvas": {
        "LoD/1.11": "0x5DFA",
        "LoD/1.11b": "0x5DFA",
        "LoD/1.12a": "0x5E34",
        "LoD/1.13c": "0x5E6A",
        "LoD/1.13d": "0x5DC4"
      },
      "sizes": {
        "LoD/1.11": 6,
        "LoD/1.11b": 6,
        "LoD/1.12a": 6,
        "LoD/1.13c": 6,
        "LoD/1.13d": 6
      },
      "name": "DecodeBitStream",
      "signature": "int DecodeBitStream(byte * pOutputBuffer, int outputSize, byte * pInputBuffer, int inputSize)",
      "calling_convention": "__fastcall",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:e3e7225badfcf3c2e051c42d71d7237a",
      "basic_block_counts": {
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.12a": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13c": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13d": "e3e7225badfcf3c2e051c42d71d7237a"
      }
    },
    "d2net.dll_DestroyResourceManager": {
      "addresses": {
        "LoD/1.11": "0x6FBF5E30",
        "LoD/1.11b": "0x6FBF5E30",
        "LoD/1.12a": "0x6FBF5E70",
        "LoD/1.13c": "0x6FBF5EA0",
        "LoD/1.13d": "0x6FBF5E00"
      },
      "rvas": {
        "LoD/1.11": "0x5E30",
        "LoD/1.11b": "0x5E30",
        "LoD/1.12a": "0x5E70",
        "LoD/1.13c": "0x5EA0",
        "LoD/1.13d": "0x5E00"
      },
      "sizes": {
        "LoD/1.11": 6,
        "LoD/1.11b": 6,
        "LoD/1.12a": 6,
        "LoD/1.13c": 6,
        "LoD/1.13d": 6
      },
      "name": "DestroyResourceManager",
      "signature": "int DestroyResourceManager(void * pResourceMgr, void * pDataBuffer, uint dwFlags)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:e3e7225badfcf3c2e051c42d71d7237a",
      "basic_block_counts": {
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.12a": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13c": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13d": "e3e7225badfcf3c2e051c42d71d7237a"
      }
    },
    "d2net.dll_ProcessContextOrSendSocketData": {
      "addresses": {
        "LoD/1.11": "0x6FBF5E7E",
        "LoD/1.11b": "0x6FBF5E7E",
        "LoD/1.12a": "0x6FBF5EC4",
        "LoD/1.13c": "0x6FBF5EEE",
        "LoD/1.13d": "0x6FBF5E54"
      },
      "rvas": {
        "LoD/1.11": "0x5E7E",
        "LoD/1.11b": "0x5E7E",
        "LoD/1.12a": "0x5EC4",
        "LoD/1.13c": "0x5EEE",
        "LoD/1.13d": "0x5E54"
      },
      "sizes": {
        "LoD/1.11": 6,
        "LoD/1.11b": 6,
        "LoD/1.12a": 6,
        "LoD/1.13c": 6,
        "LoD/1.13d": 6
      },
      "name": "ProcessContextOrSendSocketData",
      "signature": "uint ProcessContextOrSendSocketData(void * pContext, uint dwSocketKey, uint dwUnused_param3, uint dwCallbackParam)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:e3e7225badfcf3c2e051c42d71d7237a",
      "basic_block_counts": {
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.11b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.12a": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13c": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.13d": "e3e7225badfcf3c2e051c42d71d7237a"
      }
    },
    "d2net.dll_API_d07023325ff7": {
      "addresses": {
        "LoD/1.11": "0x6FBF5EF0",
        "LoD/1.11b": "0x6FBF5EF0",
        "LoD/1.12a": "0x6FBF7060"
      },
      "rvas": {
        "LoD/1.11": "0x5EF0",
        "LoD/1.11b": "0x5EF0",
        "LoD/1.12a": "0x7060"
      },
      "sizes": {
        "LoD/1.11": 69,
        "LoD/1.11b": 69,
        "LoD/1.12a": 69
      },
      "name_source": "LoD/1.11",
      "method": "API",
      "index": "API:d07023325ff7bdb683c6ce8bdf8d4c8a",
      "callees": {
        "LoD/1.11": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "Ordinal_10175"
        ],
        "LoD/1.11b": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "ProcessQueuedMessage"
        ],
        "LoD/1.12a": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "ProcessQueuedMessage"
        ]
      },
      "basic_block_counts": {
        "LoD/1.11": 3,
        "LoD/1.11b": 3,
        "LoD/1.12a": 3
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "3dcfecb09995650e75420b34977f5cfa",
        "LoD/1.11b": "3dcfecb09995650e75420b34977f5cfa",
        "LoD/1.12a": "3dcfecb09995650e75420b34977f5cfa"
      }
    },
    "d2net.dll_API_d07023325ff7_5F40": {
      "addresses": {
        "LoD/1.11": "0x6FBF5F40",
        "LoD/1.11b": "0x6FBF5F40",
        "LoD/1.12a": "0x6FBF70B0",
        "LoD/1.13c": "0x6FBF5FB0",
        "LoD/1.13d": "0x6FBF7040"
      },
      "rvas": {
        "LoD/1.11": "0x5F40",
        "LoD/1.11b": "0x5F40",
        "LoD/1.12a": "0x70B0",
        "LoD/1.13c": "0x5FB0",
        "LoD/1.13d": "0x7040"
      },
      "sizes": {
        "LoD/1.11": 66,
        "LoD/1.11b": 66,
        "LoD/1.12a": 66,
        "LoD/1.13c": 66,
        "LoD/1.13d": 66
      },
      "name_source": "LoD/1.11",
      "method": "API",
      "index": "API:d07023325ff7bdb683c6ce8bdf8d4c8a",
      "callees": {
        "LoD/1.11": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "Ordinal_10175"
        ],
        "LoD/1.11b": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "ProcessQueuedMessage"
        ],
        "LoD/1.12a": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "ProcessQueuedMessage"
        ],
        "LoD/1.13c": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "ProcessQueuedMessage"
        ],
        "LoD/1.13d": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "ProcessQueuedMessage"
        ]
      },
      "basic_block_counts": {
        "LoD/1.11": 3,
        "LoD/1.11b": 3,
        "LoD/1.12a": 3,
        "LoD/1.13c": 3,
        "LoD/1.13d": 3
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "bb4de8386bd79aba4edc4770370c4e87",
        "LoD/1.11b": "bb4de8386bd79aba4edc4770370c4e87",
        "LoD/1.12a": "bb4de8386bd79aba4edc4770370c4e87",
        "LoD/1.13c": "bb4de8386bd79aba4edc4770370c4e87",
        "LoD/1.13d": "bb4de8386bd79aba4edc4770370c4e87"
      }
    },
    "d2net.dll_EXP_10025": {
      "addresses": {
        "LoD/1.11": "0x6FBF6180",
        "LoD/1.11b": "0x6FBF6180",
        "LoD/1.12a": "0x6FBF69C0"
      },
      "rvas": {
        "LoD/1.11": "0x6180",
        "LoD/1.11b": "0x6180",
        "LoD/1.12a": "0x69C0"
      },
      "sizes": {
        "LoD/1.11": 37,
        "LoD/1.11b": 37,
        "LoD/1.12a": 70
      },
      "name": "Ordinal_10025",
      "signature": "undefined Ordinal_10025(void)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.11",
      "method": "EXP",
      "index": "EXP:10025",
      "callees": {
        "LoD/1.11": [
          "DestroyResourceManager"
        ],
        "LoD/1.11b": [
          "DestroyResourceManager"
        ],
        "LoD/1.12a": [
          "LeaveCriticalSectionValidated"
        ]
      },
      "basic_block_counts": {
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 6
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "3ba034ae7bacc34fe4ac8a696be0ebb6",
        "LoD/1.11b": "3ba034ae7bacc34fe4ac8a696be0ebb6",
        "LoD/1.12a": "d05edcc804dae275b2a6d5f760a5f40f"
      }
    },
    "d2net.dll_MNE_fbbb238d9720": {
      "addresses": {
        "LoD/1.11": "0x6FBF6260",
        "LoD/1.11b": "0x6FBF6260",
        "LoD/1.12a": "0x6FBF73D0",
        "LoD/1.13c": "0x6FBF62D0",
        "LoD/1.13d": "0x6FBF7360"
      },
      "rvas": {
        "LoD/1.11": "0x6260",
        "LoD/1.11b": "0x6260",
        "LoD/1.12a": "0x73D0",
        "LoD/1.13c": "0x62D0",
        "LoD/1.13d": "0x7360"
      },
      "sizes": {
        "LoD/1.11": 35,
        "LoD/1.11b": 35,
        "LoD/1.12a": 35,
        "LoD/1.13c": 35,
        "LoD/1.13d": 35
      },
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:fbbb238d972093d0dac52d52d2b43392",
      "callees": {
        "LoD/1.11": [
          "Ordinal_10175"
        ],
        "LoD/1.11b": [
          "ProcessQueuedMessage"
        ],
        "LoD/1.12a": [
          "ProcessQueuedMessage"
        ],
        "LoD/1.13c": [
          "ProcessQueuedMessage"
        ],
        "LoD/1.13d": [
          "ProcessQueuedMessage"
        ]
      },
      "basic_block_counts": {
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "fbbb238d972093d0dac52d52d2b43392",
        "LoD/1.11b": "fbbb238d972093d0dac52d52d2b43392",
        "LoD/1.12a": "fbbb238d972093d0dac52d52d2b43392",
        "LoD/1.13c": "fbbb238d972093d0dac52d52d2b43392",
        "LoD/1.13d": "fbbb238d972093d0dac52d52d2b43392"
      }
    },
    "d2net.dll_MNE_884dbbd8f21f": {
      "addresses": {
        "LoD/1.11": "0x6FBF6290",
        "LoD/1.11b": "0x6FBF6290",
        "LoD/1.12a": "0x6FBF7400",
        "LoD/1.13c": "0x6FBF6300",
        "LoD/1.13d": "0x6FBF7390"
      },
      "rvas": {
        "LoD/1.11": "0x6290",
        "LoD/1.11b": "0x6290",
        "LoD/1.12a": "0x7400",
        "LoD/1.13c": "0x6300",
        "LoD/1.13d": "0x7390"
      },
      "sizes": {
        "LoD/1.11": 192,
        "LoD/1.11b": 192,
        "LoD/1.12a": 192,
        "LoD/1.13c": 192,
        "LoD/1.13d": 192
      },
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:884dbbd8f21ff1a6c9f6bd445795d9f4",
      "callees": {
        "LoD/1.11": [
          "Ordinal_10010"
        ],
        "LoD/1.11b": [
          "Ordinal_10029"
        ],
        "LoD/1.12a": [
          "Ordinal_10020"
        ],
        "LoD/1.13c": [
          "Ordinal_10006"
        ],
        "LoD/1.13d": [
          "Ordinal_10004"
        ]
      },
      "basic_block_counts": {
        "LoD/1.11": 17,
        "LoD/1.11b": 17,
        "LoD/1.12a": 17,
        "LoD/1.13c": 17,
        "LoD/1.13d": 17
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "884dbbd8f21ff1a6c9f6bd445795d9f4",
        "LoD/1.11b": "884dbbd8f21ff1a6c9f6bd445795d9f4",
        "LoD/1.12a": "884dbbd8f21ff1a6c9f6bd445795d9f4",
        "LoD/1.13c": "884dbbd8f21ff1a6c9f6bd445795d9f4",
        "LoD/1.13d": "884dbbd8f21ff1a6c9f6bd445795d9f4"
      }
    },
    "d2net.dll_EXP_10018": {
      "addresses": {
        "LoD/1.11": "0x6FBF6370",
        "LoD/1.11b": "0x6FBF6370",
        "LoD/1.12a": "0x6FBF74E0",
        "LoD/1.13c": "0x6FBF63E0",
        "LoD/1.13d": "0x6FBF7470"
      },
      "rvas": {
        "LoD/1.11": "0x6370",
        "LoD/1.11b": "0x6370",
        "LoD/1.12a": "0x74E0",
        "LoD/1.13c": "0x63E0",
        "LoD/1.13d": "0x7470"
      },
      "sizes": {
        "LoD/1.11": 350,
        "LoD/1.11b": 350,
        "LoD/1.12a": 350,
        "LoD/1.13c": 350,
        "LoD/1.13d": 350
      },
      "name": "Ordinal_10018",
      "signature": "uint Ordinal_10018(char param_1, uint param_2, byte * param_3, uint param_4)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.11",
      "method": "EXP",
      "index": "EXP:10018",
      "callees": {
        "LoD/1.11": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "UpdateHuffmanTreeStatistics",
          "DecodeBitStream",
          "GetReturnAddress",
          "CleanupAndAbort",
          "ProcessContextOrSendSocketData",
          "ProcessContextOrSendSocketData",
          "ProcessContextOrSendSocketData"
        ],
        "LoD/1.11b": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "UpdateHuffmanTreeStatistics",
          "DecodeBitStream",
          "GetReturnAddress",
          "CleanupAndAbort",
          "ProcessContextOrSendSocketData",
          "ProcessContextOrSendSocketData",
          "ProcessContextOrSendSocketData"
        ],
        "LoD/1.12a": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "UpdateHuffmanTreeStatistics",
          "DecodeBitStream",
          "GetReturnAddress",
          "CleanupAndAbort",
          "ProcessContextOrSendSocketData",
          "ProcessContextOrSendSocketData",
          "ProcessContextOrSendSocketData"
        ],
        "LoD/1.13c": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "UpdateHuffmanTreeStatistics",
          "DecodeBitStream",
          "GetReturnAddress",
          "CleanupAndAbort",
          "ProcessContextOrSendSocketData",
          "ProcessContextOrSendSocketData",
          "ProcessContextOrSendSocketData"
        ],
        "LoD/1.13d": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "UpdateHuffmanTreeStatistics",
          "DecodeBitStream",
          "GetReturnAddress",
          "CleanupAndAbort",
          "ProcessContextOrSendSocketData",
          "ProcessContextOrSendSocketData",
          "ProcessContextOrSendSocketData"
        ]
      },
      "basic_block_counts": {
        "LoD/1.11": 14,
        "LoD/1.11b": 14,
        "LoD/1.12a": 14,
        "LoD/1.13c": 14,
        "LoD/1.13d": 14
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "c4afbe1b98aecac98c7ee729aedb1968",
        "LoD/1.11b": "c4afbe1b98aecac98c7ee729aedb1968",
        "LoD/1.12a": "c4afbe1b98aecac98c7ee729aedb1968",
        "LoD/1.13c": "c4afbe1b98aecac98c7ee729aedb1968",
        "LoD/1.13d": "c4afbe1b98aecac98c7ee729aedb1968"
      }
    },
    "d2net.dll_MNE_16ed5cfb2c6f": {
      "addresses": {
        "LoD/1.11": "0x6FBF64F0",
        "LoD/1.11b": "0x6FBF64F0",
        "LoD/1.12a": "0x6FBF7660",
        "LoD/1.13c": "0x6FBF6560",
        "LoD/1.13d": "0x6FBF75F0"
      },
      "rvas": {
        "LoD/1.11": "0x64F0",
        "LoD/1.11b": "0x64F0",
        "LoD/1.12a": "0x7660",
        "LoD/1.13c": "0x6560",
        "LoD/1.13d": "0x75F0"
      },
      "sizes": {
        "LoD/1.11": 35,
        "LoD/1.11b": 35,
        "LoD/1.12a": 35,
        "LoD/1.13c": 35,
        "LoD/1.13d": 35
      },
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:16ed5cfb2c6f743cb8eeb5ed3f224f68",
      "callees": {
        "LoD/1.11": [
          "Ordinal_10018"
        ],
        "LoD/1.11b": [
          "Ordinal_10018"
        ],
        "LoD/1.12a": [
          "Ordinal_10015"
        ],
        "LoD/1.13c": [
          "Ordinal_10002"
        ],
        "LoD/1.13d": [
          "Ordinal_10012"
        ]
      },
      "basic_block_counts": {
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "16ed5cfb2c6f743cb8eeb5ed3f224f68",
        "LoD/1.11b": "16ed5cfb2c6f743cb8eeb5ed3f224f68",
        "LoD/1.12a": "16ed5cfb2c6f743cb8eeb5ed3f224f68",
        "LoD/1.13c": "16ed5cfb2c6f743cb8eeb5ed3f224f68",
        "LoD/1.13d": "16ed5cfb2c6f743cb8eeb5ed3f224f68"
      }
    },
    "d2net.dll_EXP_10010": {
      "addresses": {
        "LoD/1.11": "0x6FBF6560",
        "LoD/1.11b": "0x6FBF70C0",
        "LoD/1.12a": "0x6FBF5F10",
        "LoD/1.13c": "0x6FBF65D0",
        "LoD/1.13d": "0x6FBF5EA0"
      },
      "rvas": {
        "LoD/1.11": "0x6560",
        "LoD/1.11b": "0x70C0",
        "LoD/1.12a": "0x5F10",
        "LoD/1.13c": "0x65D0",
        "LoD/1.13d": "0x5EA0"
      },
      "sizes": {
        "LoD/1.11": 269,
        "LoD/1.11b": 269,
        "LoD/1.12a": 269,
        "LoD/1.13c": 269,
        "LoD/1.13d": 269
      },
      "name": "Ordinal_10010",
      "signature": "int Ordinal_10010(byte * param_1, uint param_2, int * param_3)",
      "calling_convention": "__fastcall",
      "name_source": "LoD/1.11",
      "method": "EXP",
      "index": "EXP:10010",
      "callees": {
        "LoD/1.11": [
          "CalculateStringLength",
          "CalculateStringLength",
          "CalculateStringLength",
          "CalculateStringLength"
        ],
        "LoD/1.11b": [
          "CalculateStringLength",
          "CalculateStringLength",
          "CalculateStringLength",
          "CalculateStringLength"
        ],
        "LoD/1.12a": [
          "CalculateStringLength",
          "CalculateStringLength",
          "CalculateStringLength",
          "CalculateStringLength"
        ],
        "LoD/1.13c": [
          "CalculateStringLength",
          "CalculateStringLength",
          "CalculateStringLength",
          "CalculateStringLength"
        ],
        "LoD/1.13d": [
          "CalculateStringLength",
          "CalculateStringLength",
          "CalculateStringLength",
          "CalculateStringLength"
        ]
      },
      "basic_block_counts": {
        "LoD/1.11": 25,
        "LoD/1.11b": 25,
        "LoD/1.12a": 25,
        "LoD/1.13c": 25,
        "LoD/1.13d": 25
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "c7663e12b252fe52709e92490cb226d4",
        "LoD/1.11b": "c7663e12b252fe52709e92490cb226d4",
        "LoD/1.12a": "c7663e12b252fe52709e92490cb226d4",
        "LoD/1.13c": "c7663e12b252fe52709e92490cb226d4",
        "LoD/1.13d": "c7663e12b252fe52709e92490cb226d4"
      }
    },
    "d2net.dll_EXP_10014": {
      "addresses": {
        "LoD/1.11": "0x6FBF66E0",
        "LoD/1.11b": "0x6FBF7240",
        "LoD/1.12a": "0x6FBF6090",
        "LoD/1.13c": "0x6FBF6750",
        "LoD/1.13d": "0x6FBF6020"
      },
      "rvas": {
        "LoD/1.11": "0x66E0",
        "LoD/1.11b": "0x7240",
        "LoD/1.12a": "0x6090",
        "LoD/1.13c": "0x6750",
        "LoD/1.13d": "0x6020"
      },
      "sizes": {
        "LoD/1.11": 481,
        "LoD/1.11b": 481,
        "LoD/1.12a": 481,
        "LoD/1.13c": 481,
        "LoD/1.13d": 481
      },
      "name": "Ordinal_10014",
      "signature": "uint Ordinal_10014(byte * param_1, uint param_2, uint * param_3)",
      "calling_convention": "__fastcall",
      "name_source": "LoD/1.11",
      "method": "EXP",
      "index": "EXP:10014",
      "callees": {
        "LoD/1.11": [
          "CalculateStringLength",
          "CalculateStringLength",
          "CalculateStringLength"
        ],
        "LoD/1.11b": [
          "CalculateStringLength",
          "CalculateStringLength",
          "CalculateStringLength"
        ],
        "LoD/1.12a": [
          "CalculateStringLength",
          "CalculateStringLength",
          "CalculateStringLength"
        ],
        "LoD/1.13c": [
          "CalculateStringLength",
          "CalculateStringLength",
          "CalculateStringLength"
        ],
        "LoD/1.13d": [
          "CalculateStringLength",
          "CalculateStringLength",
          "CalculateStringLength"
        ]
      },
      "basic_block_counts": {
        "LoD/1.11": 46,
        "LoD/1.11b": 46,
        "LoD/1.12a": 46,
        "LoD/1.13c": 46,
        "LoD/1.13d": 46
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "6e8ab7d0a75fd3e1b283a5529d87fbe1",
        "LoD/1.11b": "6e8ab7d0a75fd3e1b283a5529d87fbe1",
        "LoD/1.12a": "6e8ab7d0a75fd3e1b283a5529d87fbe1",
        "LoD/1.13c": "6e8ab7d0a75fd3e1b283a5529d87fbe1",
        "LoD/1.13d": "6e8ab7d0a75fd3e1b283a5529d87fbe1"
      }
    },
    "d2net.dll_WSAGetLastError_69A0": {
      "addresses": {
        "LoD/1.11": "0x6FBF69A0",
        "LoD/1.11b": "0x6FBF7500",
        "LoD/1.12a": "0x6FBF6350",
        "LoD/1.13c": "0x6FBF6A10",
        "LoD/1.13d": "0x6FBF62E0"
      },
      "rvas": {
        "LoD/1.11": "0x69A0",
        "LoD/1.11b": "0x7500",
        "LoD/1.12a": "0x6350",
        "LoD/1.13c": "0x6A10",
        "LoD/1.13d": "0x62E0"
      },
      "sizes": {
        "LoD/1.11": 5,
        "LoD/1.11b": 5,
        "LoD/1.12a": 5,
        "LoD/1.13c": 5,
        "LoD/1.13d": 5
      },
      "name": "WSAGetLastError",
      "signature": "int WSAGetLastError(void)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:fdad073544ac1586678f808b3470f76a",
      "basic_block_counts": {
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "fdad073544ac1586678f808b3470f76a",
        "LoD/1.11b": "fdad073544ac1586678f808b3470f76a",
        "LoD/1.12a": "fdad073544ac1586678f808b3470f76a",
        "LoD/1.13c": "fdad073544ac1586678f808b3470f76a",
        "LoD/1.13d": "fdad073544ac1586678f808b3470f76a"
      }
    },
    "d2net.dll_API_280c5ccb3854": {
      "addresses": {
        "LoD/1.11": "0x6FBF69B0",
        "LoD/1.11b": "0x6FBF7510",
        "LoD/1.12a": "0x6FBF6360",
        "LoD/1.13c": "0x6FBF6A20",
        "LoD/1.13d": "0x6FBF62F0"
      },
      "rvas": {
        "LoD/1.11": "0x69B0",
        "LoD/1.11b": "0x7510",
        "LoD/1.12a": "0x6360",
        "LoD/1.13c": "0x6A20",
        "LoD/1.13d": "0x62F0"
      },
      "sizes": {
        "LoD/1.11": 59,
        "LoD/1.11b": 59,
        "LoD/1.12a": 59,
        "LoD/1.13c": 59,
        "LoD/1.13d": 59
      },
      "name_source": "LoD/1.11",
      "method": "API",
      "index": "API:280c5ccb38544306d6fa10abe09016fc",
      "callees": {
        "LoD/1.11": [
          "LeaveCriticalSectionValidated",
          "InitializeModule"
        ],
        "LoD/1.11b": [
          "LeaveCriticalSectionValidated",
          "InitializeModule"
        ],
        "LoD/1.12a": [
          "LeaveCriticalSectionValidated",
          "InitializeModule"
        ],
        "LoD/1.13c": [
          "LeaveCriticalSectionValidated",
          "InitializeModule"
        ],
        "LoD/1.13d": [
          "LeaveCriticalSectionValidated",
          "InitializeModule"
        ]
      },
      "strings": {
        "LoD/1.11": [
          "\"..\\\\Source\\\\D2Net\\\\SRC\\\\D2Net.cpp\""
        ],
        "LoD/1.11b": [
          "\"..\\\\Source\\\\D2Net\\\\SRC\\\\D2Net.cpp\""
        ],
        "LoD/1.12a": [
          "\"..\\\\Source\\\\D2Net\\\\SRC\\\\D2Net.cpp\""
        ],
        "LoD/1.13c": [
          "\"..\\\\Source\\\\D2Net\\\\SRC\\\\D2Net.cpp\""
        ],
        "LoD/1.13d": [
          "\"..\\\\Source\\\\D2Net\\\\SRC\\\\D2Net.cpp\""
        ]
      },
      "basic_block_counts": {
        "LoD/1.11": 3,
        "LoD/1.11b": 3,
        "LoD/1.12a": 3,
        "LoD/1.13c": 3,
        "LoD/1.13d": 3
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "3dd950078561e6c1f7a9e79135851d9d",
        "LoD/1.11b": "3dd950078561e6c1f7a9e79135851d9d",
        "LoD/1.12a": "3dd950078561e6c1f7a9e79135851d9d",
        "LoD/1.13c": "3dd950078561e6c1f7a9e79135851d9d",
        "LoD/1.13d": "3dd950078561e6c1f7a9e79135851d9d"
      }
    },
    "d2net.dll_MNE_e14f1e43ced5": {
      "addresses": {
        "LoD/1.11": "0x6FBF6A00",
        "LoD/1.11b": "0x6FBF7560",
        "LoD/1.12a": "0x6FBF63B0",
        "LoD/1.13c": "0x6FBF6A70",
        "LoD/1.13d": "0x6FBF6340"
      },
      "rvas": {
        "LoD/1.11": "0x6A00",
        "LoD/1.11b": "0x7560",
        "LoD/1.12a": "0x63B0",
        "LoD/1.13c": "0x6A70",
        "LoD/1.13d": "0x6340"
      },
      "sizes": {
        "LoD/1.11": 15,
        "LoD/1.11b": 15,
        "LoD/1.12a": 15,
        "LoD/1.13c": 15,
        "LoD/1.13d": 15
      },
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:e14f1e43ced536cd99c794f95eedbaf1",
      "basic_block_counts": {
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "e14f1e43ced536cd99c794f95eedbaf1",
        "LoD/1.11b": "e14f1e43ced536cd99c794f95eedbaf1",
        "LoD/1.12a": "e14f1e43ced536cd99c794f95eedbaf1",
        "LoD/1.13c": "e14f1e43ced536cd99c794f95eedbaf1",
        "LoD/1.13d": "e14f1e43ced536cd99c794f95eedbaf1"
      }
    },
    "d2net.dll_EXP_10017": {
      "addresses": {
        "LoD/1.11": "0x6FBF6B00",
        "LoD/1.11b": "0x6FBF6560",
        "LoD/1.12a": "0x6FBF64B0",
        "LoD/1.13c": "0x6FBF6B70",
        "LoD/1.13d": "0x6FBF6440"
      },
      "rvas": {
        "LoD/1.11": "0x6B00",
        "LoD/1.11b": "0x6560",
        "LoD/1.12a": "0x64B0",
        "LoD/1.13c": "0x6B70",
        "LoD/1.13d": "0x6440"
      },
      "sizes": {
        "LoD/1.11": 81,
        "LoD/1.11b": 81,
        "LoD/1.12a": 81,
        "LoD/1.13c": 81,
        "LoD/1.13d": 81
      },
      "name": "Ordinal_10017",
      "signature": "undefined Ordinal_10017(byte * param_1)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.11",
      "method": "EXP",
      "index": "EXP:10017",
      "callees": {
        "LoD/1.11": [
          "getsockname",
          "inet_ntoa",
          "CopyMemoryAndDetectTerminator"
        ],
        "LoD/1.11b": [
          "getsockname",
          "inet_ntoa",
          "CopyMemoryAndDetectTerminator"
        ],
        "LoD/1.12a": [
          "getsockname",
          "inet_ntoa",
          "CopyMemoryAndDetectTerminator"
        ],
        "LoD/1.13c": [
          "getsockname",
          "inet_ntoa",
          "CopyMemoryAndDetectTerminator"
        ],
        "LoD/1.13d": [
          "getsockname",
          "inet_ntoa",
          "CopyMemoryAndDetectTerminator"
        ]
      },
      "basic_block_counts": {
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "c510b27ae0be4e6eb0852a420e4df6d2",
        "LoD/1.11b": "c510b27ae0be4e6eb0852a420e4df6d2",
        "LoD/1.12a": "c510b27ae0be4e6eb0852a420e4df6d2",
        "LoD/1.13c": "c510b27ae0be4e6eb0852a420e4df6d2",
        "LoD/1.13d": "c510b27ae0be4e6eb0852a420e4df6d2"
      }
    },
    "d2net.dll_API_7e07200c2689": {
      "addresses": {
        "LoD/1.11": "0x6FBF6B60",
        "LoD/1.11b": "0x6FBF66B0",
        "LoD/1.12a": "0x6FBF6510",
        "LoD/1.13c": "0x6FBF6BD0",
        "LoD/1.13d": "0x6FBF64A0"
      },
      "rvas": {
        "LoD/1.11": "0x6B60",
        "LoD/1.11b": "0x66B0",
        "LoD/1.12a": "0x6510",
        "LoD/1.13c": "0x6BD0",
        "LoD/1.13d": "0x64A0"
      },
      "sizes": {
        "LoD/1.11": 318,
        "LoD/1.11b": 318,
        "LoD/1.12a": 318,
        "LoD/1.13c": 318,
        "LoD/1.13d": 318
      },
      "name_source": "LoD/1.11",
      "method": "API",
      "index": "API:7e07200c2689f520f7eece138f92145b",
      "callees": {
        "LoD/1.11": [
          "Ordinal_10042",
          "Ordinal_10014",
          "GetReturnAddress",
          "CleanupAndAbort"
        ],
        "LoD/1.11b": [
          "AllocateMemoryWithTracking",
          "Ordinal_10034",
          "GetReturnAddress",
          "CleanupAndAbort"
        ],
        "LoD/1.12a": [
          "AllocateMemoryWithTracking",
          "Ordinal_10002",
          "GetReturnAddress",
          "CleanupAndAbort"
        ],
        "LoD/1.13c": [
          "AllocateMemoryWithTracking",
          "Ordinal_10033",
          "GetReturnAddress",
          "CleanupAndAbort"
        ],
        "LoD/1.13d": [
          "AllocateMemoryWithTracking",
          "Ordinal_10001",
          "GetReturnAddress",
          "CleanupAndAbort"
        ]
      },
      "strings": {
        "LoD/1.11": [
          "\"..\\\\Source\\\\D2Net\\\\SRC\\\\Client.cpp\""
        ],
        "LoD/1.11b": [
          "\"..\\\\Source\\\\D2Net\\\\SRC\\\\Client.cpp\""
        ],
        "LoD/1.12a": [
          "\"..\\\\Source\\\\D2Net\\\\SRC\\\\Client.cpp\""
        ],
        "LoD/1.13c": [
          "\"..\\\\Source\\\\D2Net\\\\SRC\\\\Client.cpp\""
        ],
        "LoD/1.13d": [
          "\"..\\\\Source\\\\D2Net\\\\SRC\\\\Client.cpp\""
        ]
      },
      "basic_block_counts": {
        "LoD/1.11": 26,
        "LoD/1.11b": 26,
        "LoD/1.12a": 26,
        "LoD/1.13c": 26,
        "LoD/1.13d": 26
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "f501d9e4deaff966856e1b1f92eaff54",
        "LoD/1.11b": "f501d9e4deaff966856e1b1f92eaff54",
        "LoD/1.12a": "f501d9e4deaff966856e1b1f92eaff54",
        "LoD/1.13c": "f501d9e4deaff966856e1b1f92eaff54",
        "LoD/1.13d": "f501d9e4deaff966856e1b1f92eaff54"
      }
    },
    "d2net.dll_API_d7a260ed4aa8": {
      "addresses": {
        "LoD/1.11": "0x6FBF6CF0",
        "LoD/1.11b": "0x6FBF67F0",
        "LoD/1.12a": "0x6FBF6650",
        "LoD/1.13c": "0x6FBF6D60",
        "LoD/1.13d": "0x6FBF65E0"
      },
      "rvas": {
        "LoD/1.11": "0x6CF0",
        "LoD/1.11b": "0x67F0",
        "LoD/1.12a": "0x6650",
        "LoD/1.13c": "0x6D60",
        "LoD/1.13d": "0x65E0"
      },
      "sizes": {
        "LoD/1.11": 396,
        "LoD/1.11b": 396,
        "LoD/1.12a": 396,
        "LoD/1.13c": 396,
        "LoD/1.13d": 396
      },
      "name_source": "LoD/1.11",
      "method": "API",
      "index": "API:d7a260ed4aa87cbe584683f315b37054",
      "callees": {
        "LoD/1.11": [
          "Ordinal_10014",
          "Ordinal_10042",
          "BuildPKWareHuffmanDecodeTables",
          "GetReturnAddress",
          "CleanupAndAbort"
        ],
        "LoD/1.11b": [
          "Ordinal_10034",
          "AllocateMemoryWithTracking",
          "BuildPKWareHuffmanDecodeTables",
          "GetReturnAddress",
          "CleanupAndAbort"
        ],
        "LoD/1.12a": [
          "Ordinal_10002",
          "AllocateMemoryWithTracking",
          "BuildPKWareHuffmanDecodeTables",
          "GetReturnAddress",
          "CleanupAndAbort"
        ],
        "LoD/1.13c": [
          "Ordinal_10033",
          "AllocateMemoryWithTracking",
          "BuildPKWareHuffmanDecodeTables",
          "GetReturnAddress",
          "CleanupAndAbort"
        ],
        "LoD/1.13d": [
          "Ordinal_10001",
          "AllocateMemoryWithTracking",
          "BuildPKWareHuffmanDecodeTables",
          "GetReturnAddress",
          "CleanupAndAbort"
        ]
      },
      "strings": {
        "LoD/1.11": [
          "\"..\\\\Source\\\\D2Net\\\\SRC\\\\Client.cpp\""
        ],
        "LoD/1.11b": [
          "\"..\\\\Source\\\\D2Net\\\\SRC\\\\Client.cpp\""
        ],
        "LoD/1.12a": [
          "\"..\\\\Source\\\\D2Net\\\\SRC\\\\Client.cpp\""
        ],
        "LoD/1.13c": [
          "\"..\\\\Source\\\\D2Net\\\\SRC\\\\Client.cpp\""
        ],
        "LoD/1.13d": [
          "\"..\\\\Source\\\\D2Net\\\\SRC\\\\Client.cpp\""
        ]
      },
      "basic_block_counts": {
        "LoD/1.11": 23,
        "LoD/1.11b": 23,
        "LoD/1.12a": 23,
        "LoD/1.13c": 23,
        "LoD/1.13d": 23
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "92c32b888dc4a1f9d209d88321e1b2cf",
        "LoD/1.11b": "92c32b888dc4a1f9d209d88321e1b2cf",
        "LoD/1.12a": "92c32b888dc4a1f9d209d88321e1b2cf",
        "LoD/1.13c": "92c32b888dc4a1f9d209d88321e1b2cf",
        "LoD/1.13d": "92c32b888dc4a1f9d209d88321e1b2cf"
      }
    },
    "d2net.dll_EXP_10012": {
      "addresses": {
        "LoD/1.11": "0x6FBF6E80",
        "LoD/1.11b": "0x6FBF6980",
        "LoD/1.12a": "0x6FBF67E0",
        "LoD/1.13c": "0x6FBF6EF0",
        "LoD/1.13d": "0x6FBF6770"
      },
      "rvas": {
        "LoD/1.11": "0x6E80",
        "LoD/1.11b": "0x6980",
        "LoD/1.12a": "0x67E0",
        "LoD/1.13c": "0x6EF0",
        "LoD/1.13d": "0x6770"
      },
      "sizes": {
        "LoD/1.11": 304,
        "LoD/1.11b": 304,
        "LoD/1.12a": 304,
        "LoD/1.13c": 304,
        "LoD/1.13d": 304
      },
      "name": "Ordinal_10012",
      "signature": "undefined Ordinal_10012(void)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.11",
      "method": "EXP",
      "index": "EXP:10012",
      "callees": {
        "LoD/1.11": [
          "LeaveCriticalSectionValidated",
          "InitializeModule",
          "LeaveCriticalSectionValidated",
          "InitializeModule",
          "LeaveCriticalSectionValidated",
          "InitializeModule",
          "LeaveCriticalSectionValidated",
          "BuildProjectPathThunk",
          "WSAGetLastError"
        ],
        "LoD/1.11b": [
          "LeaveCriticalSectionValidated",
          "InitializeModule",
          "LeaveCriticalSectionValidated",
          "InitializeModule",
          "LeaveCriticalSectionValidated",
          "InitializeModule",
          "LeaveCriticalSectionValidated",
          "BuildProjectPathThunk",
          "WSAGetLastError"
        ],
        "LoD/1.12a": [
          "LeaveCriticalSectionValidated",
          "InitializeModule",
          "LeaveCriticalSectionValidated",
          "InitializeModule",
          "LeaveCriticalSectionValidated",
          "InitializeModule",
          "LeaveCriticalSectionValidated",
          "BuildProjectPathThunk",
          "WSAGetLastError"
        ],
        "LoD/1.13c": [
          "LeaveCriticalSectionValidated",
          "InitializeModule",
          "LeaveCriticalSectionValidated",
          "InitializeModule",
          "LeaveCriticalSectionValidated",
          "InitializeModule",
          "LeaveCriticalSectionValidated",
          "BuildProjectPathThunk",
          "WSAGetLastError"
        ],
        "LoD/1.13d": [
          "LeaveCriticalSectionValidated",
          "InitializeModule",
          "LeaveCriticalSectionValidated",
          "InitializeModule",
          "LeaveCriticalSectionValidated",
          "InitializeModule",
          "LeaveCriticalSectionValidated",
          "BuildProjectPathThunk",
          "WSAGetLastError"
        ]
      },
      "strings": {
        "LoD/1.11": [
          "\"..\\\\Source\\\\D2Net\\\\SRC\\\\D2Net.cpp\"",
          "\"..\\\\Source\\\\D2Net\\\\SRC\\\\Client.cpp\""
        ],
        "LoD/1.11b": [
          "\"..\\\\Source\\\\D2Net\\\\SRC\\\\D2Net.cpp\"",
          "\"..\\\\Source\\\\D2Net\\\\SRC\\\\Client.cpp\""
        ],
        "LoD/1.12a": [
          "\"..\\\\Source\\\\D2Net\\\\SRC\\\\D2Net.cpp\"",
          "\"..\\\\Source\\\\D2Net\\\\SRC\\\\Client.cpp\""
        ],
        "LoD/1.13c": [
          "\"..\\\\Source\\\\D2Net\\\\SRC\\\\D2Net.cpp\"",
          "\"..\\\\Source\\\\D2Net\\\\SRC\\\\Client.cpp\""
        ],
        "LoD/1.13d": [
          "\"..\\\\Source\\\\D2Net\\\\SRC\\\\D2Net.cpp\"",
          "\"..\\\\Source\\\\D2Net\\\\SRC\\\\Client.cpp\""
        ]
      },
      "basic_block_counts": {
        "LoD/1.11": 12,
        "LoD/1.11b": 12,
        "LoD/1.12a": 12,
        "LoD/1.13c": 12,
        "LoD/1.13d": 12
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "a062bd2c4926e7572afb2a64c6efac67",
        "LoD/1.11b": "a062bd2c4926e7572afb2a64c6efac67",
        "LoD/1.12a": "a062bd2c4926e7572afb2a64c6efac67",
        "LoD/1.13c": "a062bd2c4926e7572afb2a64c6efac67",
        "LoD/1.13d": "a062bd2c4926e7572afb2a64c6efac67"
      }
    },
    "d2net.dll_API_41b67e20c803": {
      "addresses": {
        "LoD/1.11": "0x6FBF6FC0",
        "LoD/1.11b": "0x6FBF6610",
        "LoD/1.12a": "0x6FBF6920",
        "LoD/1.13c": "0x6FBF7030",
        "LoD/1.13d": "0x6FBF68B0"
      },
      "rvas": {
        "LoD/1.11": "0x6FC0",
        "LoD/1.11b": "0x6610",
        "LoD/1.12a": "0x6920",
        "LoD/1.13c": "0x7030",
        "LoD/1.13d": "0x68B0"
      },
      "sizes": {
        "LoD/1.11": 160,
        "LoD/1.11b": 160,
        "LoD/1.12a": 160,
        "LoD/1.13c": 160,
        "LoD/1.13d": 160
      },
      "name_source": "LoD/1.11",
      "method": "API",
      "index": "API:41b67e20c803a97006b857007d8fa68b",
      "callees": {
        "LoD/1.11": [
          "WSAStartup",
          "socket",
          "WSAGetLastError",
          "htons",
          "ResolveNetworkAddress",
          "inet_addr",
          "connect"
        ],
        "LoD/1.11b": [
          "WSAStartup",
          "socket",
          "WSAGetLastError",
          "htons",
          "ResolveNetworkAddress",
          "inet_addr",
          "connect"
        ],
        "LoD/1.12a": [
          "WSAStartup",
          "socket",
          "WSAGetLastError",
          "htons",
          "ResolveNetworkAddress",
          "inet_addr",
          "connect"
        ],
        "LoD/1.13c": [
          "WSAStartup",
          "socket",
          "WSAGetLastError",
          "htons",
          "ResolveNetworkAddress",
          "inet_addr",
          "connect"
        ],
        "LoD/1.13d": [
          "WSAStartup",
          "socket",
          "WSAGetLastError",
          "htons",
          "ResolveNetworkAddress",
          "inet_addr",
          "connect"
        ]
      },
      "basic_block_counts": {
        "LoD/1.11": 5,
        "LoD/1.11b": 5,
        "LoD/1.12a": 5,
        "LoD/1.13c": 5,
        "LoD/1.13d": 5
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "f9e1d13e6e11ceadda277bcef6971744",
        "LoD/1.11b": "f9e1d13e6e11ceadda277bcef6971744",
        "LoD/1.12a": "f9e1d13e6e11ceadda277bcef6971744",
        "LoD/1.13c": "f9e1d13e6e11ceadda277bcef6971744",
        "LoD/1.13d": "f9e1d13e6e11ceadda277bcef6971744"
      }
    },
    "d2net.dll_EXP_10013": {
      "addresses": {
        "LoD/1.11": "0x6FBF7060",
        "LoD/1.11b": "0x6FBF6AE0",
        "LoD/1.12a": "0x6FBF6F20",
        "LoD/1.13c": "0x6FBF70D0",
        "LoD/1.13d": "0x6FBF6950"
      },
      "rvas": {
        "LoD/1.11": "0x7060",
        "LoD/1.11b": "0x6AE0",
        "LoD/1.12a": "0x6F20",
        "LoD/1.13c": "0x70D0",
        "LoD/1.13d": "0x6950"
      },
      "sizes": {
        "LoD/1.11": 70,
        "LoD/1.11b": 70,
        "LoD/1.12a": 102,
        "LoD/1.13c": 70,
        "LoD/1.13d": 70
      },
      "name": "Ordinal_10013",
      "signature": "undefined4 Ordinal_10013(void)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.11",
      "method": "EXP",
      "index": "EXP:10013",
      "callees": {
        "LoD/1.11": [
          "LeaveCriticalSectionValidated"
        ],
        "LoD/1.11b": [
          "LeaveCriticalSectionValidated"
        ],
        "LoD/1.13c": [
          "LeaveCriticalSectionValidated"
        ],
        "LoD/1.13d": [
          "LeaveCriticalSectionValidated"
        ]
      },
      "basic_block_counts": {
        "LoD/1.11": 6,
        "LoD/1.11b": 6,
        "LoD/1.12a": 8,
        "LoD/1.13c": 6,
        "LoD/1.13d": 6
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "d05edcc804dae275b2a6d5f760a5f40f",
        "LoD/1.11b": "d05edcc804dae275b2a6d5f760a5f40f",
        "LoD/1.12a": "e89903eba0c99afbd11fe0ee13c592bf",
        "LoD/1.13c": "d05edcc804dae275b2a6d5f760a5f40f",
        "LoD/1.13d": "d05edcc804dae275b2a6d5f760a5f40f"
      }
    },
    "d2net.dll_MNE_b3cd84a86949": {
      "addresses": {
        "LoD/1.11": "0x6FBF70B0",
        "LoD/1.11b": "0x6FBF6B30",
        "LoD/1.12a": "0x6FBF6A10",
        "LoD/1.13c": "0x6FBF7120",
        "LoD/1.13d": "0x6FBF69A0"
      },
      "rvas": {
        "LoD/1.11": "0x70B0",
        "LoD/1.11b": "0x6B30",
        "LoD/1.12a": "0x6A10",
        "LoD/1.13c": "0x7120",
        "LoD/1.13d": "0x69A0"
      },
      "sizes": {
        "LoD/1.11": 56,
        "LoD/1.11b": 56,
        "LoD/1.12a": 56,
        "LoD/1.13c": 56,
        "LoD/1.13d": 56
      },
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:b3cd84a8694934f99edcb073eba88994",
      "callees": {
        "LoD/1.11": [
          "LeaveCriticalSectionValidated"
        ],
        "LoD/1.11b": [
          "LeaveCriticalSectionValidated"
        ],
        "LoD/1.12a": [
          "LeaveCriticalSectionValidated"
        ],
        "LoD/1.13c": [
          "LeaveCriticalSectionValidated"
        ],
        "LoD/1.13d": [
          "LeaveCriticalSectionValidated"
        ]
      },
      "basic_block_counts": {
        "LoD/1.11": 4,
        "LoD/1.11b": 4,
        "LoD/1.12a": 4,
        "LoD/1.13c": 4,
        "LoD/1.13d": 4
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "b3cd84a8694934f99edcb073eba88994",
        "LoD/1.11b": "b3cd84a8694934f99edcb073eba88994",
        "LoD/1.12a": "b3cd84a8694934f99edcb073eba88994",
        "LoD/1.13c": "b3cd84a8694934f99edcb073eba88994",
        "LoD/1.13d": "b3cd84a8694934f99edcb073eba88994"
      }
    },
    "d2net.dll_MNE_9b2bb0fa194f": {
      "addresses": {
        "LoD/1.11": "0x6FBF70F0",
        "LoD/1.11b": "0x6FBF6B70",
        "LoD/1.12a": "0x6FBF6AA0",
        "LoD/1.13c": "0x6FBF7160",
        "LoD/1.13d": "0x6FBF6A30"
      },
      "rvas": {
        "LoD/1.11": "0x70F0",
        "LoD/1.11b": "0x6B70",
        "LoD/1.12a": "0x6AA0",
        "LoD/1.13c": "0x7160",
        "LoD/1.13d": "0x6A30"
      },
      "sizes": {
        "LoD/1.11": 52,
        "LoD/1.11b": 52,
        "LoD/1.12a": 52,
        "LoD/1.13c": 52,
        "LoD/1.13d": 52
      },
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:9b2bb0fa194fe6c25163ff45ce7e8f85",
      "callees": {
        "LoD/1.11": [
          "LeaveCriticalSectionValidated"
        ],
        "LoD/1.11b": [
          "LeaveCriticalSectionValidated"
        ],
        "LoD/1.12a": [
          "LeaveCriticalSectionValidated"
        ],
        "LoD/1.13c": [
          "LeaveCriticalSectionValidated"
        ],
        "LoD/1.13d": [
          "LeaveCriticalSectionValidated"
        ]
      },
      "basic_block_counts": {
        "LoD/1.11": 4,
        "LoD/1.11b": 4,
        "LoD/1.12a": 4,
        "LoD/1.13c": 4,
        "LoD/1.13d": 4
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "9b2bb0fa194fe6c25163ff45ce7e8f85",
        "LoD/1.11b": "9b2bb0fa194fe6c25163ff45ce7e8f85",
        "LoD/1.12a": "9b2bb0fa194fe6c25163ff45ce7e8f85",
        "LoD/1.13c": "9b2bb0fa194fe6c25163ff45ce7e8f85",
        "LoD/1.13d": "9b2bb0fa194fe6c25163ff45ce7e8f85"
      }
    },
    "d2net.dll_API_cf2bb0c5f051": {
      "addresses": {
        "LoD/1.11": "0x6FBF7130",
        "LoD/1.11b": "0x6FBF6BB0",
        "LoD/1.12a": "0x6FBF6AE0",
        "LoD/1.13c": "0x6FBF71A0",
        "LoD/1.13d": "0x6FBF6A70"
      },
      "rvas": {
        "LoD/1.11": "0x7130",
        "LoD/1.11b": "0x6BB0",
        "LoD/1.12a": "0x6AE0",
        "LoD/1.13c": "0x71A0",
        "LoD/1.13d": "0x6A70"
      },
      "sizes": {
        "LoD/1.11": 57,
        "LoD/1.11b": 57,
        "LoD/1.12a": 57,
        "LoD/1.13c": 57,
        "LoD/1.13d": 57
      },
      "name_source": "LoD/1.11",
      "method": "API",
      "index": "API:cf2bb0c5f0518bba7e02d6f48607024e",
      "callees": {
        "LoD/1.11": [
          "WSAGetLastError",
          "LeaveCriticalSectionValidated"
        ],
        "LoD/1.11b": [
          "WSAGetLastError",
          "LeaveCriticalSectionValidated"
        ],
        "LoD/1.12a": [
          "WSAGetLastError",
          "LeaveCriticalSectionValidated"
        ],
        "LoD/1.13c": [
          "WSAGetLastError",
          "LeaveCriticalSectionValidated"
        ],
        "LoD/1.13d": [
          "WSAGetLastError",
          "LeaveCriticalSectionValidated"
        ]
      },
      "basic_block_counts": {
        "LoD/1.11": 4,
        "LoD/1.11b": 4,
        "LoD/1.12a": 4,
        "LoD/1.13c": 4,
        "LoD/1.13d": 4
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "3fa3f558f1be57bcf8375fa73e7aac09",
        "LoD/1.11b": "3fa3f558f1be57bcf8375fa73e7aac09",
        "LoD/1.12a": "3fa3f558f1be57bcf8375fa73e7aac09",
        "LoD/1.13c": "3fa3f558f1be57bcf8375fa73e7aac09",
        "LoD/1.13d": "3fa3f558f1be57bcf8375fa73e7aac09"
      }
    },
    "d2net.dll_EXP_10034": {
      "addresses": {
        "LoD/1.11": "0x6FBF7170",
        "LoD/1.11b": "0x6FBF6BF0",
        "LoD/1.12a": "0x6FBF6B20",
        "LoD/1.13c": "0x6FBF75E0",
        "LoD/1.13d": "0x6FBF6EB0"
      },
      "rvas": {
        "LoD/1.11": "0x7170",
        "LoD/1.11b": "0x6BF0",
        "LoD/1.12a": "0x6B20",
        "LoD/1.13c": "0x75E0",
        "LoD/1.13d": "0x6EB0"
      },
      "sizes": {
        "LoD/1.11": 27,
        "LoD/1.11b": 27,
        "LoD/1.12a": 27,
        "LoD/1.13c": 102,
        "LoD/1.13d": 102
      },
      "name": "Ordinal_10034",
      "signature": "undefined Ordinal_10034(undefined4 * param_1)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.11",
      "method": "EXP",
      "index": "EXP:10034",
      "basic_block_counts": {
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 8,
        "LoD/1.13d": 8
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "50efb6c37a868379ce8439bd65fe6d05",
        "LoD/1.11b": "50efb6c37a868379ce8439bd65fe6d05",
        "LoD/1.12a": "50efb6c37a868379ce8439bd65fe6d05",
        "LoD/1.13c": "e89903eba0c99afbd11fe0ee13c592bf",
        "LoD/1.13d": "e89903eba0c99afbd11fe0ee13c592bf"
      }
    },
    "d2net.dll_EXP_10028": {
      "addresses": {
        "LoD/1.11": "0x6FBF7190",
        "LoD/1.11b": "0x6FBF6C10",
        "LoD/1.12a": "0x6FBF6B40",
        "LoD/1.13c": "0x6FBF7200",
        "LoD/1.13d": "0x6FBF6AD0"
      },
      "rvas": {
        "LoD/1.11": "0x7190",
        "LoD/1.11b": "0x6C10",
        "LoD/1.12a": "0x6B40",
        "LoD/1.13c": "0x7200",
        "LoD/1.13d": "0x6AD0"
      },
      "sizes": {
        "LoD/1.11": 27,
        "LoD/1.11b": 27,
        "LoD/1.12a": 27,
        "LoD/1.13c": 27,
        "LoD/1.13d": 27
      },
      "name": "Ordinal_10028",
      "signature": "undefined Ordinal_10028(undefined4 * param_1)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.11",
      "method": "EXP",
      "index": "EXP:10028",
      "basic_block_counts": {
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "50efb6c37a868379ce8439bd65fe6d05",
        "LoD/1.11b": "50efb6c37a868379ce8439bd65fe6d05",
        "LoD/1.12a": "50efb6c37a868379ce8439bd65fe6d05",
        "LoD/1.13c": "50efb6c37a868379ce8439bd65fe6d05",
        "LoD/1.13d": "50efb6c37a868379ce8439bd65fe6d05"
      }
    },
    "d2net.dll_MNE_cc306ba4c62f": {
      "addresses": {
        "LoD/1.11": "0x6FBF71B0",
        "LoD/1.11b": "0x6FBF6AC0",
        "LoD/1.12a": "0x6FBF6B60",
        "LoD/1.13c": "0x6FBF7220",
        "LoD/1.13d": "0x6FBF6AF0"
      },
      "rvas": {
        "LoD/1.11": "0x71B0",
        "LoD/1.11b": "0x6AC0",
        "LoD/1.12a": "0x6B60",
        "LoD/1.13c": "0x7220",
        "LoD/1.13d": "0x6AF0"
      },
      "sizes": {
        "LoD/1.11": 29,
        "LoD/1.11b": 29,
        "LoD/1.12a": 29,
        "LoD/1.13c": 29,
        "LoD/1.13d": 29
      },
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:cc306ba4c62f26d026f76037590ec8bf",
      "basic_block_counts": {
        "LoD/1.11": 1,
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "cc306ba4c62f26d026f76037590ec8bf",
        "LoD/1.11b": "cc306ba4c62f26d026f76037590ec8bf",
        "LoD/1.12a": "cc306ba4c62f26d026f76037590ec8bf",
        "LoD/1.13c": "cc306ba4c62f26d026f76037590ec8bf",
        "LoD/1.13d": "cc306ba4c62f26d026f76037590ec8bf"
      }
    },
    "d2net.dll_API_2ea6d5d7afa7": {
      "addresses": {
        "LoD/1.11": "0x6FBF71D0",
        "LoD/1.11b": "0x6FBF6C30",
        "LoD/1.12a": "0x6FBF6B80",
        "LoD/1.13c": "0x6FBF7240",
        "LoD/1.13d": "0x6FBF6B10"
      },
      "rvas": {
        "LoD/1.11": "0x71D0",
        "LoD/1.11b": "0x6C30",
        "LoD/1.12a": "0x6B80",
        "LoD/1.13c": "0x7240",
        "LoD/1.13d": "0x6B10"
      },
      "sizes": {
        "LoD/1.11": 80,
        "LoD/1.11b": 80,
        "LoD/1.12a": 80,
        "LoD/1.13c": 80,
        "LoD/1.13d": 80
      },
      "name_source": "LoD/1.11",
      "method": "API",
      "index": "API:2ea6d5d7afa7a00dfba501708d4a0eb7",
      "callees": {
        "LoD/1.11": [
          "send",
          "WSAGetLastError",
          "LeaveCriticalSectionValidated"
        ],
        "LoD/1.11b": [
          "send",
          "WSAGetLastError",
          "LeaveCriticalSectionValidated"
        ],
        "LoD/1.12a": [
          "send",
          "WSAGetLastError",
          "LeaveCriticalSectionValidated"
        ],
        "LoD/1.13c": [
          "send",
          "WSAGetLastError",
          "LeaveCriticalSectionValidated"
        ],
        "LoD/1.13d": [
          "send",
          "WSAGetLastError",
          "LeaveCriticalSectionValidated"
        ]
      },
      "basic_block_counts": {
        "LoD/1.11": 6,
        "LoD/1.11b": 6,
        "LoD/1.12a": 6,
        "LoD/1.13c": 6,
        "LoD/1.13d": 6
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "68fd61bdb2e3f1f75070911f9c9f8717",
        "LoD/1.11b": "68fd61bdb2e3f1f75070911f9c9f8717",
        "LoD/1.12a": "68fd61bdb2e3f1f75070911f9c9f8717",
        "LoD/1.13c": "68fd61bdb2e3f1f75070911f9c9f8717",
        "LoD/1.13d": "68fd61bdb2e3f1f75070911f9c9f8717"
      }
    },
    "d2net.dll_EXP_10036": {
      "addresses": {
        "LoD/1.11": "0x6FBF7570",
        "LoD/1.11b": "0x6FBF6FD0"
      },
      "rvas": {
        "LoD/1.11": "0x7570",
        "LoD/1.11b": "0x6FD0"
      },
      "sizes": {
        "LoD/1.11": 102,
        "LoD/1.11b": 102
      },
      "name": "Ordinal_10036",
      "signature": "undefined4 Ordinal_10036(void)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.11",
      "method": "EXP",
      "index": "EXP:10036",
      "basic_block_counts": {
        "LoD/1.11": 8,
        "LoD/1.11b": 8
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "e89903eba0c99afbd11fe0ee13c592bf",
        "LoD/1.11b": "e89903eba0c99afbd11fe0ee13c592bf"
      }
    },
    "d2net.dll_EXP_10035": {
      "addresses": {
        "LoD/1.11": "0x6FBF75E0",
        "LoD/1.11b": "0x6FBF7040",
        "LoD/1.12a": "0x6FBF6F90",
        "LoD/1.13c": "0x6FBF7650",
        "LoD/1.13d": "0x6FBF6F20"
      },
      "rvas": {
        "LoD/1.11": "0x75E0",
        "LoD/1.11b": "0x7040",
        "LoD/1.12a": "0x6F90",
        "LoD/1.13c": "0x7650",
        "LoD/1.13d": "0x6F20"
      },
      "sizes": {
        "LoD/1.11": 118,
        "LoD/1.11b": 118,
        "LoD/1.12a": 118,
        "LoD/1.13c": 118,
        "LoD/1.13d": 118
      },
      "name": "Ordinal_10035",
      "signature": "uint Ordinal_10035(ushort param_1, undefined4 param_2, char * param_3)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.11",
      "method": "EXP",
      "index": "EXP:10035",
      "callees": {
        "LoD/1.11": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "Ordinal_10175"
        ],
        "LoD/1.11b": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "ProcessQueuedMessage"
        ],
        "LoD/1.12a": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "ProcessQueuedMessage"
        ],
        "LoD/1.13c": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "ProcessQueuedMessage"
        ],
        "LoD/1.13d": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "ProcessQueuedMessage"
        ]
      },
      "basic_block_counts": {
        "LoD/1.11": 8,
        "LoD/1.11b": 8,
        "LoD/1.12a": 8,
        "LoD/1.13c": 8,
        "LoD/1.13d": 8
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "abd4d5d0c5faf1315d5b684d261bc4d7",
        "LoD/1.11b": "abd4d5d0c5faf1315d5b684d261bc4d7",
        "LoD/1.12a": "abd4d5d0c5faf1315d5b684d261bc4d7",
        "LoD/1.13c": "abd4d5d0c5faf1315d5b684d261bc4d7",
        "LoD/1.13d": "abd4d5d0c5faf1315d5b684d261bc4d7"
      }
    },
    "d2net.dll_API_fdbfe976ab93": {
      "addresses": {
        "LoD/1.11b": "0x6FBF65C0",
        "LoD/1.12a": "0x6FBF6A50",
        "LoD/1.13c": "0x6FBF5F60",
        "LoD/1.13d": "0x6FBF69E0"
      },
      "rvas": {
        "LoD/1.11b": "0x65C0",
        "LoD/1.12a": "0x6A50",
        "LoD/1.13c": "0x5F60",
        "LoD/1.13d": "0x69E0"
      },
      "sizes": {
        "LoD/1.11b": 69,
        "LoD/1.12a": 69,
        "LoD/1.13c": 69,
        "LoD/1.13d": 69
      },
      "name_source": "LoD/1.11b",
      "method": "API",
      "index": "API:fdbfe976ab936acb4b93de5302ff5358",
      "callees": {
        "LoD/1.11b": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "ProcessQueuedMessage"
        ],
        "LoD/1.12a": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "ProcessQueuedMessage"
        ],
        "LoD/1.13c": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "ProcessQueuedMessage"
        ],
        "LoD/1.13d": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "ProcessQueuedMessage"
        ]
      },
      "basic_block_counts": {
        "LoD/1.11b": 3,
        "LoD/1.12a": 3,
        "LoD/1.13c": 3,
        "LoD/1.13d": 3
      },
      "loop_counts": {
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11b": "3dcfecb09995650e75420b34977f5cfa",
        "LoD/1.12a": "3dcfecb09995650e75420b34977f5cfa",
        "LoD/1.13c": "3dcfecb09995650e75420b34977f5cfa",
        "LoD/1.13d": "3dcfecb09995650e75420b34977f5cfa"
      }
    },
    "d2net.dll_AllocateMemory": {
      "addresses": {
        "LoD/1.12a": "0x6FBF1F69",
        "LoD/1.13c": "0x6FBF1F61"
      },
      "rvas": {
        "LoD/1.12a": "0x1F69",
        "LoD/1.13c": "0x1F61"
      },
      "sizes": {
        "LoD/1.12a": 203,
        "LoD/1.13c": 203
      },
      "name": "AllocateMemory",
      "signature": "int * AllocateMemory(uint dwElementCount, uint dwElementSize)",
      "calling_convention": "__cdecl",
      "comment": "Allocates a zero-initialized memory block for element arrays with automatic retry on failure.\n\nAlgorithm:\n1. Validate parameters: elementCount must be non-zero AND elementSize must be <= 0xffffffe0 / elementCount to prevent integer overflow\n2. Calculate total allocation size by multiplying elementCount * elementSize\n3. If calculated size is zero, set minimum allocation to 1 byte (handles edge case of zero-sized requests)\n4. Enter allocation loop with two strategies based on heap configuration:\n   a. Small Block Heap (SBH) optimization: If g_dwHeapState == 3 AND original size <= g_dwMaxSmallBlockSize:\n      - Align size to 16-byte boundary (size + 0xF AND 0xFFFFFFF0) for SBH alignment requirements\n      - Acquire critical section lock (index 4) for thread-safe SBH access\n      - Call ___sbh_alloc_block with original (unaligned) size to allocate from small block heap\n      - Release critical section lock\n      - If allocation succeeds: Zero-initialize memory with memset and return pointer\n   b. Windows HeapAlloc fallback: Call HeapAlloc with HEAP_ZERO_MEMORY flag (0x8) to allocate from process heap and zero-initialize\n5. Test allocation result: If non-NULL, return allocated pointer immediately\n6. Test out-of-memory handler flag (g_dwLowMemoryFlag): If zero, return NULL (no recovery possible)\n7. Call __callnewh handler to attempt memory recovery (e.g., purge caches, free resources)\n8. If handler returns non-zero, loop back to step 4 to retry allocation; otherwise fall through to failure\n9. Return NULL if allocation fails and handler returns zero (no recovery possible)\n\nParameters:\nelementCount - uint: Number of elements to allocate (multiplied with elementSize to determine total bytes)\nelementSize - uint: Size in bytes of each individual element\n\nReturns:\nint * : Pointer to allocated and zero-initialized memory block on success\n        NULL (0x00000000) if allocation fails persistently or parameters cause integer overflow\n\nSpecial Cases:\n- Zero-size requests: If elementCount * elementSize == 0, minimum 1-byte allocation is attempted\n- Integer overflow protection: DIV instruction at 0x6fbf91b0 compares product against 0xffffffe0 limit to detect overflow\n- SBH optimization: Allocations <= g_dwMaxSmallBlockSize use aligned small block heap for better fragmentation behavior\n- Size alignment: SBH allocations aligned to 16-byte boundary; heap allocations use HEAP_ZERO_MEMORY flag\n- Retry mechanism: __callnewh handler called on allocation failure to attempt memory recovery before final failure\n- Heap handles and state: Uses g_pHeapHandle (process heap handle), g_dwHeapState (mode), g_dwMaxSmallBlockSize (SBH threshold)\n\nGlobal Data References:\ng_pHeapHandle (0x6fc47b94) - Handle to process heap for Windows HeapAlloc calls\ng_dwHeapState (0x6fc47b98) - Heap mode flag (value 3 enables small block heap optimization)\ng_dwMaxSmallBlockSize (0x6fc46910) - Maximum size threshold for small block heap allocations\ng_dwLowMemoryFlag (0x6fc427c4) - Flag indicating if out-of-memory handler should be invoked",
      "name_source": "LoD/1.12a",
      "method": "MNE",
      "index": "MNE:43c1542ced67dd840c298e093699fef1",
      "basic_block_counts": {
        "LoD/1.12a": 18,
        "LoD/1.13c": 18
      },
      "loop_counts": {
        "LoD/1.12a": 0,
        "LoD/1.13c": 0
      },
      "mnemonic_hashes": {
        "LoD/1.12a": "43c1542ced67dd840c298e093699fef1",
        "LoD/1.13c": "43c1542ced67dd840c298e093699fef1"
      }
    },
    "d2net.dll_ReallocateMemory": {
      "addresses": {
        "LoD/1.12a": "0x6FBF2D2A",
        "LoD/1.13c": "0x6FBF2D2A"
      },
      "rvas": {
        "LoD/1.12a": "0x2D2A",
        "LoD/1.13c": "0x2D2A"
      },
      "sizes": {
        "LoD/1.12a": 417,
        "LoD/1.13c": 417
      },
      "name": "ReallocateMemory",
      "signature": "void * ReallocateMemory(void * pOriginalBlock, size_t newSize)",
      "calling_convention": "__cdecl",
      "comment": "\nReallocates a memory block to a new size using the system heap.\n\nAlgorithm:\n1. Acquire critical section lock (critical section 4)\n2. If pOriginalBlock is NULL, allocate new block with newSize and return\n3. If newSize is 0, free original block and return NULL\n4. If heap state is not initialized (g_dwHeapState != 3), attempt error recovery with low memory handling\n5. If newSize is small (less than 32 bytes), use small block allocator path:\n   a. Try in-place resize with ___sbh_resize_block\n   b. If resize fails, allocate new block and copy data using _memcpy\n   c. Free original block after successful copy\n6. For larger blocks (32+ bytes), use heap allocator:\n   a. Align size to 16-byte boundary (add 15, AND with 0xFFFFFFF0)\n   b. Call g_pfnHeapAlloc (HeapAlloc) to allocate new block\n   c. Copy original data up to min(originalSize, newSize) bytes\n   d. Free original block using ___sbh_free_block\n7. If allocation fails and low memory flag set, invoke memory pressure callback and retry allocation\n8. Release critical section lock and return allocated block pointer (or NULL on failure)\n\nParameters:\n- pOriginalBlock (EDI): Pointer to existing memory block to reallocate, or NULL for new allocation\n- newSize (ESI): Requested size in bytes for reallocated block\n\nReturns:\n- EAX: Pointer to reallocated memory block on success, NULL on failure\n\nStructure Layout:\n- Block header (offset -4): Contains original size - 1 (used by resize operations)\n- Block data (offset 0): User-accessible data payload\n\nSpecial Cases:\n- If newSize is 0, block is freed and NULL is returned\n- If pOriginalBlock is NULL, newSize bytes are allocated as new block\n- Small blocks (< 32 bytes) use specialized small block heap allocator\n- Large blocks use system HeapAlloc/HeapReAlloc\n- Alignment: All allocations aligned to 16-byte boundary\n- Low memory handling: If allocation fails with low memory condition set, retry after cleanup callback\n- Lock: Critical section 4 held throughout operation to serialize heap access\n",
      "name_source": "LoD/1.12a",
      "method": "MNE",
      "index": "MNE:630b0e4f3169af3d32abd2ac2d1bf3c9",
      "basic_block_counts": {
        "LoD/1.12a": 39,
        "LoD/1.13c": 39
      },
      "loop_counts": {
        "LoD/1.12a": 0,
        "LoD/1.13c": 0
      },
      "mnemonic_hashes": {
        "LoD/1.12a": "630b0e4f3169af3d32abd2ac2d1bf3c9",
        "LoD/1.13c": "630b0e4f3169af3d32abd2ac2d1bf3c9"
      }
    },
    "d2net.dll_InitializeLocaleCharacterMaps": {
      "addresses": {
        "LoD/1.12a": "0x6FBF339F",
        "LoD/1.13c": "0x6FBF339F"
      },
      "rvas": {
        "LoD/1.12a": "0x339F",
        "LoD/1.13c": "0x339F"
      },
      "sizes": {
        "LoD/1.12a": 411,
        "LoD/1.13c": 411
      },
      "name": "InitializeLocaleCharacterMaps",
      "signature": "void InitializeLocaleCharacterMaps(void)",
      "calling_convention": "__stdcall",
      "comment": "Initializes locale-specific character case mapping tables and character class flags.\n\nAlgorithm:\n1. Initialize stack canary for buffer overflow protection using XOR with global seed\n2. Call GetCPInfo to retrieve code page information for current locale\n3. If code page info available (locale-aware path):\n   a. Create character table (0-255) with space as default for index 0\n   b. Process lead byte ranges from cpInfo.LeadByte to mark multi-byte characters\n   c. Fill all lead byte range positions with spaces (0x20)\n   d. Call ___crtGetStringTypeA to retrieve character type information (CT_CTYPE1)\n   e. Call LocaleMapString with LCMAP_UPPERCASE to build uppercase conversion table\n   f. Call LocaleMapString with LCMAP_LOWERCASE to build lowercase conversion table\n   g. For each character 0-255:\n      - If character is alphanumeric (CT_CTYPE1 & 0x01):\n        * Set bit 0x10 (uppercase flag) in DAT_6fc47960[i+1]\n        * Copy uppercase mapping from uppercaseMap to DAT_6fc47a80[i]\n      - Else if character is lowercase (CT_CTYPE1 & 0x02):\n        * Set bit 0x20 (lowercase flag) in DAT_6fc47960[i+1]\n        * Copy lowercase mapping from lowercaseMap to DAT_6fc47a80[i]\n      - Else set DAT_6fc47a80[i] to 0 (no mapping)\n4. If code page info unavailable (ASCII fallback path):\n   a. For each character 0-255:\n      - If character is A-Z (0x41-0x5A):\n        * Set bit 0x10 (uppercase) in DAT_6fc47960[i+1]\n        * Convert to lowercase by adding 0x20, store in DAT_6fc47a80[i]\n      - Else if character is a-z (0x61-0x7A):\n        * Set bit 0x20 (lowercase) in DAT_6fc47960[i+1]\n        * Convert to uppercase by subtracting 0x20, store in DAT_6fc47a80[i]\n      - Else set DAT_6fc47a80[i] to 0 (non-alphabetic)\n5. Verify stack canary integrity and return\n\nReturns: void - Populates global character mapping tables as side effect\n\nSpecial Cases:\n- DAT_6fc406bc: Global XOR seed for stack canary\n- DAT_6fc47a64: Current code page identifier\n- DAT_6fc47944: Locale handle\n- DAT_6fc47960: Character class flags (-1 offset for 1-based indexing)\n- DAT_6fc47a80: Character case mapping table output\n- Lead byte handling: Multi-byte character encodings skip uppercase mapping\n- Fallback mode: Basic ASCII-only conversion used if GetCPInfo fails\n\nCharacter Class Flags (DAT_6fc47960):\n- 0x10: Uppercase character\n- 0x20: Lowercase character\n- 0x00: Non-alphabetic or unmapped",
      "name_source": "LoD/1.12a",
      "method": "MNE",
      "index": "MNE:9dba01f3a3f519a348d690b818dfa854",
      "basic_block_counts": {
        "LoD/1.12a": 29,
        "LoD/1.13c": 29
      },
      "loop_counts": {
        "LoD/1.12a": 0,
        "LoD/1.13c": 0
      },
      "mnemonic_hashes": {
        "LoD/1.12a": "9dba01f3a3f519a348d690b818dfa854",
        "LoD/1.13c": "9dba01f3a3f519a348d690b818dfa854"
      }
    },
    "d2net.dll_SetupCodePage": {
      "addresses": {
        "LoD/1.12a": "0x6FBF353A",
        "LoD/1.13c": "0x6FBF353A"
      },
      "rvas": {
        "LoD/1.12a": "0x353A",
        "LoD/1.13c": "0x353A"
      },
      "sizes": {
        "LoD/1.12a": 404,
        "LoD/1.13c": 404
      },
      "name": "SetupCodePage",
      "signature": "void SetupCodePage(uint codePage)",
      "calling_convention": "__cdecl",
      "comment": "SetupCodePage - Initialize locale character classification maps for a specific code page\nThis function configures the runtime character classification tables (upper/lower case, digits, whitespace, etc.)\nfor the specified code page. It either uses predefined tables for known code pages or retrieves them\nfrom the system via GetCPInfo API. The character type bitmap is stored in a global 256-entry table\nwhere each byte represents the character types for that code point.\n\nAlgorithm:\n1. Initialize stack canary for buffer overflow detection\n2. Check if codePage parameter is non-zero; if zero, use default SBCS setup\n3. Search predefined code page table (8 entries) for matching code page ID\n4. If found in predefined list:\n   a. Clear the global character type table (DAT_6fc47960, 256 bytes)\n   b. For each of 4 lead byte ranges in predefined table:\n      i. Iterate through range start/end pairs\n      ii. Mark bytes in range with 0x4 flag (lead byte indicator)\n   c. Mark all single-byte values 0x01-0xFE with 0x8 flag (trail byte indicator)\n5. If not found, call GetCPInfo to retrieve system code page information\n6. If GetCPInfo succeeds:\n   a. Clear character type table\n   b. If MaxCharSize >= 2 (multi-byte code page):\n      i. Process lead byte ranges from LeadByte array\n      ii. Mark each byte in range with 0x4 flag\n      iii. Mark all single bytes 0x01-0xFE with 0x8 flag\n7. If GetCPInfo fails and DAT_6fc427b8 is zero, skip setSBCS call\n8. Store code page ID in DAT_6fc47a64\n9. Call InitializeLocaleCharacterMaps to configure additional locale structures\n10. Verify stack canary and return\n\nParameters:\ncodePage - Requested code page identifier (0 = use default, >0 = specific code page to configure)\n\nReturns:\nvoid - Configuration stored in global character classification tables\n\nSpecial Cases:\n- Code page 0 uses default SBCS (Single-Byte Character Set) setup\n- Predefined code pages use static tables, reducing system calls\n- Lead byte ranges marked with 0x04 flag, trail bytes with 0x08 flag\n- Maximum of 8 predefined code pages; beyond that uses GetCPInfo\n- Character type table DAT_6fc47960 is 256 bytes (one entry per possible byte value)",
      "name_source": "LoD/1.12a",
      "method": "MNE",
      "index": "MNE:3b865c2f933cac7b684f56d2d74a981a",
      "basic_block_counts": {
        "LoD/1.12a": 33,
        "LoD/1.13c": 33
      },
      "loop_counts": {
        "LoD/1.12a": 0,
        "LoD/1.13c": 0
      },
      "mnemonic_hashes": {
        "LoD/1.12a": "3b865c2f933cac7b684f56d2d74a981a",
        "LoD/1.13c": "3b865c2f933cac7b684f56d2d74a981a"
      }
    },
    "d2net.dll_LocaleMapString": {
      "addresses": {
        "LoD/1.12a": "0x6FBF51C0",
        "LoD/1.13c": "0x6FBF51C0"
      },
      "rvas": {
        "LoD/1.12a": "0x51C0",
        "LoD/1.13c": "0x51C0"
      },
      "sizes": {
        "LoD/1.12a": 912,
        "LoD/1.13c": 912
      },
      "name": "LocaleMapString",
      "signature": "uint LocaleMapString(LCID localeId, DWORD mapFlags, LPCSTR sourceString, int sourceLength, LPSTR destString, int destLength, uint sourceCodePage, int mbszSourceFlag)",
      "calling_convention": "__cdecl",
      "comment": "Locale-aware string mapping and code page conversion function.\n\nAlgorithm:\n1. Initialize locale capability cache (g_dwLocaleMapStringCapability):\n   - If not cached, test LCMapStringW with flag 0x100 on test string\n   - Cache result: 1 for success (wide-char path), 2 for failure (direct mapping)\n   - On error 0x78, force direct mapping mode\n2. Calculate actual source string length by scanning for null terminator if needed\n3. Branch on cached capability and select mapping path:\n   Path A (Capability=1, wide-char path):\n   - Allocate temporary wide-char buffer (size: wideCharCount*2 rounded to DWORD)\n   - Convert source ANSI to wide chars using MultiByteToWideChar\n   - Map wide string using LCMapStringW with provided mapFlags\n   - If mapFlags & 0x400: Direct wide output, else convert back to ANSI\n   - Allocate second wide buffer if output conversion needed\n   - Convert mapped result to ANSI using WideCharToMultiByte\n   - Free temporary buffers on exit\n   Path B (Capability=0 or 2, direct mapping):\n   - Use default locale (g_dwDefaultLocaleId) if localeId is 0\n   - Get default code page from g_dwActiveCodePage if sourceCodePage is 0\n   - Query target code page for locale using GetLocaleDefaultCodePage\n   - If code pages match: call LCMapStringA directly\n   - If code pages differ: transcode source using ConvertCodePageString\n   - Map transcoded string with LCMapStringA\n   - Convert result back to source code page using ConvertCodePageString\n   - Free all intermediate buffers\n4. Return character count written (or 0 on any allocation/conversion failure)\n\nParameters:\n  localeId (LCID): Locale identifier for string operations (0 = use default)\n  mapFlags (DWORD): LC_MAP_* flags for transformation (0x400 = skip output conversion)\n  sourceString (LPCSTR): Pointer to input string buffer\n  sourceLength (int): Length of source (-1 = scan for null terminator)\n  destString (LPSTR): Pointer to output buffer (NULL = get required size only)\n  destLength (int): Size of destination buffer in bytes\n  sourceCodePage (uint): Input code page (0 = use g_dwActiveCodePage)\n  mbszSourceFlag (int): Multi-byte character flag for MultiByteToWideChar (0 or 1+)\n\nReturns:\n  uint: Number of characters written to destString, or 0 on error\n  Error conditions: allocation failure, invalid parameters, API failures\n\nSpecial Cases:\n  - Null localeId uses g_dwDefaultLocaleId as fallback\n  - Null sourceCodePage uses g_dwActiveCodePage\n  - Null destString with 0 destLength: returns required buffer size only\n  - LCMapStringW error 0x78: sets capability to 2, retries with LCMapStringA\n  - Code page conversion uses ConvertCodePageString helper (FUN_6fbfd74a)\n  - Wide buffers allocated with stack/heap hybrid (inline if small, malloc if large)\n  - mapFlags 0x400 prevents final output conversion step for optimization\n  - All intermediate allocations freed via _free() in cleanup section",
      "name_source": "LoD/1.12a",
      "method": "MNE",
      "index": "MNE:9202742c31e7fad9c07478efa934202a",
      "basic_block_counts": {
        "LoD/1.12a": 68,
        "LoD/1.13c": 68
      },
      "loop_counts": {
        "LoD/1.12a": 0,
        "LoD/1.13c": 0
      },
      "mnemonic_hashes": {
        "LoD/1.12a": "9202742c31e7fad9c07478efa934202a",
        "LoD/1.13c": "9202742c31e7fad9c07478efa934202a"
      }
    },
    "d2net.dll_GetLocaleDefaultCodePage": {
      "addresses": {
        "LoD/1.12a": "0x6FBF5909",
        "LoD/1.13c": "0x6FBF5909"
      },
      "rvas": {
        "LoD/1.12a": "0x5909",
        "LoD/1.13c": "0x5909"
      },
      "sizes": {
        "LoD/1.12a": 71,
        "LoD/1.13c": 71
      },
      "name": "GetLocaleDefaultCodePage",
      "signature": "int GetLocaleDefaultCodePage(LCID localeId)",
      "calling_convention": "__cdecl",
      "comment": "Retrieve the default code page (character encoding) for a Windows locale ID.\n\nAlgorithm:\n1. Initialize stack overflow protection by XORing global canary seed with EBP\n2. Call GetLocaleInfoA with LOCALE_IDEFAULTCODEPAGE (0x1004) to fetch code page string\n3. Test return value: non-zero indicates successful retrieval into 6-byte buffer\n4. If successful: call _atol to convert ASCII string to integer code page number\n5. If failed: set EAX to -1 (0xffffffff) to signal error\n6. Verify stack canary by XORing stored value with EBP and calling validation\n7. Return code page integer in EAX (or -1 for failure)\n\nParameters:\n  lcid (LCID): Windows locale ID (e.g., 0x409 for US English)\n\nReturns:\n  int: Code page number (e.g., 1252 for Windows-1252, 65001 for UTF-8)\n  -1: Error code if GetLocaleInfoA failed or locale not found\n\nSpecial Cases:\n  - Buffer size 6 bytes handles code page strings up to \"65001\\0\"\n  - Return -1 (0xffffffff) indicates locale not supported or query failed\n  - Stack canary protects against stack buffer overflow attacks",
      "name_source": "LoD/1.12a",
      "method": "MNE",
      "index": "MNE:138cb9be9d7caeaaa6cff721ddf1f5fa",
      "basic_block_counts": {
        "LoD/1.12a": 4,
        "LoD/1.13c": 4
      },
      "loop_counts": {
        "LoD/1.12a": 0,
        "LoD/1.13c": 0
      },
      "mnemonic_hashes": {
        "LoD/1.12a": "138cb9be9d7caeaaa6cff721ddf1f5fa",
        "LoD/1.13c": "138cb9be9d7caeaaa6cff721ddf1f5fa"
      }
    },
    "d2net.dll_ConvertStringBetweenCodePages": {
      "addresses": {
        "LoD/1.12a": "0x6FBF5950",
        "LoD/1.13c": "0x6FBF5950"
      },
      "rvas": {
        "LoD/1.12a": "0x5950",
        "LoD/1.13c": "0x5950"
      },
      "sizes": {
        "LoD/1.12a": 451,
        "LoD/1.13c": 451
      },
      "name": "ConvertStringBetweenCodePages",
      "signature": "int ConvertStringBetweenCodePages(UINT sourceCodePage, UINT targetCodePage, char * sourceString, uint * pSourceSize, LPSTR outputBuffer, uint outputBufferSize)",
      "calling_convention": "__cdecl",
      "comment": "Converts a string from one Windows code page encoding to another using intermediate UTF-16 conversion.\n\nAlgorithm:\n1. Validate source and target code pages support single-byte characters via GetCPInfo\n2. If both pages are single-byte compatible, mark for direct conversion path\n3. If conversion required, use MultiByteToWideChar to decode source string to UTF-16\n4. Calculate intermediate UTF-16 buffer size (source size * 2) and allocate on stack or heap\n5. Clear UTF-16 buffer with memset\n6. If output buffer provided, convert UTF-16 to target encoding with WideCharToMultiByte\n7. If no output buffer, allocate heap memory for result and convert to target page\n8. Update output size pointer if provided (pSourceSize not 0xFFFFFFFF)\n9. Free temporary heap allocations and perform stack security cookie validation\n\nParameters:\nsourceCodePage - Windows ANSI code page ID for source string (e.g., 1252 for Windows-1252)\ntargetCodePage - Windows ANSI code page ID for target encoding (e.g., 20127 for ASCII)\nsourceString - Pointer to null-terminated string in source encoding\npSourceSize - Pointer to source size; 0xFFFFFFFF means calculate via strlen()+1, updated with result size\noutputBuffer - Destination buffer for converted string; NULL for heap allocation and size calculation\noutputBufferSize - Size of output buffer in bytes if provided\n\nReturns:\nNon-zero (size of converted string) on success; 0 on failure (invalid code page or allocation error)\n\nSpecial Cases:\n- sourceCodePage == targetCodePage: No conversion performed, function returns immediately\n- pSourceSize == 0xFFFFFFFF: Function calculates source length via strlen()+1 for null-terminator\n- outputBuffer == NULL: Function allocates heap memory for converted string result\n- Large source strings: Stack buffer (64KB) exceeded triggers heap allocation for UTF-16\n- Stack security: XOR cookie validation protects against stack buffer overruns\n- Error handling: Freed allocations and returns 0 on GetCPInfo failure, MultiByteToWideChar failure, or allocation failure",
      "name_source": "LoD/1.12a",
      "method": "MNE",
      "index": "MNE:a82412e86c7e059d3af6ea9d376e2875",
      "basic_block_counts": {
        "LoD/1.12a": 35,
        "LoD/1.13c": 35
      },
      "loop_counts": {
        "LoD/1.12a": 0,
        "LoD/1.13c": 0
      },
      "mnemonic_hashes": {
        "LoD/1.12a": "a82412e86c7e059d3af6ea9d376e2875",
        "LoD/1.13c": "a82412e86c7e059d3af6ea9d376e2875"
      }
    },
    "d2net.dll_EXP_10005": {
      "addresses": {
        "LoD/1.12a": "0x6FBF72F0",
        "LoD/1.13c": "0x6FBF61F0",
        "LoD/1.13d": "0x6FBF7280"
      },
      "rvas": {
        "LoD/1.12a": "0x72F0",
        "LoD/1.13c": "0x61F0",
        "LoD/1.13d": "0x7280"
      },
      "sizes": {
        "LoD/1.12a": 37,
        "LoD/1.13c": 37,
        "LoD/1.13d": 37
      },
      "name": "Ordinal_10005",
      "signature": "undefined Ordinal_10005(void)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.12a",
      "method": "EXP",
      "index": "EXP:10005",
      "callees": {
        "LoD/1.12a": [
          "DestroyResourceManager"
        ],
        "LoD/1.13c": [
          "DestroyResourceManager"
        ],
        "LoD/1.13d": [
          "DestroyResourceManager"
        ]
      },
      "basic_block_counts": {
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.12a": "3ba034ae7bacc34fe4ac8a696be0ebb6",
        "LoD/1.13c": "3ba034ae7bacc34fe4ac8a696be0ebb6",
        "LoD/1.13d": "3ba034ae7bacc34fe4ac8a696be0ebb6"
      }
    },
    "d2net.dll_EXP_10020": {
      "addresses": {
        "LoD/1.13c": "0x6FBF71E0",
        "LoD/1.13d": "0x6FBF6AB0"
      },
      "rvas": {
        "LoD/1.13c": "0x71E0",
        "LoD/1.13d": "0x6AB0"
      },
      "sizes": {
        "LoD/1.13c": 27,
        "LoD/1.13d": 27
      },
      "name": "Ordinal_10020",
      "signature": "undefined Ordinal_10020(undefined4 * param_1)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.13c",
      "method": "EXP",
      "index": "EXP:10020",
      "basic_block_counts": {
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.13c": "50efb6c37a868379ce8439bd65fe6d05",
        "LoD/1.13d": "50efb6c37a868379ce8439bd65fe6d05"
      }
    },
    "d2net.dll__calloc_1F69": {
      "addresses": {
        "LoD/1.13d": "0x6FBF1F69"
      },
      "rvas": {
        "LoD/1.13d": "0x1F69"
      },
      "sizes": {
        "LoD/1.13d": 175
      },
      "name": "_calloc",
      "signature": "void * _calloc(size_t _Count, size_t _Size)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n _calloc\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.13d",
      "method": "MNE",
      "index": "MNE:91411ab4247869eeb28238e92930a4a5",
      "basic_block_counts": {
        "LoD/1.13d": 15
      },
      "loop_counts": {
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.13d": "91411ab4247869eeb28238e92930a4a5"
      }
    },
    "d2net.dll__realloc_2D0A": {
      "addresses": {
        "LoD/1.13d": "0x6FBF2D0A"
      },
      "rvas": {
        "LoD/1.13d": "0x2D0A"
      },
      "sizes": {
        "LoD/1.13d": 412
      },
      "name": "_realloc",
      "signature": "void * _realloc(void * _Memory, size_t _NewSize)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n _realloc\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.13d",
      "method": "MNE",
      "index": "MNE:8c4228500987c1daeeb1fa9fd68f17a9",
      "basic_block_counts": {
        "LoD/1.13d": 38
      },
      "loop_counts": {
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.13d": "8c4228500987c1daeeb1fa9fd68f17a9"
      }
    },
    "d2net.dll_setSBUpLow_337A": {
      "addresses": {
        "LoD/1.13d": "0x6FBF337A"
      },
      "rvas": {
        "LoD/1.13d": "0x337A"
      },
      "sizes": {
        "LoD/1.13d": 396
      },
      "name": "setSBUpLow",
      "signature": "undefined setSBUpLow(void)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n _setSBUpLow\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.13d",
      "method": "MNE",
      "index": "MNE:0c44e947b1ea344017d45b0d6df8c6c5",
      "basic_block_counts": {
        "LoD/1.13d": 29
      },
      "loop_counts": {
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.13d": "0c44e947b1ea344017d45b0d6df8c6c5"
      }
    },
    "d2net.dll___setmbcp_lk_3506": {
      "addresses": {
        "LoD/1.13d": "0x6FBF3506"
      },
      "rvas": {
        "LoD/1.13d": "0x3506"
      },
      "sizes": {
        "LoD/1.13d": 400
      },
      "name": "__setmbcp_lk",
      "signature": "undefined __setmbcp_lk(UINT param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n __setmbcp_lk\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.13d",
      "method": "MNE",
      "index": "MNE:aca83c0b308ebe5f47dff9cf83f354c7",
      "basic_block_counts": {
        "LoD/1.13d": 33
      },
      "loop_counts": {
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.13d": "aca83c0b308ebe5f47dff9cf83f354c7"
      }
    },
    "d2net.dll____crtLCMapStringA_5190": {
      "addresses": {
        "LoD/1.13d": "0x6FBF5190"
      },
      "rvas": {
        "LoD/1.13d": "0x5190"
      },
      "sizes": {
        "LoD/1.13d": 886
      },
      "name": "___crtLCMapStringA",
      "signature": "int ___crtLCMapStringA(_locale_t _Plocinfo, LPCWSTR _LocaleName, DWORD _DwMapFlag, LPCSTR _LpSrcStr, int _CchSrc, LPSTR _LpDestStr, int _CchDest, int _Code_page, BOOL _BError)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___crtLCMapStringA\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.13d",
      "method": "MNE",
      "index": "MNE:40ace89e5da5d434e25a5d26402f71e1",
      "basic_block_counts": {
        "LoD/1.13d": 65
      },
      "loop_counts": {
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.13d": "40ace89e5da5d434e25a5d26402f71e1"
      }
    },
    "d2net.dll____ansicp_58B9": {
      "addresses": {
        "LoD/1.13d": "0x6FBF58B9"
      },
      "rvas": {
        "LoD/1.13d": "0x58B9"
      },
      "sizes": {
        "LoD/1.13d": 67
      },
      "name": "___ansicp",
      "signature": "undefined ___ansicp(LCID param_1)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___ansicp\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.13d",
      "method": "MNE",
      "index": "MNE:137dd1f09c34b57b162936229329b15b",
      "basic_block_counts": {
        "LoD/1.13d": 4
      },
      "loop_counts": {
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.13d": "137dd1f09c34b57b162936229329b15b"
      }
    },
    "d2net.dll____convertcp_58FC": {
      "addresses": {
        "LoD/1.13d": "0x6FBF58FC"
      },
      "rvas": {
        "LoD/1.13d": "0x58FC"
      },
      "sizes": {
        "LoD/1.13d": 434
      },
      "name": "___convertcp",
      "signature": "undefined ___convertcp(UINT param_1, UINT param_2, char * param_3, size_t * param_4, LPSTR param_5, int param_6)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n ___convertcp\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.13d",
      "method": "MNE",
      "index": "MNE:2db85971dc36836255f9e9bf407d84c7",
      "basic_block_counts": {
        "LoD/1.13d": 35
      },
      "loop_counts": {
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.13d": "2db85971dc36836255f9e9bf407d84c7"
      }
    },
    "d2net.dll_API_fdbfe976ab93_6FF0": {
      "addresses": {
        "LoD/1.13d": "0x6FBF6FF0"
      },
      "rvas": {
        "LoD/1.13d": "0x6FF0"
      },
      "sizes": {
        "LoD/1.13d": 69
      },
      "name_source": "LoD/1.13d",
      "method": "API",
      "index": "API:fdbfe976ab936acb4b93de5302ff5358",
      "callees": {
        "LoD/1.13d": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "ProcessQueuedMessage"
        ]
      },
      "basic_block_counts": {
        "LoD/1.13d": 3
      },
      "loop_counts": {
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.13d": "3dcfecb09995650e75420b34977f5cfa"
      }
    }
  }
};

if (typeof FUNCTION_DATA === 'undefined') FUNCTION_DATA = {};
FUNCTION_DATA['D2Net.dll'] = FUNCTIONS_D2Net_dll;
