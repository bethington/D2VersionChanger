// Auto-generated from function_registry_v2.json
// Generated: 2025-12-13T00:30:31.404426
// Functions for D2MCPClient.dll
// Versions: LoD/1.07, LoD/1.08, LoD/1.09, LoD/1.09b, LoD/1.09d, LoD/1.10, LoD/1.11, LoD/1.11b, LoD/1.12a, LoD/1.13c, LoD/1.13d

var FUNCTIONS_D2MCPClient_dll = {
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
    "d2mcpclient.dll_MNE_d7897101f3cb": {
      "addresses": {
        "LoD/1.07": "0x6FA51000",
        "LoD/1.08": "0x6FA51000",
        "LoD/1.09": "0x6F9F1000",
        "LoD/1.09b": "0x6F9F1000",
        "LoD/1.09d": "0x6F9F1000",
        "LoD/1.10": "0x6F9F1000",
        "LoD/1.11": "0x6FA27590",
        "LoD/1.11b": "0x6FA25DD0",
        "LoD/1.12a": "0x6FA26F20",
        "LoD/1.13c": "0x6FA27600",
        "LoD/1.13d": "0x6FA26E10"
      },
      "rvas": {
        "LoD/1.07": "0x1000",
        "LoD/1.08": "0x1000",
        "LoD/1.09": "0x1000",
        "LoD/1.09b": "0x1000",
        "LoD/1.09d": "0x1000",
        "LoD/1.10": "0x1000",
        "LoD/1.11": "0x7590",
        "LoD/1.11b": "0x5DD0",
        "LoD/1.12a": "0x6F20",
        "LoD/1.13c": "0x7600",
        "LoD/1.13d": "0x6E10"
      },
      "sizes": {
        "LoD/1.07": 8,
        "LoD/1.08": 8,
        "LoD/1.09": 8,
        "LoD/1.09b": 8,
        "LoD/1.09d": 8,
        "LoD/1.10": 8,
        "LoD/1.11": 8,
        "LoD/1.11b": 8,
        "LoD/1.12a": 8,
        "LoD/1.13c": 8,
        "LoD/1.13d": 8
      },
      "signature": "bool ValidateBinkInstallLocation(void)",
      "calling_convention": "__stdcall",
      "comment": "Stub function that always returns success (1).\n\nAlgorithm:\n1. Return TRUE immediately\n\nParameters:\n- pModule (void*): DLL instance handle (unused)\n- dwReason (uint): DLL attach/detach reason (unused)\n- pReserved (void*): Reserved parameter (unused)\n\nReturns:\n- Always returns 1 (TRUE/success)\n\nNotes:\n- Called from DllMain entry point during DLL_PROCESS_ATTACH\n- Placeholder for optional initialization that requires no action",
      "name_source": "LoD/1.08",
      "method": "MNE",
      "index": "MNE:d7897101f3cb99eb3b89274dfb087bc9",
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
        "LoD/1.07": "d7897101f3cb99eb3b89274dfb087bc9",
        "LoD/1.08": "d7897101f3cb99eb3b89274dfb087bc9",
        "LoD/1.09": "d7897101f3cb99eb3b89274dfb087bc9",
        "LoD/1.09b": "d7897101f3cb99eb3b89274dfb087bc9",
        "LoD/1.09d": "d7897101f3cb99eb3b89274dfb087bc9",
        "LoD/1.10": "d7897101f3cb99eb3b89274dfb087bc9",
        "LoD/1.11": "d7897101f3cb99eb3b89274dfb087bc9",
        "LoD/1.11b": "d7897101f3cb99eb3b89274dfb087bc9",
        "LoD/1.12a": "d7897101f3cb99eb3b89274dfb087bc9",
        "LoD/1.13c": "d7897101f3cb99eb3b89274dfb087bc9",
        "LoD/1.13d": "d7897101f3cb99eb3b89274dfb087bc9"
      }
    },
    "d2mcpclient.dll_MNE_546c17e22a38": {
      "addresses": {
        "LoD/1.07": "0x6FA566E0"
      },
      "rvas": {
        "LoD/1.07": "0x66E0"
      },
      "sizes": {
        "LoD/1.07": 1
      },
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:546c17e22a38a8e15c8829671ea3e893",
      "basic_block_counts": {
        "LoD/1.07": 1
      },
      "loop_counts": {
        "LoD/1.07": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "546c17e22a38a8e15c8829671ea3e893"
      }
    },
    "d2mcpclient.dll_API_8df21ee8d099": {
      "addresses": {
        "LoD/1.07": "0x6FA510C0",
        "LoD/1.08": "0x6FA510C0",
        "LoD/1.09": "0x6F9F10C0",
        "LoD/1.09b": "0x6F9F10C0",
        "LoD/1.09d": "0x6F9F10C0",
        "LoD/1.10": "0x6F9F10C0"
      },
      "rvas": {
        "LoD/1.07": "0x10C0",
        "LoD/1.08": "0x10C0",
        "LoD/1.09": "0x10C0",
        "LoD/1.09b": "0x10C0",
        "LoD/1.09d": "0x10C0",
        "LoD/1.10": "0x10C0"
      },
      "sizes": {
        "LoD/1.07": 115,
        "LoD/1.08": 115,
        "LoD/1.09": 115,
        "LoD/1.09b": 115,
        "LoD/1.09d": 115,
        "LoD/1.10": 115
      },
      "name_source": "LoD/1.07",
      "method": "API",
      "index": "API:8df21ee8d0997ac09ea958529801c23f",
      "callees": {
        "LoD/1.07": [
          "Ordinal_10047",
          "Ordinal_10047",
          "InetNtoaToStaticBuffer",
          "SStrCopy"
        ],
        "LoD/1.08": [
          "Ordinal_10047",
          "Ordinal_10047",
          "InetNtoaToStaticBuffer",
          "Ordinal_501"
        ],
        "LoD/1.09": [
          "Ordinal_10047",
          "Ordinal_10047",
          "InetNtoaToStaticBuffer",
          "Ordinal_501"
        ],
        "LoD/1.09b": [
          "Ordinal_10047",
          "Ordinal_10047",
          "InetNtoaToStaticBuffer",
          "Ordinal_501"
        ],
        "LoD/1.09d": [
          "Ordinal_10047",
          "Ordinal_10047",
          "InetNtoaToStaticBuffer",
          "Ordinal_501"
        ],
        "LoD/1.10": [
          "Ordinal_10047",
          "Ordinal_10047",
          "Ordinal_10014",
          "Ordinal_501"
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
        "LoD/1.07": "57156ab73e34dcf3954f1125fe948aee",
        "LoD/1.08": "57156ab73e34dcf3954f1125fe948aee",
        "LoD/1.09": "57156ab73e34dcf3954f1125fe948aee",
        "LoD/1.09b": "57156ab73e34dcf3954f1125fe948aee",
        "LoD/1.09d": "57156ab73e34dcf3954f1125fe948aee",
        "LoD/1.10": "57156ab73e34dcf3954f1125fe948aee"
      }
    },
    "d2mcpclient.dll_MNE_1de091de38a0": {
      "addresses": {
        "LoD/1.07": "0x6FA518A0"
      },
      "rvas": {
        "LoD/1.07": "0x18A0"
      },
      "sizes": {
        "LoD/1.07": 1
      },
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:1de091de38a0c8104999bec46fd52d0f",
      "basic_block_counts": {
        "LoD/1.07": 1
      },
      "loop_counts": {
        "LoD/1.07": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "1de091de38a0c8104999bec46fd52d0f"
      }
    },
    "d2mcpclient.dll_MNE_f270bd4ea935": {
      "addresses": {
        "LoD/1.07": "0x6FA51480"
      },
      "rvas": {
        "LoD/1.07": "0x1480"
      },
      "sizes": {
        "LoD/1.07": 1
      },
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:f270bd4ea9353a0eb6c1909a1eb635e5",
      "basic_block_counts": {
        "LoD/1.07": 1
      },
      "loop_counts": {
        "LoD/1.07": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "f270bd4ea9353a0eb6c1909a1eb635e5"
      }
    },
    "d2mcpclient.dll_MNE_2043487ec0ce": {
      "addresses": {
        "LoD/1.07": "0x6FA56A40"
      },
      "rvas": {
        "LoD/1.07": "0x6A40"
      },
      "sizes": {
        "LoD/1.07": 1
      },
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:2043487ec0ce2238c03195f2d42cad4f",
      "basic_block_counts": {
        "LoD/1.07": 1
      },
      "loop_counts": {
        "LoD/1.07": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "2043487ec0ce2238c03195f2d42cad4f"
      }
    },
    "d2mcpclient.dll_MNE_5c22dede0f74": {
      "addresses": {
        "LoD/1.07": "0x6FA51720"
      },
      "rvas": {
        "LoD/1.07": "0x1720"
      },
      "sizes": {
        "LoD/1.07": 1
      },
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:5c22dede0f74ae8b02dbfc7aae0ebe58",
      "basic_block_counts": {
        "LoD/1.07": 1
      },
      "loop_counts": {
        "LoD/1.07": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "5c22dede0f74ae8b02dbfc7aae0ebe58"
      }
    },
    "d2mcpclient.dll_MNE_7adc3407635b": {
      "addresses": {
        "LoD/1.07": "0x6FA51780",
        "LoD/1.08": "0x6FA51780",
        "LoD/1.09": "0x6F9F1780",
        "LoD/1.09b": "0x6F9F1780",
        "LoD/1.09d": "0x6F9F1780",
        "LoD/1.10": "0x6F9F16F0"
      },
      "rvas": {
        "LoD/1.07": "0x1780",
        "LoD/1.08": "0x1780",
        "LoD/1.09": "0x1780",
        "LoD/1.09b": "0x1780",
        "LoD/1.09d": "0x1780",
        "LoD/1.10": "0x16F0"
      },
      "sizes": {
        "LoD/1.07": 59,
        "LoD/1.08": 59,
        "LoD/1.09": 59,
        "LoD/1.09b": 59,
        "LoD/1.09d": 59,
        "LoD/1.10": 59
      },
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:7adc3407635b45ef7f8073163a37838c",
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
        "LoD/1.07": "7adc3407635b45ef7f8073163a37838c",
        "LoD/1.08": "7adc3407635b45ef7f8073163a37838c",
        "LoD/1.09": "7adc3407635b45ef7f8073163a37838c",
        "LoD/1.09b": "7adc3407635b45ef7f8073163a37838c",
        "LoD/1.09d": "7adc3407635b45ef7f8073163a37838c",
        "LoD/1.10": "7adc3407635b45ef7f8073163a37838c"
      }
    },
    "d2mcpclient.dll_EXP_10011": {
      "addresses": {
        "LoD/1.07": "0x6FA51810",
        "LoD/1.08": "0x6FA51810",
        "LoD/1.09": "0x6F9F1820",
        "LoD/1.09b": "0x6F9F1820",
        "LoD/1.09d": "0x6F9F1820",
        "LoD/1.10": "0x6F9F1790",
        "LoD/1.11": "0x6FA26E20",
        "LoD/1.11b": "0x6FA25DE0",
        "LoD/1.12a": "0x6FA26790",
        "LoD/1.13c": "0x6FA25E40",
        "LoD/1.13d": "0x6FA26EF0"
      },
      "rvas": {
        "LoD/1.07": "0x1810",
        "LoD/1.08": "0x1810",
        "LoD/1.09": "0x1820",
        "LoD/1.09b": "0x1820",
        "LoD/1.09d": "0x1820",
        "LoD/1.10": "0x1790",
        "LoD/1.11": "0x6E20",
        "LoD/1.11b": "0x5DE0",
        "LoD/1.12a": "0x6790",
        "LoD/1.13c": "0x5E40",
        "LoD/1.13d": "0x6EF0"
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
      "name": "Ordinal_10011",
      "signature": "undefined Ordinal_10011(undefined4 param_1)",
      "calling_convention": "__fastcall",
      "name_source": "LoD/1.07",
      "method": "EXP",
      "index": "EXP:10011",
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
        "LoD/1.07": "305c32d33191c1b22ce2562362c5fa24",
        "LoD/1.08": "305c32d33191c1b22ce2562362c5fa24",
        "LoD/1.09": "305c32d33191c1b22ce2562362c5fa24",
        "LoD/1.09b": "305c32d33191c1b22ce2562362c5fa24",
        "LoD/1.09d": "305c32d33191c1b22ce2562362c5fa24",
        "LoD/1.10": "305c32d33191c1b22ce2562362c5fa24",
        "LoD/1.11": "305c32d33191c1b22ce2562362c5fa24",
        "LoD/1.11b": "305c32d33191c1b22ce2562362c5fa24",
        "LoD/1.12a": "305c32d33191c1b22ce2562362c5fa24",
        "LoD/1.13c": "305c32d33191c1b22ce2562362c5fa24",
        "LoD/1.13d": "305c32d33191c1b22ce2562362c5fa24"
      }
    },
    "d2mcpclient.dll_EXP_10010": {
      "addresses": {
        "LoD/1.07": "0x6FA51820",
        "LoD/1.08": "0x6FA51820",
        "LoD/1.09": "0x6F9F1840",
        "LoD/1.09b": "0x6F9F1840",
        "LoD/1.09d": "0x6F9F1810",
        "LoD/1.10": "0x6F9F17B0",
        "LoD/1.11": "0x6FA26E00",
        "LoD/1.11b": "0x6FA25E00",
        "LoD/1.12a": "0x6FA267B0",
        "LoD/1.13c": "0x6FA25E60",
        "LoD/1.13d": "0x6FA26EC0"
      },
      "rvas": {
        "LoD/1.07": "0x1820",
        "LoD/1.08": "0x1820",
        "LoD/1.09": "0x1840",
        "LoD/1.09b": "0x1840",
        "LoD/1.09d": "0x1810",
        "LoD/1.10": "0x17B0",
        "LoD/1.11": "0x6E00",
        "LoD/1.11b": "0x5E00",
        "LoD/1.12a": "0x67B0",
        "LoD/1.13c": "0x5E60",
        "LoD/1.13d": "0x6EC0"
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
      "name": "Ordinal_10010",
      "signature": "undefined Ordinal_10010(undefined4 param_1)",
      "calling_convention": "__fastcall",
      "name_source": "LoD/1.07",
      "method": "EXP",
      "index": "EXP:10010",
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
        "LoD/1.07": "305c32d33191c1b22ce2562362c5fa24",
        "LoD/1.08": "305c32d33191c1b22ce2562362c5fa24",
        "LoD/1.09": "305c32d33191c1b22ce2562362c5fa24",
        "LoD/1.09b": "305c32d33191c1b22ce2562362c5fa24",
        "LoD/1.09d": "305c32d33191c1b22ce2562362c5fa24",
        "LoD/1.10": "305c32d33191c1b22ce2562362c5fa24",
        "LoD/1.11": "305c32d33191c1b22ce2562362c5fa24",
        "LoD/1.11b": "305c32d33191c1b22ce2562362c5fa24",
        "LoD/1.12a": "305c32d33191c1b22ce2562362c5fa24",
        "LoD/1.13c": "305c32d33191c1b22ce2562362c5fa24",
        "LoD/1.13d": "305c32d33191c1b22ce2562362c5fa24"
      }
    },
    "d2mcpclient.dll_EXP_10012": {
      "addresses": {
        "LoD/1.07": "0x6FA51830",
        "LoD/1.08": "0x6FA51830",
        "LoD/1.09": "0x6F9F1830",
        "LoD/1.09b": "0x6F9F1830",
        "LoD/1.09d": "0x6F9F1830",
        "LoD/1.10": "0x6F9F17A0",
        "LoD/1.11": "0x6FA26E10",
        "LoD/1.11b": "0x6FA25DF0",
        "LoD/1.12a": "0x6FA267A0",
        "LoD/1.13c": "0x6FA25E50",
        "LoD/1.13d": "0x6FA26ED0"
      },
      "rvas": {
        "LoD/1.07": "0x1830",
        "LoD/1.08": "0x1830",
        "LoD/1.09": "0x1830",
        "LoD/1.09b": "0x1830",
        "LoD/1.09d": "0x1830",
        "LoD/1.10": "0x17A0",
        "LoD/1.11": "0x6E10",
        "LoD/1.11b": "0x5DF0",
        "LoD/1.12a": "0x67A0",
        "LoD/1.13c": "0x5E50",
        "LoD/1.13d": "0x6ED0"
      },
      "sizes": {
        "LoD/1.07": 13,
        "LoD/1.08": 13,
        "LoD/1.09": 13,
        "LoD/1.09b": 13,
        "LoD/1.09d": 13,
        "LoD/1.10": 13,
        "LoD/1.11": 13,
        "LoD/1.11b": 13,
        "LoD/1.12a": 13,
        "LoD/1.13c": 13,
        "LoD/1.13d": 13
      },
      "name": "Ordinal_10012",
      "signature": "undefined Ordinal_10012(undefined4 param_1, undefined4 param_2)",
      "calling_convention": "__fastcall",
      "name_source": "LoD/1.07",
      "method": "EXP",
      "index": "EXP:10012",
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
        "LoD/1.07": "da11010bec3d59770c090d0277a18455",
        "LoD/1.08": "da11010bec3d59770c090d0277a18455",
        "LoD/1.09": "da11010bec3d59770c090d0277a18455",
        "LoD/1.09b": "da11010bec3d59770c090d0277a18455",
        "LoD/1.09d": "da11010bec3d59770c090d0277a18455",
        "LoD/1.10": "da11010bec3d59770c090d0277a18455",
        "LoD/1.11": "da11010bec3d59770c090d0277a18455",
        "LoD/1.11b": "da11010bec3d59770c090d0277a18455",
        "LoD/1.12a": "da11010bec3d59770c090d0277a18455",
        "LoD/1.13c": "da11010bec3d59770c090d0277a18455",
        "LoD/1.13d": "da11010bec3d59770c090d0277a18455"
      }
    },
    "d2mcpclient.dll_EXP_10048": {
      "addresses": {
        "LoD/1.07": "0x6FA51840",
        "LoD/1.08": "0x6FA51840",
        "LoD/1.09": "0x6F9F1810",
        "LoD/1.09b": "0x6F9F1810",
        "LoD/1.09d": "0x6F9F1840",
        "LoD/1.10": "0x6F9F1780",
        "LoD/1.11": "0x6FA26E30",
        "LoD/1.11b": "0x6FA25E10",
        "LoD/1.12a": "0x6FA267C0",
        "LoD/1.13c": "0x6FA25E70",
        "LoD/1.13d": "0x6FA26EE0"
      },
      "rvas": {
        "LoD/1.07": "0x1840",
        "LoD/1.08": "0x1840",
        "LoD/1.09": "0x1810",
        "LoD/1.09b": "0x1810",
        "LoD/1.09d": "0x1840",
        "LoD/1.10": "0x1780",
        "LoD/1.11": "0x6E30",
        "LoD/1.11b": "0x5E10",
        "LoD/1.12a": "0x67C0",
        "LoD/1.13c": "0x5E70",
        "LoD/1.13d": "0x6EE0"
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
      "name": "Ordinal_10048",
      "signature": "undefined Ordinal_10048(undefined4 param_1)",
      "calling_convention": "__fastcall",
      "name_source": "LoD/1.07",
      "method": "EXP",
      "index": "EXP:10048",
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
        "LoD/1.07": "305c32d33191c1b22ce2562362c5fa24",
        "LoD/1.08": "305c32d33191c1b22ce2562362c5fa24",
        "LoD/1.09": "305c32d33191c1b22ce2562362c5fa24",
        "LoD/1.09b": "305c32d33191c1b22ce2562362c5fa24",
        "LoD/1.09d": "305c32d33191c1b22ce2562362c5fa24",
        "LoD/1.10": "305c32d33191c1b22ce2562362c5fa24",
        "LoD/1.11": "305c32d33191c1b22ce2562362c5fa24",
        "LoD/1.11b": "305c32d33191c1b22ce2562362c5fa24",
        "LoD/1.12a": "305c32d33191c1b22ce2562362c5fa24",
        "LoD/1.13c": "305c32d33191c1b22ce2562362c5fa24",
        "LoD/1.13d": "305c32d33191c1b22ce2562362c5fa24"
      }
    },
    "d2mcpclient.dll_EXP_10055": {
      "addresses": {
        "LoD/1.07": "0x6FA51850",
        "LoD/1.08": "0x6FA51850",
        "LoD/1.09": "0x6F9F1D60",
        "LoD/1.09b": "0x6F9F1D60",
        "LoD/1.09d": "0x6F9F1BF0",
        "LoD/1.10": "0x6F9F1C30",
        "LoD/1.11": "0x6FA25F10",
        "LoD/1.11b": "0x6FA266B0",
        "LoD/1.12a": "0x6FA27070",
        "LoD/1.13c": "0x6FA26710",
        "LoD/1.13d": "0x6FA25FB0"
      },
      "rvas": {
        "LoD/1.07": "0x1850",
        "LoD/1.08": "0x1850",
        "LoD/1.09": "0x1D60",
        "LoD/1.09b": "0x1D60",
        "LoD/1.09d": "0x1BF0",
        "LoD/1.10": "0x1C30",
        "LoD/1.11": "0x5F10",
        "LoD/1.11b": "0x66B0",
        "LoD/1.12a": "0x7070",
        "LoD/1.13c": "0x6710",
        "LoD/1.13d": "0x5FB0"
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
      "name": "Ordinal_10055",
      "signature": "undefined4 Ordinal_10055(void)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.07",
      "method": "EXP",
      "index": "EXP:10055",
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
        "LoD/1.07": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.08": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.09": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.09b": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.09d": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.10": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.11": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.11b": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.12a": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.13c": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.13d": "7b4de9f0cf357b113d12e0c7e214792b"
      }
    },
    "d2mcpclient.dll_EXP_10000": {
      "addresses": {
        "LoD/1.07": "0x6FA51860",
        "LoD/1.08": "0x6FA51860",
        "LoD/1.09": "0x6F9F1860",
        "LoD/1.09b": "0x6F9F1860",
        "LoD/1.09d": "0x6F9F1860",
        "LoD/1.10": "0x6F9F17D0",
        "LoD/1.11": "0x6FA264F0",
        "LoD/1.11b": "0x6FA26CC0",
        "LoD/1.12a": "0x6FA26060",
        "LoD/1.13c": "0x6FA26CF0",
        "LoD/1.13d": "0x6FA265F0"
      },
      "rvas": {
        "LoD/1.07": "0x1860",
        "LoD/1.08": "0x1860",
        "LoD/1.09": "0x1860",
        "LoD/1.09b": "0x1860",
        "LoD/1.09d": "0x1860",
        "LoD/1.10": "0x17D0",
        "LoD/1.11": "0x64F0",
        "LoD/1.11b": "0x6CC0",
        "LoD/1.12a": "0x6060",
        "LoD/1.13c": "0x6CF0",
        "LoD/1.13d": "0x65F0"
      },
      "sizes": {
        "LoD/1.07": 61,
        "LoD/1.08": 61,
        "LoD/1.09": 61,
        "LoD/1.09b": 61,
        "LoD/1.09d": 61,
        "LoD/1.10": 61,
        "LoD/1.11": 37,
        "LoD/1.11b": 37,
        "LoD/1.12a": 37,
        "LoD/1.13c": 37,
        "LoD/1.13d": 37
      },
      "name": "Ordinal_10000",
      "signature": "undefined Ordinal_10000(undefined4 * param_1)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.07",
      "method": "EXP",
      "index": "EXP:10000",
      "callees": {
        "LoD/1.11": [
          "Ordinal_10070"
        ],
        "LoD/1.11b": [
          "Ordinal_10070"
        ],
        "LoD/1.12a": [
          "EncodeBufferWithContext"
        ],
        "LoD/1.13c": [
          "EncodeBufferWithContext"
        ],
        "LoD/1.13d": [
          "EncodeBufferWithContext"
        ]
      },
      "basic_block_counts": {
        "LoD/1.07": 3,
        "LoD/1.08": 3,
        "LoD/1.09": 3,
        "LoD/1.09b": 3,
        "LoD/1.09d": 3,
        "LoD/1.10": 3,
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
        "LoD/1.07": "bc25972d8ffffbae67ab1b81ddc12a86",
        "LoD/1.08": "bc25972d8ffffbae67ab1b81ddc12a86",
        "LoD/1.09": "bc25972d8ffffbae67ab1b81ddc12a86",
        "LoD/1.09b": "bc25972d8ffffbae67ab1b81ddc12a86",
        "LoD/1.09d": "bc25972d8ffffbae67ab1b81ddc12a86",
        "LoD/1.10": "bc25972d8ffffbae67ab1b81ddc12a86",
        "LoD/1.11": "27cf70e216d5f82ac091c77f63637746",
        "LoD/1.11b": "27cf70e216d5f82ac091c77f63637746",
        "LoD/1.12a": "27cf70e216d5f82ac091c77f63637746",
        "LoD/1.13c": "27cf70e216d5f82ac091c77f63637746",
        "LoD/1.13d": "27cf70e216d5f82ac091c77f63637746"
      }
    },
    "d2mcpclient.dll_EXP_10001": {
      "addresses": {
        "LoD/1.07": "0x6FA51A10",
        "LoD/1.08": "0x6FA51A10",
        "LoD/1.09": "0x6F9F1A10",
        "LoD/1.09b": "0x6F9F1A10",
        "LoD/1.09d": "0x6F9F1A10",
        "LoD/1.10": "0x6F9F1980",
        "LoD/1.11": "0x6FA267B0",
        "LoD/1.11b": "0x6FA27050",
        "LoD/1.12a": "0x6FA26240",
        "LoD/1.13c": "0x6FA27140",
        "LoD/1.13d": "0x6FA268C0"
      },
      "rvas": {
        "LoD/1.07": "0x1A10",
        "LoD/1.08": "0x1A10",
        "LoD/1.09": "0x1A10",
        "LoD/1.09b": "0x1A10",
        "LoD/1.09d": "0x1A10",
        "LoD/1.10": "0x1980",
        "LoD/1.11": "0x67B0",
        "LoD/1.11b": "0x7050",
        "LoD/1.12a": "0x6240",
        "LoD/1.13c": "0x7140",
        "LoD/1.13d": "0x68C0"
      },
      "sizes": {
        "LoD/1.07": 92,
        "LoD/1.08": 92,
        "LoD/1.09": 92,
        "LoD/1.09b": 92,
        "LoD/1.09d": 92,
        "LoD/1.10": 92,
        "LoD/1.11": 110,
        "LoD/1.11b": 129,
        "LoD/1.12a": 129,
        "LoD/1.13c": 129,
        "LoD/1.13d": 129
      },
      "name": "Ordinal_10001",
      "signature": "undefined Ordinal_10001(void)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.07",
      "method": "EXP",
      "index": "EXP:10001",
      "callees": {
        "LoD/1.07": [
          "DestroyNetworkContext"
        ],
        "LoD/1.08": [
          "DestroyNetworkContext"
        ],
        "LoD/1.09": [
          "DestroyNetworkContext"
        ],
        "LoD/1.09b": [
          "DestroyNetworkContext"
        ],
        "LoD/1.09d": [
          "DestroyNetworkContext"
        ],
        "LoD/1.10": [
          "Ordinal_10069"
        ],
        "LoD/1.11": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "Ordinal_10070"
        ],
        "LoD/1.11b": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "Ordinal_10070"
        ],
        "LoD/1.12a": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "EncodeBufferWithContext"
        ],
        "LoD/1.13c": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "EncodeBufferWithContext"
        ],
        "LoD/1.13d": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "EncodeBufferWithContext"
        ]
      },
      "basic_block_counts": {
        "LoD/1.07": 7,
        "LoD/1.08": 7,
        "LoD/1.09": 7,
        "LoD/1.09b": 7,
        "LoD/1.09d": 7,
        "LoD/1.10": 7,
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
        "LoD/1.07": "ffd6221cea7169bc6b2bc3418f4ddda8",
        "LoD/1.08": "ffd6221cea7169bc6b2bc3418f4ddda8",
        "LoD/1.09": "ffd6221cea7169bc6b2bc3418f4ddda8",
        "LoD/1.09b": "ffd6221cea7169bc6b2bc3418f4ddda8",
        "LoD/1.09d": "ffd6221cea7169bc6b2bc3418f4ddda8",
        "LoD/1.10": "ffd6221cea7169bc6b2bc3418f4ddda8",
        "LoD/1.11": "309c7651d80129250d0c2018c96c4c58",
        "LoD/1.11b": "3eac90692de3b7c4393f1c737342792a",
        "LoD/1.12a": "3eac90692de3b7c4393f1c737342792a",
        "LoD/1.13c": "3eac90692de3b7c4393f1c737342792a",
        "LoD/1.13d": "3eac90692de3b7c4393f1c737342792a"
      }
    },
    "d2mcpclient.dll_EXP_10002": {
      "addresses": {
        "LoD/1.07": "0x6FA51A70",
        "LoD/1.08": "0x6FA51A70",
        "LoD/1.09": "0x6F9F1A70",
        "LoD/1.09b": "0x6F9F1A70",
        "LoD/1.09d": "0x6F9F1A70",
        "LoD/1.10": "0x6F9F19E0",
        "LoD/1.11": "0x6FA26940",
        "LoD/1.11b": "0x6FA26F50",
        "LoD/1.12a": "0x6FA26090",
        "LoD/1.13c": "0x6FA26FB0",
        "LoD/1.13d": "0x6FA267C0"
      },
      "rvas": {
        "LoD/1.07": "0x1A70",
        "LoD/1.08": "0x1A70",
        "LoD/1.09": "0x1A70",
        "LoD/1.09b": "0x1A70",
        "LoD/1.09d": "0x1A70",
        "LoD/1.10": "0x19E0",
        "LoD/1.11": "0x6940",
        "LoD/1.11b": "0x6F50",
        "LoD/1.12a": "0x6090",
        "LoD/1.13c": "0x6FB0",
        "LoD/1.13d": "0x67C0"
      },
      "sizes": {
        "LoD/1.07": 50,
        "LoD/1.08": 50,
        "LoD/1.09": 50,
        "LoD/1.09b": 50,
        "LoD/1.09d": 50,
        "LoD/1.10": 50,
        "LoD/1.11": 129,
        "LoD/1.11b": 110,
        "LoD/1.12a": 110,
        "LoD/1.13c": 110,
        "LoD/1.13d": 110
      },
      "name": "Ordinal_10002",
      "signature": "undefined Ordinal_10002(void)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.07",
      "method": "EXP",
      "index": "EXP:10002",
      "callees": {
        "LoD/1.07": [
          "GetField0x110",
          "GetPeerName"
        ],
        "LoD/1.08": [
          "GetField0x110",
          "GetPeerName"
        ],
        "LoD/1.09": [
          "GetField0x110",
          "GetPeerName"
        ],
        "LoD/1.09b": [
          "GetField0x110",
          "GetPeerName"
        ],
        "LoD/1.09d": [
          "GetField0x110",
          "GetPeerName"
        ],
        "LoD/1.10": [
          "GetField0x110",
          "Ordinal_10012"
        ],
        "LoD/1.11": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "Ordinal_10070"
        ],
        "LoD/1.11b": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "Ordinal_10070"
        ],
        "LoD/1.12a": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "EncodeBufferWithContext"
        ],
        "LoD/1.13c": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "EncodeBufferWithContext"
        ],
        "LoD/1.13d": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "EncodeBufferWithContext"
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
        "LoD/1.07": "2dbd2ed1e82bd22db1301a8c11d6ee6e",
        "LoD/1.08": "2dbd2ed1e82bd22db1301a8c11d6ee6e",
        "LoD/1.09": "2dbd2ed1e82bd22db1301a8c11d6ee6e",
        "LoD/1.09b": "2dbd2ed1e82bd22db1301a8c11d6ee6e",
        "LoD/1.09d": "2dbd2ed1e82bd22db1301a8c11d6ee6e",
        "LoD/1.10": "2dbd2ed1e82bd22db1301a8c11d6ee6e",
        "LoD/1.11": "3eac90692de3b7c4393f1c737342792a",
        "LoD/1.11b": "309c7651d80129250d0c2018c96c4c58",
        "LoD/1.12a": "309c7651d80129250d0c2018c96c4c58",
        "LoD/1.13c": "309c7651d80129250d0c2018c96c4c58",
        "LoD/1.13d": "309c7651d80129250d0c2018c96c4c58"
      }
    },
    "d2mcpclient.dll_EXP_10003": {
      "addresses": {
        "LoD/1.07": "0x6FA51AB0",
        "LoD/1.08": "0x6FA51AB0",
        "LoD/1.09": "0x6F9F1AB0",
        "LoD/1.09b": "0x6F9F1AB0",
        "LoD/1.09d": "0x6F9F1AB0",
        "LoD/1.10": "0x6F9F1A20",
        "LoD/1.11": "0x6FA26A90",
        "LoD/1.11b": "0x6FA27230",
        "LoD/1.12a": "0x6FA26420",
        "LoD/1.13c": "0x6FA27290",
        "LoD/1.13d": "0x6FA26AA0"
      },
      "rvas": {
        "LoD/1.07": "0x1AB0",
        "LoD/1.08": "0x1AB0",
        "LoD/1.09": "0x1AB0",
        "LoD/1.09b": "0x1AB0",
        "LoD/1.09d": "0x1AB0",
        "LoD/1.10": "0x1A20",
        "LoD/1.11": "0x6A90",
        "LoD/1.11b": "0x7230",
        "LoD/1.12a": "0x6420",
        "LoD/1.13c": "0x7290",
        "LoD/1.13d": "0x6AA0"
      },
      "sizes": {
        "LoD/1.07": 72,
        "LoD/1.08": 72,
        "LoD/1.09": 72,
        "LoD/1.09b": 72,
        "LoD/1.09d": 72,
        "LoD/1.10": 72,
        "LoD/1.11": 155,
        "LoD/1.11b": 155,
        "LoD/1.12a": 155,
        "LoD/1.13c": 155,
        "LoD/1.13d": 155
      },
      "name": "Ordinal_10003",
      "signature": "undefined4 Ordinal_10003(void)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.07",
      "method": "EXP",
      "index": "EXP:10003",
      "callees": {
        "LoD/1.07": [
          "DequeueQueueData"
        ],
        "LoD/1.08": [
          "DequeueQueueData"
        ],
        "LoD/1.09": [
          "DequeueQueueData"
        ],
        "LoD/1.09b": [
          "DequeueQueueData"
        ],
        "LoD/1.09d": [
          "DequeueQueueData"
        ],
        "LoD/1.10": [
          "Ordinal_10072"
        ],
        "LoD/1.11": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "Ordinal_10070"
        ],
        "LoD/1.11b": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "Ordinal_10070"
        ],
        "LoD/1.12a": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "EncodeBufferWithContext"
        ],
        "LoD/1.13c": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "EncodeBufferWithContext"
        ],
        "LoD/1.13d": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "EncodeBufferWithContext"
        ]
      },
      "basic_block_counts": {
        "LoD/1.07": 5,
        "LoD/1.08": 5,
        "LoD/1.09": 5,
        "LoD/1.09b": 5,
        "LoD/1.09d": 5,
        "LoD/1.10": 5,
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
        "LoD/1.07": "0d83dc1309904626927bc8cf60c69015",
        "LoD/1.08": "0d83dc1309904626927bc8cf60c69015",
        "LoD/1.09": "0d83dc1309904626927bc8cf60c69015",
        "LoD/1.09b": "0d83dc1309904626927bc8cf60c69015",
        "LoD/1.09d": "0d83dc1309904626927bc8cf60c69015",
        "LoD/1.10": "0d83dc1309904626927bc8cf60c69015",
        "LoD/1.11": "1d9fe6cac55852aa195a26f9722bc17e",
        "LoD/1.11b": "1d9fe6cac55852aa195a26f9722bc17e",
        "LoD/1.12a": "1d9fe6cac55852aa195a26f9722bc17e",
        "LoD/1.13c": "1d9fe6cac55852aa195a26f9722bc17e",
        "LoD/1.13d": "1d9fe6cac55852aa195a26f9722bc17e"
      }
    },
    "d2mcpclient.dll_EXP_10015": {
      "addresses": {
        "LoD/1.07": "0x6FA51B00",
        "LoD/1.08": "0x6FA51B00",
        "LoD/1.09": "0x6F9F1B00",
        "LoD/1.09b": "0x6F9F1B00",
        "LoD/1.09d": "0x6F9F1B00",
        "LoD/1.10": "0x6F9F1C00",
        "LoD/1.11": "0x6FA25FF0",
        "LoD/1.11b": "0x6FA26790",
        "LoD/1.12a": "0x6FA27150",
        "LoD/1.13c": "0x6FA267F0",
        "LoD/1.13d": "0x6FA26190"
      },
      "rvas": {
        "LoD/1.07": "0x1B00",
        "LoD/1.08": "0x1B00",
        "LoD/1.09": "0x1B00",
        "LoD/1.09b": "0x1B00",
        "LoD/1.09d": "0x1B00",
        "LoD/1.10": "0x1C00",
        "LoD/1.11": "0x5FF0",
        "LoD/1.11b": "0x6790",
        "LoD/1.12a": "0x7150",
        "LoD/1.13c": "0x67F0",
        "LoD/1.13d": "0x6190"
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
      "name": "Ordinal_10015",
      "signature": "undefined * Ordinal_10015(void)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.07",
      "method": "EXP",
      "index": "EXP:10015",
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
        "LoD/1.07": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.08": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.09": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.09b": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.09d": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.10": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.11": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.11b": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.12a": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.13c": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.13d": "7b4de9f0cf357b113d12e0c7e214792b"
      }
    },
    "d2mcpclient.dll_EXP_10016": {
      "addresses": {
        "LoD/1.07": "0x6FA51B10",
        "LoD/1.08": "0x6FA51B10",
        "LoD/1.09": "0x6F9F1B10",
        "LoD/1.09b": "0x6F9F1B10",
        "LoD/1.09d": "0x6F9F1B10",
        "LoD/1.10": "0x6F9F1A80",
        "LoD/1.11": "0x6FA26170",
        "LoD/1.11b": "0x6FA26910",
        "LoD/1.12a": "0x6FA272D0",
        "LoD/1.13c": "0x6FA26970",
        "LoD/1.13d": "0x6FA26180"
      },
      "rvas": {
        "LoD/1.07": "0x1B10",
        "LoD/1.08": "0x1B10",
        "LoD/1.09": "0x1B10",
        "LoD/1.09b": "0x1B10",
        "LoD/1.09d": "0x1B10",
        "LoD/1.10": "0x1A80",
        "LoD/1.11": "0x6170",
        "LoD/1.11b": "0x6910",
        "LoD/1.12a": "0x72D0",
        "LoD/1.13c": "0x6970",
        "LoD/1.13d": "0x6180"
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
      "name": "Ordinal_10016",
      "signature": "undefined2 Ordinal_10016(void)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.07",
      "method": "EXP",
      "index": "EXP:10016",
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
        "LoD/1.07": "305c32d33191c1b22ce2562362c5fa24",
        "LoD/1.08": "305c32d33191c1b22ce2562362c5fa24",
        "LoD/1.09": "305c32d33191c1b22ce2562362c5fa24",
        "LoD/1.09b": "305c32d33191c1b22ce2562362c5fa24",
        "LoD/1.09d": "305c32d33191c1b22ce2562362c5fa24",
        "LoD/1.10": "305c32d33191c1b22ce2562362c5fa24",
        "LoD/1.11": "305c32d33191c1b22ce2562362c5fa24",
        "LoD/1.11b": "305c32d33191c1b22ce2562362c5fa24",
        "LoD/1.12a": "305c32d33191c1b22ce2562362c5fa24",
        "LoD/1.13c": "305c32d33191c1b22ce2562362c5fa24",
        "LoD/1.13d": "305c32d33191c1b22ce2562362c5fa24"
      }
    },
    "d2mcpclient.dll_EXP_10017": {
      "addresses": {
        "LoD/1.07": "0x6FA51B20",
        "LoD/1.08": "0x6FA51B20",
        "LoD/1.09": "0x6F9F1B20",
        "LoD/1.09b": "0x6F9F1B20",
        "LoD/1.09d": "0x6F9F1BB0",
        "LoD/1.10": "0x6F9F1A90",
        "LoD/1.11": "0x6FA25F30",
        "LoD/1.11b": "0x6FA266D0",
        "LoD/1.12a": "0x6FA27090",
        "LoD/1.13c": "0x6FA26730",
        "LoD/1.13d": "0x6FA26240"
      },
      "rvas": {
        "LoD/1.07": "0x1B20",
        "LoD/1.08": "0x1B20",
        "LoD/1.09": "0x1B20",
        "LoD/1.09b": "0x1B20",
        "LoD/1.09d": "0x1BB0",
        "LoD/1.10": "0x1A90",
        "LoD/1.11": "0x5F30",
        "LoD/1.11b": "0x66D0",
        "LoD/1.12a": "0x7090",
        "LoD/1.13c": "0x6730",
        "LoD/1.13d": "0x6240"
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
      "name": "Ordinal_10017",
      "signature": "undefined4 Ordinal_10017(void)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.07",
      "method": "EXP",
      "index": "EXP:10017",
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
        "LoD/1.07": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.08": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.09": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.09b": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.09d": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.10": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.11": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.11b": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.12a": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.13c": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.13d": "7b4de9f0cf357b113d12e0c7e214792b"
      }
    },
    "d2mcpclient.dll_EXP_10047": {
      "addresses": {
        "LoD/1.07": "0x6FA51B30",
        "LoD/1.08": "0x6FA51B30",
        "LoD/1.09": "0x6F9F1B30",
        "LoD/1.09b": "0x6F9F1B30",
        "LoD/1.09d": "0x6F9F1B30",
        "LoD/1.10": "0x6F9F1AA0",
        "LoD/1.11": "0x6FA269D0",
        "LoD/1.11b": "0x6FA27170",
        "LoD/1.12a": "0x6FA26360"
      },
      "rvas": {
        "LoD/1.07": "0x1B30",
        "LoD/1.08": "0x1B30",
        "LoD/1.09": "0x1B30",
        "LoD/1.09b": "0x1B30",
        "LoD/1.09d": "0x1B30",
        "LoD/1.10": "0x1AA0",
        "LoD/1.11": "0x69D0",
        "LoD/1.11b": "0x7170",
        "LoD/1.12a": "0x6360"
      },
      "sizes": {
        "LoD/1.07": 12,
        "LoD/1.08": 12,
        "LoD/1.09": 12,
        "LoD/1.09b": 12,
        "LoD/1.09d": 12,
        "LoD/1.10": 12,
        "LoD/1.11": 86,
        "LoD/1.11b": 86,
        "LoD/1.12a": 86
      },
      "name": "Ordinal_10047",
      "signature": "undefined Ordinal_10047(undefined4 param_1)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.07",
      "method": "EXP",
      "index": "EXP:10047",
      "callees": {
        "LoD/1.11": [
          "Ordinal_10070"
        ],
        "LoD/1.11b": [
          "Ordinal_10070"
        ],
        "LoD/1.12a": [
          "EncodeBufferWithContext"
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
        "LoD/1.12a": 1
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
        "LoD/1.12a": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.08": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.09": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.09b": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.09d": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.10": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.11": "566dda4133f217384fb38c1f4ca1301f",
        "LoD/1.11b": "566dda4133f217384fb38c1f4ca1301f",
        "LoD/1.12a": "566dda4133f217384fb38c1f4ca1301f"
      }
    },
    "d2mcpclient.dll_EXP_10046": {
      "addresses": {
        "LoD/1.07": "0x6FA51B40",
        "LoD/1.08": "0x6FA51B40",
        "LoD/1.09": "0x6F9F1D00",
        "LoD/1.09b": "0x6F9F1D00",
        "LoD/1.09d": "0x6F9F1850",
        "LoD/1.10": "0x6F9F1AE0",
        "LoD/1.11": "0x6FA260F0",
        "LoD/1.11b": "0x6FA26890",
        "LoD/1.12a": "0x6FA27250",
        "LoD/1.13c": "0x6FA268F0",
        "LoD/1.13d": "0x6FA25F60"
      },
      "rvas": {
        "LoD/1.07": "0x1B40",
        "LoD/1.08": "0x1B40",
        "LoD/1.09": "0x1D00",
        "LoD/1.09b": "0x1D00",
        "LoD/1.09d": "0x1850",
        "LoD/1.10": "0x1AE0",
        "LoD/1.11": "0x60F0",
        "LoD/1.11b": "0x6890",
        "LoD/1.12a": "0x7250",
        "LoD/1.13c": "0x68F0",
        "LoD/1.13d": "0x5F60"
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
      "name": "Ordinal_10046",
      "signature": "undefined4 Ordinal_10046(void)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.07",
      "method": "EXP",
      "index": "EXP:10046",
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
        "LoD/1.07": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.08": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.09": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.09b": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.09d": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.10": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.11": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.11b": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.12a": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.13c": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.13d": "7b4de9f0cf357b113d12e0c7e214792b"
      }
    },
    "d2mcpclient.dll_EXP_10029": {
      "addresses": {
        "LoD/1.07": "0x6FA51B50",
        "LoD/1.08": "0x6FA51B50",
        "LoD/1.09": "0x6F9F1BB0",
        "LoD/1.09b": "0x6F9F1BB0",
        "LoD/1.09d": "0x6F9F1D20",
        "LoD/1.10": "0x6F9F1AC0",
        "LoD/1.11": "0x6FA25FA0",
        "LoD/1.11b": "0x6FA26740",
        "LoD/1.12a": "0x6FA27100",
        "LoD/1.13c": "0x6FA267A0",
        "LoD/1.13d": "0x6FA25FD0"
      },
      "rvas": {
        "LoD/1.07": "0x1B50",
        "LoD/1.08": "0x1B50",
        "LoD/1.09": "0x1BB0",
        "LoD/1.09b": "0x1BB0",
        "LoD/1.09d": "0x1D20",
        "LoD/1.10": "0x1AC0",
        "LoD/1.11": "0x5FA0",
        "LoD/1.11b": "0x6740",
        "LoD/1.12a": "0x7100",
        "LoD/1.13c": "0x67A0",
        "LoD/1.13d": "0x5FD0"
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
      "name": "Ordinal_10029",
      "signature": "undefined4 Ordinal_10029(void)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.07",
      "method": "EXP",
      "index": "EXP:10029",
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
        "LoD/1.07": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.08": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.09": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.09b": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.09d": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.10": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.11": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.11b": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.12a": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.13c": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.13d": "7b4de9f0cf357b113d12e0c7e214792b"
      }
    },
    "d2mcpclient.dll_EXP_10028": {
      "addresses": {
        "LoD/1.07": "0x6FA51B60",
        "LoD/1.08": "0x6FA51B60",
        "LoD/1.09": "0x6F9F1BD0",
        "LoD/1.09b": "0x6F9F1BD0",
        "LoD/1.09d": "0x6F9F1B60",
        "LoD/1.10": "0x6F9F1D00",
        "LoD/1.11": "0x6FA25FB0",
        "LoD/1.11b": "0x6FA26750",
        "LoD/1.12a": "0x6FA27110",
        "LoD/1.13c": "0x6FA267B0",
        "LoD/1.13d": "0x6FA26090"
      },
      "rvas": {
        "LoD/1.07": "0x1B60",
        "LoD/1.08": "0x1B60",
        "LoD/1.09": "0x1BD0",
        "LoD/1.09b": "0x1BD0",
        "LoD/1.09d": "0x1B60",
        "LoD/1.10": "0x1D00",
        "LoD/1.11": "0x5FB0",
        "LoD/1.11b": "0x6750",
        "LoD/1.12a": "0x7110",
        "LoD/1.13c": "0x67B0",
        "LoD/1.13d": "0x6090"
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
      "name": "Ordinal_10028",
      "signature": "undefined Ordinal_10028(undefined4 param_1)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.07",
      "method": "EXP",
      "index": "EXP:10028",
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
        "LoD/1.07": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.08": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.09": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.09b": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.09d": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.10": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.11": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.11b": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.12a": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.13c": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.13d": "0f26f5ebbb6562741331dd6e6bdd0342"
      }
    },
    "d2mcpclient.dll_EXP_10031": {
      "addresses": {
        "LoD/1.07": "0x6FA51B70",
        "LoD/1.08": "0x6FA51B70",
        "LoD/1.09": "0x6F9F1BE0",
        "LoD/1.09b": "0x6F9F1BE0",
        "LoD/1.09d": "0x6F9F1DE0",
        "LoD/1.10": "0x6F9F1D10",
        "LoD/1.11": "0x6FA25FC0",
        "LoD/1.11b": "0x6FA26760",
        "LoD/1.12a": "0x6FA27120",
        "LoD/1.13c": "0x6FA267C0",
        "LoD/1.13d": "0x6FA260A0"
      },
      "rvas": {
        "LoD/1.07": "0x1B70",
        "LoD/1.08": "0x1B70",
        "LoD/1.09": "0x1BE0",
        "LoD/1.09b": "0x1BE0",
        "LoD/1.09d": "0x1DE0",
        "LoD/1.10": "0x1D10",
        "LoD/1.11": "0x5FC0",
        "LoD/1.11b": "0x6760",
        "LoD/1.12a": "0x7120",
        "LoD/1.13c": "0x67C0",
        "LoD/1.13d": "0x60A0"
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
      "name": "Ordinal_10031",
      "signature": "undefined4 Ordinal_10031(void)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.07",
      "method": "EXP",
      "index": "EXP:10031",
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
        "LoD/1.07": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.08": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.09": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.09b": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.09d": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.10": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.11": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.11b": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.12a": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.13c": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.13d": "7b4de9f0cf357b113d12e0c7e214792b"
      }
    },
    "d2mcpclient.dll_EXP_10030": {
      "addresses": {
        "LoD/1.07": "0x6FA51B80",
        "LoD/1.08": "0x6FA51B80",
        "LoD/1.09": "0x6F9F1C00",
        "LoD/1.09b": "0x6F9F1C00",
        "LoD/1.09d": "0x6F9F1DB0",
        "LoD/1.10": "0x6F9F1C60",
        "LoD/1.11": "0x6FA26120",
        "LoD/1.11b": "0x6FA268C0",
        "LoD/1.12a": "0x6FA27280",
        "LoD/1.13c": "0x6FA26920",
        "LoD/1.13d": "0x6FA26110"
      },
      "rvas": {
        "LoD/1.07": "0x1B80",
        "LoD/1.08": "0x1B80",
        "LoD/1.09": "0x1C00",
        "LoD/1.09b": "0x1C00",
        "LoD/1.09d": "0x1DB0",
        "LoD/1.10": "0x1C60",
        "LoD/1.11": "0x6120",
        "LoD/1.11b": "0x68C0",
        "LoD/1.12a": "0x7280",
        "LoD/1.13c": "0x6920",
        "LoD/1.13d": "0x6110"
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
      "name": "Ordinal_10030",
      "signature": "undefined Ordinal_10030(undefined4 param_1)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.07",
      "method": "EXP",
      "index": "EXP:10030",
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
        "LoD/1.07": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.08": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.09": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.09b": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.09d": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.10": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.11": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.11b": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.12a": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.13c": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.13d": "0f26f5ebbb6562741331dd6e6bdd0342"
      }
    },
    "d2mcpclient.dll_EXP_10033": {
      "addresses": {
        "LoD/1.07": "0x6FA51B90",
        "LoD/1.08": "0x6FA51B90",
        "LoD/1.09": "0x6F9F1B90",
        "LoD/1.09b": "0x6F9F1B90",
        "LoD/1.09d": "0x6F9F1B50",
        "LoD/1.10": "0x6F9F1B20",
        "LoD/1.11": "0x6FA26140",
        "LoD/1.11b": "0x6FA268E0",
        "LoD/1.12a": "0x6FA272A0",
        "LoD/1.13c": "0x6FA26940",
        "LoD/1.13d": "0x6FA26170"
      },
      "rvas": {
        "LoD/1.07": "0x1B90",
        "LoD/1.08": "0x1B90",
        "LoD/1.09": "0x1B90",
        "LoD/1.09b": "0x1B90",
        "LoD/1.09d": "0x1B50",
        "LoD/1.10": "0x1B20",
        "LoD/1.11": "0x6140",
        "LoD/1.11b": "0x68E0",
        "LoD/1.12a": "0x72A0",
        "LoD/1.13c": "0x6940",
        "LoD/1.13d": "0x6170"
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
      "name": "Ordinal_10033",
      "signature": "undefined4 Ordinal_10033(void)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.07",
      "method": "EXP",
      "index": "EXP:10033",
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
        "LoD/1.07": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.08": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.09": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.09b": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.09d": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.10": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.11": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.11b": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.12a": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.13c": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.13d": "7b4de9f0cf357b113d12e0c7e214792b"
      }
    },
    "d2mcpclient.dll_EXP_10032": {
      "addresses": {
        "LoD/1.07": "0x6FA51BA0",
        "LoD/1.08": "0x6FA51BA0",
        "LoD/1.09": "0x6F9F1B80",
        "LoD/1.09b": "0x6F9F1B80",
        "LoD/1.09d": "0x6F9F1BD0",
        "LoD/1.10": "0x6F9F1AD0",
        "LoD/1.11": "0x6FA25F40",
        "LoD/1.11b": "0x6FA266E0",
        "LoD/1.12a": "0x6FA270A0",
        "LoD/1.13c": "0x6FA26740",
        "LoD/1.13d": "0x6FA26160"
      },
      "rvas": {
        "LoD/1.07": "0x1BA0",
        "LoD/1.08": "0x1BA0",
        "LoD/1.09": "0x1B80",
        "LoD/1.09b": "0x1B80",
        "LoD/1.09d": "0x1BD0",
        "LoD/1.10": "0x1AD0",
        "LoD/1.11": "0x5F40",
        "LoD/1.11b": "0x66E0",
        "LoD/1.12a": "0x70A0",
        "LoD/1.13c": "0x6740",
        "LoD/1.13d": "0x6160"
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
      "name": "Ordinal_10032",
      "signature": "undefined Ordinal_10032(undefined4 param_1)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.07",
      "method": "EXP",
      "index": "EXP:10032",
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
        "LoD/1.07": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.08": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.09": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.09b": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.09d": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.10": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.11": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.11b": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.12a": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.13c": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.13d": "0f26f5ebbb6562741331dd6e6bdd0342"
      }
    },
    "d2mcpclient.dll_EXP_10061": {
      "addresses": {
        "LoD/1.07": "0x6FA51BB0",
        "LoD/1.08": "0x6FA51BB0",
        "LoD/1.09": "0x6F9F1B50",
        "LoD/1.09b": "0x6F9F1B50",
        "LoD/1.09d": "0x6F9F1D00",
        "LoD/1.10": "0x6F9F1AB0",
        "LoD/1.11": "0x6FA260A0",
        "LoD/1.11b": "0x6FA26840",
        "LoD/1.12a": "0x6FA27200",
        "LoD/1.13c": "0x6FA268A0",
        "LoD/1.13d": "0x6FA25F90"
      },
      "rvas": {
        "LoD/1.07": "0x1BB0",
        "LoD/1.08": "0x1BB0",
        "LoD/1.09": "0x1B50",
        "LoD/1.09b": "0x1B50",
        "LoD/1.09d": "0x1D00",
        "LoD/1.10": "0x1AB0",
        "LoD/1.11": "0x60A0",
        "LoD/1.11b": "0x6840",
        "LoD/1.12a": "0x7200",
        "LoD/1.13c": "0x68A0",
        "LoD/1.13d": "0x5F90"
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
      "name": "Ordinal_10061",
      "signature": "undefined4 Ordinal_10061(void)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.07",
      "method": "EXP",
      "index": "EXP:10061",
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
        "LoD/1.07": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.08": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.09": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.09b": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.09d": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.10": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.11": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.11b": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.12a": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.13c": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.13d": "7b4de9f0cf357b113d12e0c7e214792b"
      }
    },
    "d2mcpclient.dll_EXP_10060": {
      "addresses": {
        "LoD/1.07": "0x6FA51BC0",
        "LoD/1.08": "0x6FA51BC0",
        "LoD/1.09": "0x6F9F1B60",
        "LoD/1.09b": "0x6F9F1B60",
        "LoD/1.09d": "0x6F9F1D10",
        "LoD/1.10": "0x6F9F1B10",
        "LoD/1.11": "0x6FA25F20",
        "LoD/1.11b": "0x6FA266C0",
        "LoD/1.12a": "0x6FA27080",
        "LoD/1.13c": "0x6FA26720",
        "LoD/1.13d": "0x6FA25F80"
      },
      "rvas": {
        "LoD/1.07": "0x1BC0",
        "LoD/1.08": "0x1BC0",
        "LoD/1.09": "0x1B60",
        "LoD/1.09b": "0x1B60",
        "LoD/1.09d": "0x1D10",
        "LoD/1.10": "0x1B10",
        "LoD/1.11": "0x5F20",
        "LoD/1.11b": "0x66C0",
        "LoD/1.12a": "0x7080",
        "LoD/1.13c": "0x6720",
        "LoD/1.13d": "0x5F80"
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
      "name": "Ordinal_10060",
      "signature": "undefined Ordinal_10060(undefined4 param_1)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.07",
      "method": "EXP",
      "index": "EXP:10060",
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
        "LoD/1.07": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.08": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.09": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.09b": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.09d": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.10": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.11": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.11b": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.12a": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.13c": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.13d": "0f26f5ebbb6562741331dd6e6bdd0342"
      }
    },
    "d2mcpclient.dll_EXP_10034": {
      "addresses": {
        "LoD/1.07": "0x6FA51BD0",
        "LoD/1.08": "0x6FA51BD0",
        "LoD/1.09": "0x6F9F1DB0",
        "LoD/1.09b": "0x6F9F1DB0",
        "LoD/1.09d": "0x6F9F1D30",
        "LoD/1.10": "0x6F9F1AF0",
        "LoD/1.11": "0x6FA25F90",
        "LoD/1.11b": "0x6FA26730",
        "LoD/1.12a": "0x6FA270F0",
        "LoD/1.13c": "0x6FA26790",
        "LoD/1.13d": "0x6FA260D0"
      },
      "rvas": {
        "LoD/1.07": "0x1BD0",
        "LoD/1.08": "0x1BD0",
        "LoD/1.09": "0x1DB0",
        "LoD/1.09b": "0x1DB0",
        "LoD/1.09d": "0x1D30",
        "LoD/1.10": "0x1AF0",
        "LoD/1.11": "0x5F90",
        "LoD/1.11b": "0x6730",
        "LoD/1.12a": "0x70F0",
        "LoD/1.13c": "0x6790",
        "LoD/1.13d": "0x60D0"
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
      "name": "Ordinal_10034",
      "signature": "undefined Ordinal_10034(undefined4 param_1)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.07",
      "method": "EXP",
      "index": "EXP:10034",
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
        "LoD/1.07": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.08": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.09": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.09b": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.09d": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.10": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.11": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.11b": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.12a": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.13c": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.13d": "0f26f5ebbb6562741331dd6e6bdd0342"
      }
    },
    "d2mcpclient.dll_EXP_10035": {
      "addresses": {
        "LoD/1.07": "0x6FA51BE0",
        "LoD/1.08": "0x6FA51BE0",
        "LoD/1.09": "0x6F9F1D20",
        "LoD/1.09b": "0x6F9F1D20",
        "LoD/1.09d": "0x6F9F1B40",
        "LoD/1.10": "0x6F9F1C70",
        "LoD/1.11": "0x6FA25F50",
        "LoD/1.11b": "0x6FA266F0",
        "LoD/1.12a": "0x6FA270B0",
        "LoD/1.13c": "0x6FA26750",
        "LoD/1.13d": "0x6FA25F70"
      },
      "rvas": {
        "LoD/1.07": "0x1BE0",
        "LoD/1.08": "0x1BE0",
        "LoD/1.09": "0x1D20",
        "LoD/1.09b": "0x1D20",
        "LoD/1.09d": "0x1B40",
        "LoD/1.10": "0x1C70",
        "LoD/1.11": "0x5F50",
        "LoD/1.11b": "0x66F0",
        "LoD/1.12a": "0x70B0",
        "LoD/1.13c": "0x6750",
        "LoD/1.13d": "0x5F70"
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
      "name": "Ordinal_10035",
      "signature": "undefined4 Ordinal_10035(void)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.07",
      "method": "EXP",
      "index": "EXP:10035",
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
        "LoD/1.07": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.08": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.09": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.09b": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.09d": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.10": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.11": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.11b": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.12a": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.13c": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.13d": "7b4de9f0cf357b113d12e0c7e214792b"
      }
    },
    "d2mcpclient.dll_EXP_10037": {
      "addresses": {
        "LoD/1.07": "0x6FA51BF0",
        "LoD/1.08": "0x6FA51BF0",
        "LoD/1.09": "0x6F9F1DE0",
        "LoD/1.09b": "0x6F9F1DE0",
        "LoD/1.09d": "0x6F9F1DC0",
        "LoD/1.10": "0x6F9F1C50",
        "LoD/1.11": "0x6FA26130",
        "LoD/1.11b": "0x6FA268D0",
        "LoD/1.12a": "0x6FA27290",
        "LoD/1.13c": "0x6FA26930",
        "LoD/1.13d": "0x6FA26120"
      },
      "rvas": {
        "LoD/1.07": "0x1BF0",
        "LoD/1.08": "0x1BF0",
        "LoD/1.09": "0x1DE0",
        "LoD/1.09b": "0x1DE0",
        "LoD/1.09d": "0x1DC0",
        "LoD/1.10": "0x1C50",
        "LoD/1.11": "0x6130",
        "LoD/1.11b": "0x68D0",
        "LoD/1.12a": "0x7290",
        "LoD/1.13c": "0x6930",
        "LoD/1.13d": "0x6120"
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
      "name": "Ordinal_10037",
      "signature": "undefined4 Ordinal_10037(void)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.07",
      "method": "EXP",
      "index": "EXP:10037",
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
        "LoD/1.07": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.08": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.09": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.09b": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.09d": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.10": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.11": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.11b": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.12a": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.13c": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.13d": "7b4de9f0cf357b113d12e0c7e214792b"
      }
    },
    "d2mcpclient.dll_EXP_10036": {
      "addresses": {
        "LoD/1.07": "0x6FA51C00",
        "LoD/1.08": "0x6FA51C00",
        "LoD/1.09": "0x6F9F1D50",
        "LoD/1.09b": "0x6F9F1D50",
        "LoD/1.09d": "0x6F9F1BA0",
        "LoD/1.10": "0x6F9F1B70",
        "LoD/1.11": "0x6FA26150",
        "LoD/1.11b": "0x6FA268F0",
        "LoD/1.12a": "0x6FA272B0",
        "LoD/1.13c": "0x6FA26950",
        "LoD/1.13d": "0x6FA25FA0"
      },
      "rvas": {
        "LoD/1.07": "0x1C00",
        "LoD/1.08": "0x1C00",
        "LoD/1.09": "0x1D50",
        "LoD/1.09b": "0x1D50",
        "LoD/1.09d": "0x1BA0",
        "LoD/1.10": "0x1B70",
        "LoD/1.11": "0x6150",
        "LoD/1.11b": "0x68F0",
        "LoD/1.12a": "0x72B0",
        "LoD/1.13c": "0x6950",
        "LoD/1.13d": "0x5FA0"
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
      "name": "Ordinal_10036",
      "signature": "undefined Ordinal_10036(undefined4 param_1)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.07",
      "method": "EXP",
      "index": "EXP:10036",
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
        "LoD/1.07": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.08": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.09": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.09b": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.09d": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.10": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.11": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.11b": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.12a": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.13c": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.13d": "0f26f5ebbb6562741331dd6e6bdd0342"
      }
    },
    "d2mcpclient.dll_EXP_10038": {
      "addresses": {
        "LoD/1.07": "0x6FA51C10",
        "LoD/1.08": "0x6FA51C10",
        "LoD/1.09": "0x6F9F1C10",
        "LoD/1.09b": "0x6F9F1C10",
        "LoD/1.09d": "0x6F9F1C10",
        "LoD/1.10": "0x6F9F1B80",
        "LoD/1.11": "0x6FA26660",
        "LoD/1.11b": "0x6FA26E00"
      },
      "rvas": {
        "LoD/1.07": "0x1C10",
        "LoD/1.08": "0x1C10",
        "LoD/1.09": "0x1C10",
        "LoD/1.09b": "0x1C10",
        "LoD/1.09d": "0x1C10",
        "LoD/1.10": "0x1B80",
        "LoD/1.11": "0x6660",
        "LoD/1.11b": "0x6E00"
      },
      "sizes": {
        "LoD/1.07": 84,
        "LoD/1.08": 84,
        "LoD/1.09": 84,
        "LoD/1.09b": 84,
        "LoD/1.09d": 84,
        "LoD/1.10": 50,
        "LoD/1.11": 86,
        "LoD/1.11b": 86
      },
      "name": "Ordinal_10038",
      "signature": "undefined4 Ordinal_10038(char * param_1, char * param_2)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.07",
      "method": "EXP",
      "index": "EXP:10038",
      "callees": {
        "LoD/1.11": [
          "CopyMemoryAndDetectTerminator",
          "CalculateStringLength",
          "Ordinal_10070"
        ],
        "LoD/1.11b": [
          "CopyMemoryAndDetectTerminator",
          "CalculateStringLength",
          "Ordinal_10070"
        ]
      },
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 5,
        "LoD/1.11": 1,
        "LoD/1.11b": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0,
        "LoD/1.11b": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "171b6bc36cab64635d8bb9c9798ae851",
        "LoD/1.08": "171b6bc36cab64635d8bb9c9798ae851",
        "LoD/1.09": "171b6bc36cab64635d8bb9c9798ae851",
        "LoD/1.09b": "171b6bc36cab64635d8bb9c9798ae851",
        "LoD/1.09d": "171b6bc36cab64635d8bb9c9798ae851",
        "LoD/1.10": "38de582ad1c61cab1222e52523047258",
        "LoD/1.11": "3b3ba9dbeb1bcd03134b7287059a3981",
        "LoD/1.11b": "3b3ba9dbeb1bcd03134b7287059a3981"
      }
    },
    "d2mcpclient.dll_EXP_10039": {
      "addresses": {
        "LoD/1.07": "0x6FA51C70",
        "LoD/1.08": "0x6FA51C70",
        "LoD/1.09": "0x6F9F1C70",
        "LoD/1.09b": "0x6F9F1C70",
        "LoD/1.09d": "0x6F9F1C70",
        "LoD/1.10": "0x6F9F1BC0",
        "LoD/1.11": "0x6FA26040",
        "LoD/1.11b": "0x6FA267E0",
        "LoD/1.12a": "0x6FA271A0",
        "LoD/1.13c": "0x6FA26840",
        "LoD/1.13d": "0x6FA26050"
      },
      "rvas": {
        "LoD/1.07": "0x1C70",
        "LoD/1.08": "0x1C70",
        "LoD/1.09": "0x1C70",
        "LoD/1.09b": "0x1C70",
        "LoD/1.09d": "0x1C70",
        "LoD/1.10": "0x1BC0",
        "LoD/1.11": "0x6040",
        "LoD/1.11b": "0x67E0",
        "LoD/1.12a": "0x71A0",
        "LoD/1.13c": "0x6840",
        "LoD/1.13d": "0x6050"
      },
      "sizes": {
        "LoD/1.07": 88,
        "LoD/1.08": 88,
        "LoD/1.09": 88,
        "LoD/1.09b": 88,
        "LoD/1.09d": 88,
        "LoD/1.10": 54,
        "LoD/1.11": 52,
        "LoD/1.11b": 52,
        "LoD/1.12a": 52,
        "LoD/1.13c": 52,
        "LoD/1.13d": 52
      },
      "name": "Ordinal_10039",
      "signature": "undefined Ordinal_10039(undefined4 param_1, char * param_2, char * param_3)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.07",
      "method": "EXP",
      "index": "EXP:10039",
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
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
        "LoD/1.07": "ec911464c23705114de8601ffa5a4b34",
        "LoD/1.08": "ec911464c23705114de8601ffa5a4b34",
        "LoD/1.09": "ec911464c23705114de8601ffa5a4b34",
        "LoD/1.09b": "ec911464c23705114de8601ffa5a4b34",
        "LoD/1.09d": "ec911464c23705114de8601ffa5a4b34",
        "LoD/1.10": "a15d01049b22b51e7987fc396d2a4b4e",
        "LoD/1.11": "d7768bd3eaf7ab7bb4b918bdf52a139b",
        "LoD/1.11b": "d7768bd3eaf7ab7bb4b918bdf52a139b",
        "LoD/1.12a": "d7768bd3eaf7ab7bb4b918bdf52a139b",
        "LoD/1.13c": "d7768bd3eaf7ab7bb4b918bdf52a139b",
        "LoD/1.13d": "d7768bd3eaf7ab7bb4b918bdf52a139b"
      }
    },
    "d2mcpclient.dll_EXP_10019": {
      "addresses": {
        "LoD/1.07": "0x6FA51CD0",
        "LoD/1.08": "0x6FA51CD0",
        "LoD/1.09": "0x6F9F1CD0",
        "LoD/1.09b": "0x6F9F1CD0",
        "LoD/1.09d": "0x6F9F1CD0",
        "LoD/1.10": "0x6F9F1A70",
        "LoD/1.11": "0x6FA26180",
        "LoD/1.11b": "0x6FA26920",
        "LoD/1.12a": "0x6FA272E0",
        "LoD/1.13c": "0x6FA26980",
        "LoD/1.13d": "0x6FA26000"
      },
      "rvas": {
        "LoD/1.07": "0x1CD0",
        "LoD/1.08": "0x1CD0",
        "LoD/1.09": "0x1CD0",
        "LoD/1.09b": "0x1CD0",
        "LoD/1.09d": "0x1CD0",
        "LoD/1.10": "0x1A70",
        "LoD/1.11": "0x6180",
        "LoD/1.11b": "0x6920",
        "LoD/1.12a": "0x72E0",
        "LoD/1.13c": "0x6980",
        "LoD/1.13d": "0x6000"
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
      "name": "Ordinal_10019",
      "signature": "undefined4 * Ordinal_10019(void)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.07",
      "method": "EXP",
      "index": "EXP:10019",
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
        "LoD/1.07": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.08": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.09": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.09b": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.09d": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.10": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.11": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.11b": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.12a": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.13c": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.13d": "7b4de9f0cf357b113d12e0c7e214792b"
      }
    },
    "d2mcpclient.dll_EXP_10020": {
      "addresses": {
        "LoD/1.07": "0x6FA51CE0",
        "LoD/1.08": "0x6FA51CE0",
        "LoD/1.09": "0x6F9F1CE0",
        "LoD/1.09b": "0x6F9F1CE0",
        "LoD/1.09d": "0x6F9F1CE0",
        "LoD/1.10": "0x6F9F1C10",
        "LoD/1.11": "0x6FA25FD0",
        "LoD/1.11b": "0x6FA26770",
        "LoD/1.12a": "0x6FA27130",
        "LoD/1.13c": "0x6FA267D0",
        "LoD/1.13d": "0x6FA25FE0"
      },
      "rvas": {
        "LoD/1.07": "0x1CE0",
        "LoD/1.08": "0x1CE0",
        "LoD/1.09": "0x1CE0",
        "LoD/1.09b": "0x1CE0",
        "LoD/1.09d": "0x1CE0",
        "LoD/1.10": "0x1C10",
        "LoD/1.11": "0x5FD0",
        "LoD/1.11b": "0x6770",
        "LoD/1.12a": "0x7130",
        "LoD/1.13c": "0x67D0",
        "LoD/1.13d": "0x5FE0"
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
      "name": "Ordinal_10020",
      "signature": "undefined Ordinal_10020(void)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.07",
      "method": "EXP",
      "index": "EXP:10020",
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
        "LoD/1.07": "57f9ec64af4be3e0ffbc2e88bab6837a",
        "LoD/1.08": "57f9ec64af4be3e0ffbc2e88bab6837a",
        "LoD/1.09": "57f9ec64af4be3e0ffbc2e88bab6837a",
        "LoD/1.09b": "57f9ec64af4be3e0ffbc2e88bab6837a",
        "LoD/1.09d": "57f9ec64af4be3e0ffbc2e88bab6837a",
        "LoD/1.10": "57f9ec64af4be3e0ffbc2e88bab6837a",
        "LoD/1.11": "57f9ec64af4be3e0ffbc2e88bab6837a",
        "LoD/1.11b": "57f9ec64af4be3e0ffbc2e88bab6837a",
        "LoD/1.12a": "57f9ec64af4be3e0ffbc2e88bab6837a",
        "LoD/1.13c": "57f9ec64af4be3e0ffbc2e88bab6837a",
        "LoD/1.13d": "57f9ec64af4be3e0ffbc2e88bab6837a"
      }
    },
    "d2mcpclient.dll_EXP_10040": {
      "addresses": {
        "LoD/1.07": "0x6FA51D00",
        "LoD/1.08": "0x6FA51D00",
        "LoD/1.09": "0x6F9F1DA0",
        "LoD/1.09b": "0x6F9F1DA0",
        "LoD/1.09d": "0x6F9F1D60",
        "LoD/1.10": "0x6F9F1B60",
        "LoD/1.11": "0x6FA26110",
        "LoD/1.11b": "0x6FA268B0",
        "LoD/1.12a": "0x6FA27270",
        "LoD/1.13c": "0x6FA26910",
        "LoD/1.13d": "0x6FA25F20"
      },
      "rvas": {
        "LoD/1.07": "0x1D00",
        "LoD/1.08": "0x1D00",
        "LoD/1.09": "0x1DA0",
        "LoD/1.09b": "0x1DA0",
        "LoD/1.09d": "0x1D60",
        "LoD/1.10": "0x1B60",
        "LoD/1.11": "0x6110",
        "LoD/1.11b": "0x68B0",
        "LoD/1.12a": "0x7270",
        "LoD/1.13c": "0x6910",
        "LoD/1.13d": "0x5F20"
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
      "name": "Ordinal_10040",
      "signature": "undefined4 Ordinal_10040(void)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.07",
      "method": "EXP",
      "index": "EXP:10040",
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
        "LoD/1.07": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.08": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.09": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.09b": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.09d": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.10": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.11": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.11b": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.12a": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.13c": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.13d": "7b4de9f0cf357b113d12e0c7e214792b"
      }
    },
    "d2mcpclient.dll_EXP_10041": {
      "addresses": {
        "LoD/1.07": "0x6FA51D10",
        "LoD/1.08": "0x6FA51D10",
        "LoD/1.09": "0x6F9F1DD0",
        "LoD/1.09b": "0x6F9F1DD0",
        "LoD/1.09d": "0x6F9F1BC0",
        "LoD/1.10": "0x6F9F1C40",
        "LoD/1.11": "0x6FA260C0",
        "LoD/1.11b": "0x6FA26860",
        "LoD/1.12a": "0x6FA27220",
        "LoD/1.13c": "0x6FA268C0",
        "LoD/1.13d": "0x6FA26130"
      },
      "rvas": {
        "LoD/1.07": "0x1D10",
        "LoD/1.08": "0x1D10",
        "LoD/1.09": "0x1DD0",
        "LoD/1.09b": "0x1DD0",
        "LoD/1.09d": "0x1BC0",
        "LoD/1.10": "0x1C40",
        "LoD/1.11": "0x60C0",
        "LoD/1.11b": "0x6860",
        "LoD/1.12a": "0x7220",
        "LoD/1.13c": "0x68C0",
        "LoD/1.13d": "0x6130"
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
      "name": "Ordinal_10041",
      "signature": "undefined Ordinal_10041(undefined4 param_1)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.07",
      "method": "EXP",
      "index": "EXP:10041",
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
        "LoD/1.07": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.08": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.09": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.09b": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.09d": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.10": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.11": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.11b": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.12a": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.13c": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.13d": "0f26f5ebbb6562741331dd6e6bdd0342"
      }
    },
    "d2mcpclient.dll_EXP_10042": {
      "addresses": {
        "LoD/1.07": "0x6FA51D20",
        "LoD/1.08": "0x6FA51D20",
        "LoD/1.09": "0x6F9F1850",
        "LoD/1.09b": "0x6F9F1850",
        "LoD/1.09d": "0x6F9F1B20",
        "LoD/1.10": "0x6F9F1B00",
        "LoD/1.11": "0x6FA25F60",
        "LoD/1.11b": "0x6FA26700",
        "LoD/1.12a": "0x6FA270C0",
        "LoD/1.13c": "0x6FA26760",
        "LoD/1.13d": "0x6FA260E0"
      },
      "rvas": {
        "LoD/1.07": "0x1D20",
        "LoD/1.08": "0x1D20",
        "LoD/1.09": "0x1850",
        "LoD/1.09b": "0x1850",
        "LoD/1.09d": "0x1B20",
        "LoD/1.10": "0x1B00",
        "LoD/1.11": "0x5F60",
        "LoD/1.11b": "0x6700",
        "LoD/1.12a": "0x70C0",
        "LoD/1.13c": "0x6760",
        "LoD/1.13d": "0x60E0"
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
      "name": "Ordinal_10042",
      "signature": "undefined4 Ordinal_10042(void)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.07",
      "method": "EXP",
      "index": "EXP:10042",
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
        "LoD/1.07": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.08": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.09": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.09b": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.09d": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.10": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.11": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.11b": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.12a": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.13c": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.13d": "7b4de9f0cf357b113d12e0c7e214792b"
      }
    },
    "d2mcpclient.dll_EXP_10043": {
      "addresses": {
        "LoD/1.07": "0x6FA51D30",
        "LoD/1.08": "0x6FA51D30",
        "LoD/1.09": "0x6F9F1BA0",
        "LoD/1.09b": "0x6F9F1BA0",
        "LoD/1.09d": "0x6F9F1C00",
        "LoD/1.10": "0x6F9F1C80",
        "LoD/1.11": "0x6FA26100",
        "LoD/1.11b": "0x6FA268A0",
        "LoD/1.12a": "0x6FA27260",
        "LoD/1.13c": "0x6FA26900",
        "LoD/1.13d": "0x6FA260C0"
      },
      "rvas": {
        "LoD/1.07": "0x1D30",
        "LoD/1.08": "0x1D30",
        "LoD/1.09": "0x1BA0",
        "LoD/1.09b": "0x1BA0",
        "LoD/1.09d": "0x1C00",
        "LoD/1.10": "0x1C80",
        "LoD/1.11": "0x6100",
        "LoD/1.11b": "0x68A0",
        "LoD/1.12a": "0x7260",
        "LoD/1.13c": "0x6900",
        "LoD/1.13d": "0x60C0"
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
      "name": "Ordinal_10043",
      "signature": "undefined Ordinal_10043(undefined4 param_1)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.07",
      "method": "EXP",
      "index": "EXP:10043",
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
        "LoD/1.07": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.08": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.09": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.09b": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.09d": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.10": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.11": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.11b": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.12a": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.13c": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.13d": "0f26f5ebbb6562741331dd6e6bdd0342"
      }
    },
    "d2mcpclient.dll_EXP_10044": {
      "addresses": {
        "LoD/1.07": "0x6FA51D40",
        "LoD/1.08": "0x6FA51D40",
        "LoD/1.09": "0x6F9F1B40",
        "LoD/1.09b": "0x6F9F1B40",
        "LoD/1.09d": "0x6F9F1BE0",
        "LoD/1.10": "0x6F9F1CF0",
        "LoD/1.11": "0x6FA26090",
        "LoD/1.11b": "0x6FA26830",
        "LoD/1.12a": "0x6FA271F0",
        "LoD/1.13c": "0x6FA26890",
        "LoD/1.13d": "0x6FA26100"
      },
      "rvas": {
        "LoD/1.07": "0x1D40",
        "LoD/1.08": "0x1D40",
        "LoD/1.09": "0x1B40",
        "LoD/1.09b": "0x1B40",
        "LoD/1.09d": "0x1BE0",
        "LoD/1.10": "0x1CF0",
        "LoD/1.11": "0x6090",
        "LoD/1.11b": "0x6830",
        "LoD/1.12a": "0x71F0",
        "LoD/1.13c": "0x6890",
        "LoD/1.13d": "0x6100"
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
      "name": "Ordinal_10044",
      "signature": "undefined4 Ordinal_10044(void)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.07",
      "method": "EXP",
      "index": "EXP:10044",
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
        "LoD/1.07": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.08": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.09": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.09b": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.09d": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.10": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.11": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.11b": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.12a": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.13c": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.13d": "7b4de9f0cf357b113d12e0c7e214792b"
      }
    },
    "d2mcpclient.dll_EXP_10045": {
      "addresses": {
        "LoD/1.07": "0x6FA51D50",
        "LoD/1.08": "0x6FA51D50",
        "LoD/1.09": "0x6F9F1D30",
        "LoD/1.09b": "0x6F9F1D30",
        "LoD/1.09d": "0x6F9F1DD0",
        "LoD/1.10": "0x6F9F1B30",
        "LoD/1.11": "0x6FA26080",
        "LoD/1.11b": "0x6FA26820",
        "LoD/1.12a": "0x6FA271E0",
        "LoD/1.13c": "0x6FA26880",
        "LoD/1.13d": "0x6FA260F0"
      },
      "rvas": {
        "LoD/1.07": "0x1D50",
        "LoD/1.08": "0x1D50",
        "LoD/1.09": "0x1D30",
        "LoD/1.09b": "0x1D30",
        "LoD/1.09d": "0x1DD0",
        "LoD/1.10": "0x1B30",
        "LoD/1.11": "0x6080",
        "LoD/1.11b": "0x6820",
        "LoD/1.12a": "0x71E0",
        "LoD/1.13c": "0x6880",
        "LoD/1.13d": "0x60F0"
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
      "name": "Ordinal_10045",
      "signature": "undefined Ordinal_10045(undefined4 param_1)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.07",
      "method": "EXP",
      "index": "EXP:10045",
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
        "LoD/1.07": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.08": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.09": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.09b": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.09d": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.10": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.11": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.11b": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.12a": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.13c": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.13d": "0f26f5ebbb6562741331dd6e6bdd0342"
      }
    },
    "d2mcpclient.dll_EXP_10018": {
      "addresses": {
        "LoD/1.07": "0x6FA51D60",
        "LoD/1.08": "0x6FA51D60",
        "LoD/1.09": "0x6F9F1B70",
        "LoD/1.09b": "0x6F9F1B70",
        "LoD/1.09d": "0x6F9F1B90",
        "LoD/1.10": "0x6F9F1B50",
        "LoD/1.11": "0x6FA260D0",
        "LoD/1.11b": "0x6FA26870",
        "LoD/1.12a": "0x6FA27230",
        "LoD/1.13c": "0x6FA268D0",
        "LoD/1.13d": "0x6FA26140"
      },
      "rvas": {
        "LoD/1.07": "0x1D60",
        "LoD/1.08": "0x1D60",
        "LoD/1.09": "0x1B70",
        "LoD/1.09b": "0x1B70",
        "LoD/1.09d": "0x1B90",
        "LoD/1.10": "0x1B50",
        "LoD/1.11": "0x60D0",
        "LoD/1.11b": "0x6870",
        "LoD/1.12a": "0x7230",
        "LoD/1.13c": "0x68D0",
        "LoD/1.13d": "0x6140"
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
      "name": "Ordinal_10018",
      "signature": "undefined4 Ordinal_10018(void)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.07",
      "method": "EXP",
      "index": "EXP:10018",
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
        "LoD/1.07": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.08": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.09": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.09b": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.09d": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.10": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.11": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.11b": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.12a": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.13c": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.13d": "7b4de9f0cf357b113d12e0c7e214792b"
      }
    },
    "d2mcpclient.dll_EXP_10008": {
      "addresses": {
        "LoD/1.07": "0x6FA51D70",
        "LoD/1.08": "0x6FA51D70",
        "LoD/1.09": "0x6F9F1D70",
        "LoD/1.09b": "0x6F9F1D70",
        "LoD/1.09d": "0x6F9F1D70",
        "LoD/1.10": "0x6F9F1CA0"
      },
      "rvas": {
        "LoD/1.07": "0x1D70",
        "LoD/1.08": "0x1D70",
        "LoD/1.09": "0x1D70",
        "LoD/1.09b": "0x1D70",
        "LoD/1.09d": "0x1D70",
        "LoD/1.10": "0x1CA0"
      },
      "sizes": {
        "LoD/1.07": 21,
        "LoD/1.08": 21,
        "LoD/1.09": 21,
        "LoD/1.09b": 21,
        "LoD/1.09d": 21,
        "LoD/1.10": 21
      },
      "name": "Ordinal_10008",
      "signature": "undefined Ordinal_10008(void * param_1, undefined4 param_2, undefined2 param_3)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.07",
      "method": "EXP",
      "index": "EXP:10008",
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
        "LoD/1.07": "fa5b6dcb5f7ba0777ac210e361bcb291",
        "LoD/1.08": "fa5b6dcb5f7ba0777ac210e361bcb291",
        "LoD/1.09": "fa5b6dcb5f7ba0777ac210e361bcb291",
        "LoD/1.09b": "fa5b6dcb5f7ba0777ac210e361bcb291",
        "LoD/1.09d": "fa5b6dcb5f7ba0777ac210e361bcb291",
        "LoD/1.10": "fa5b6dcb5f7ba0777ac210e361bcb291"
      }
    },
    "d2mcpclient.dll_EXP_10009": {
      "addresses": {
        "LoD/1.07": "0x6FA51D90",
        "LoD/1.08": "0x6FA51D90",
        "LoD/1.09": "0x6F9F1D90",
        "LoD/1.09b": "0x6F9F1D90",
        "LoD/1.09d": "0x6F9F1D90",
        "LoD/1.10": "0x6F9F1CC0",
        "LoD/1.11": "0x6FA262A0",
        "LoD/1.11b": "0x6FA26A40",
        "LoD/1.12a": "0x6FA27400",
        "LoD/1.13c": "0x6FA26AA0",
        "LoD/1.13d": "0x6FA262B0"
      },
      "rvas": {
        "LoD/1.07": "0x1D90",
        "LoD/1.08": "0x1D90",
        "LoD/1.09": "0x1D90",
        "LoD/1.09b": "0x1D90",
        "LoD/1.09d": "0x1D90",
        "LoD/1.10": "0x1CC0",
        "LoD/1.11": "0x62A0",
        "LoD/1.11b": "0x6A40",
        "LoD/1.12a": "0x7400",
        "LoD/1.13c": "0x6AA0",
        "LoD/1.13d": "0x62B0"
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
      "name": "Ordinal_10009",
      "signature": "undefined Ordinal_10009(char * param_1)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.07",
      "method": "EXP",
      "index": "EXP:10009",
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
        "LoD/1.07": "fa21beffb431e943ed5fadd642c8dbd2",
        "LoD/1.08": "fa21beffb431e943ed5fadd642c8dbd2",
        "LoD/1.09": "fa21beffb431e943ed5fadd642c8dbd2",
        "LoD/1.09b": "fa21beffb431e943ed5fadd642c8dbd2",
        "LoD/1.09d": "fa21beffb431e943ed5fadd642c8dbd2",
        "LoD/1.10": "fa21beffb431e943ed5fadd642c8dbd2",
        "LoD/1.11": "fa21beffb431e943ed5fadd642c8dbd2",
        "LoD/1.11b": "fa21beffb431e943ed5fadd642c8dbd2",
        "LoD/1.12a": "fa21beffb431e943ed5fadd642c8dbd2",
        "LoD/1.13c": "fa21beffb431e943ed5fadd642c8dbd2",
        "LoD/1.13d": "fa21beffb431e943ed5fadd642c8dbd2"
      }
    },
    "d2mcpclient.dll_EXP_10050": {
      "addresses": {
        "LoD/1.07": "0x6FA51DA0",
        "LoD/1.08": "0x6FA51DA0",
        "LoD/1.09": "0x6F9F1BF0",
        "LoD/1.09b": "0x6F9F1BF0",
        "LoD/1.09d": "0x6F9F1DA0",
        "LoD/1.10": "0x6F9F1CD0",
        "LoD/1.11": "0x6FA26230",
        "LoD/1.11b": "0x6FA26A30",
        "LoD/1.12a": "0x6FA273F0",
        "LoD/1.13c": "0x6FA26A90",
        "LoD/1.13d": "0x6FA26150"
      },
      "rvas": {
        "LoD/1.07": "0x1DA0",
        "LoD/1.08": "0x1DA0",
        "LoD/1.09": "0x1BF0",
        "LoD/1.09b": "0x1BF0",
        "LoD/1.09d": "0x1DA0",
        "LoD/1.10": "0x1CD0",
        "LoD/1.11": "0x6230",
        "LoD/1.11b": "0x6A30",
        "LoD/1.12a": "0x73F0",
        "LoD/1.13c": "0x6A90",
        "LoD/1.13d": "0x6150"
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
      "name": "Ordinal_10050",
      "signature": "undefined4 Ordinal_10050(void)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.07",
      "method": "EXP",
      "index": "EXP:10050",
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
        "LoD/1.07": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.08": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.09": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.09b": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.09d": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.10": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.11": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.11b": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.12a": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.13c": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.13d": "7b4de9f0cf357b113d12e0c7e214792b"
      }
    },
    "d2mcpclient.dll_EXP_10051": {
      "addresses": {
        "LoD/1.07": "0x6FA51DB0",
        "LoD/1.08": "0x6FA51DB0",
        "LoD/1.09": "0x6F9F1D10",
        "LoD/1.09b": "0x6F9F1D10",
        "LoD/1.09d": "0x6F9F1D50",
        "LoD/1.10": "0x6F9F1CE0",
        "LoD/1.11": "0x6FA260E0",
        "LoD/1.11b": "0x6FA26880",
        "LoD/1.12a": "0x6FA27240",
        "LoD/1.13c": "0x6FA268E0",
        "LoD/1.13d": "0x6FA25F50"
      },
      "rvas": {
        "LoD/1.07": "0x1DB0",
        "LoD/1.08": "0x1DB0",
        "LoD/1.09": "0x1D10",
        "LoD/1.09b": "0x1D10",
        "LoD/1.09d": "0x1D50",
        "LoD/1.10": "0x1CE0",
        "LoD/1.11": "0x60E0",
        "LoD/1.11b": "0x6880",
        "LoD/1.12a": "0x7240",
        "LoD/1.13c": "0x68E0",
        "LoD/1.13d": "0x5F50"
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
      "name": "Ordinal_10051",
      "signature": "undefined Ordinal_10051(undefined4 param_1)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.07",
      "method": "EXP",
      "index": "EXP:10051",
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
        "LoD/1.07": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.08": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.09": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.09b": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.09d": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.10": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.11": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.11b": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.12a": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.13c": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.13d": "0f26f5ebbb6562741331dd6e6bdd0342"
      }
    },
    "d2mcpclient.dll_EXP_10052": {
      "addresses": {
        "LoD/1.07": "0x6FA51DC0",
        "LoD/1.08": "0x6FA51DC0",
        "LoD/1.09": "0x6F9F1D40",
        "LoD/1.09b": "0x6F9F1D40",
        "LoD/1.09d": "0x6F9F1B70",
        "LoD/1.10": "0x6F9F17C0",
        "LoD/1.11": "0x6FA25F80",
        "LoD/1.11b": "0x6FA26720",
        "LoD/1.12a": "0x6FA270E0",
        "LoD/1.13c": "0x6FA26780",
        "LoD/1.13d": "0x6FA25F40"
      },
      "rvas": {
        "LoD/1.07": "0x1DC0",
        "LoD/1.08": "0x1DC0",
        "LoD/1.09": "0x1D40",
        "LoD/1.09b": "0x1D40",
        "LoD/1.09d": "0x1B70",
        "LoD/1.10": "0x17C0",
        "LoD/1.11": "0x5F80",
        "LoD/1.11b": "0x6720",
        "LoD/1.12a": "0x70E0",
        "LoD/1.13c": "0x6780",
        "LoD/1.13d": "0x5F40"
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
      "name": "Ordinal_10052",
      "signature": "undefined4 Ordinal_10052(void)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.07",
      "method": "EXP",
      "index": "EXP:10052",
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
        "LoD/1.07": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.08": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.09": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.09b": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.09d": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.10": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.11": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.11b": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.12a": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.13c": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.13d": "7b4de9f0cf357b113d12e0c7e214792b"
      }
    },
    "d2mcpclient.dll_EXP_10053": {
      "addresses": {
        "LoD/1.07": "0x6FA51DD0",
        "LoD/1.08": "0x6FA51DD0",
        "LoD/1.09": "0x6F9F1BC0",
        "LoD/1.09b": "0x6F9F1BC0",
        "LoD/1.09d": "0x6F9F1B80",
        "LoD/1.10": "0x6F9F1B40",
        "LoD/1.11": "0x6FA25F70",
        "LoD/1.11b": "0x6FA26710",
        "LoD/1.12a": "0x6FA270D0",
        "LoD/1.13c": "0x6FA26770",
        "LoD/1.13d": "0x6FA25F30"
      },
      "rvas": {
        "LoD/1.07": "0x1DD0",
        "LoD/1.08": "0x1DD0",
        "LoD/1.09": "0x1BC0",
        "LoD/1.09b": "0x1BC0",
        "LoD/1.09d": "0x1B80",
        "LoD/1.10": "0x1B40",
        "LoD/1.11": "0x5F70",
        "LoD/1.11b": "0x6710",
        "LoD/1.12a": "0x70D0",
        "LoD/1.13c": "0x6770",
        "LoD/1.13d": "0x5F30"
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
      "name": "Ordinal_10053",
      "signature": "undefined Ordinal_10053(undefined4 param_1)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.07",
      "method": "EXP",
      "index": "EXP:10053",
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
        "LoD/1.07": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.08": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.09": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.09b": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.09d": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.10": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.11": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.11b": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.12a": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.13c": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.13d": "0f26f5ebbb6562741331dd6e6bdd0342"
      }
    },
    "d2mcpclient.dll_EXP_10057": {
      "addresses": {
        "LoD/1.07": "0x6FA51DE0",
        "LoD/1.08": "0x6FA51DE0",
        "LoD/1.09": "0x6F9F1DC0",
        "LoD/1.09b": "0x6F9F1DC0",
        "LoD/1.09d": "0x6F9F1D40",
        "LoD/1.10": "0x6F9F1C90",
        "LoD/1.11": "0x6FA26160",
        "LoD/1.11b": "0x6FA26900",
        "LoD/1.12a": "0x6FA272C0",
        "LoD/1.13c": "0x6FA26960",
        "LoD/1.13d": "0x6FA260B0"
      },
      "rvas": {
        "LoD/1.07": "0x1DE0",
        "LoD/1.08": "0x1DE0",
        "LoD/1.09": "0x1DC0",
        "LoD/1.09b": "0x1DC0",
        "LoD/1.09d": "0x1D40",
        "LoD/1.10": "0x1C90",
        "LoD/1.11": "0x6160",
        "LoD/1.11b": "0x6900",
        "LoD/1.12a": "0x72C0",
        "LoD/1.13c": "0x6960",
        "LoD/1.13d": "0x60B0"
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
      "name": "Ordinal_10057",
      "signature": "undefined4 Ordinal_10057(void)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.07",
      "method": "EXP",
      "index": "EXP:10057",
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
        "LoD/1.07": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.08": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.09": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.09b": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.09d": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.10": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.11": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.11b": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.12a": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.13c": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.13d": "7b4de9f0cf357b113d12e0c7e214792b"
      }
    },
    "d2mcpclient.dll_EXP_10058": {
      "addresses": {
        "LoD/1.07": "0x6FA51DF0",
        "LoD/1.08": "0x6FA51DF0",
        "LoD/1.09": "0x6F9F1DF0",
        "LoD/1.09b": "0x6F9F1DF0",
        "LoD/1.09d": "0x6F9F1DF0",
        "LoD/1.10": "0x6F9F1D20"
      },
      "rvas": {
        "LoD/1.07": "0x1DF0",
        "LoD/1.08": "0x1DF0",
        "LoD/1.09": "0x1DF0",
        "LoD/1.09b": "0x1DF0",
        "LoD/1.09d": "0x1DF0",
        "LoD/1.10": "0x1D20"
      },
      "sizes": {
        "LoD/1.07": 256,
        "LoD/1.08": 256,
        "LoD/1.09": 256,
        "LoD/1.09b": 256,
        "LoD/1.09d": 256,
        "LoD/1.10": 512
      },
      "name": "Ordinal_10058",
      "signature": "undefined Ordinal_10058(undefined4 * param_1, uint param_2)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.07",
      "method": "EXP",
      "index": "EXP:10058",
      "callees": {
        "LoD/1.07": [
          "ReleasePoolAllocation",
          "FogMemAlloc",
          "FogAssert",
          "FogAssert",
          "FogAssert",
          "FogAssert"
        ],
        "LoD/1.08": [
          "ReleasePoolAllocation",
          "FogMemAlloc",
          "FogAssert",
          "FogAssert",
          "FogAssert",
          "FogAssert"
        ],
        "LoD/1.09": [
          "ReleasePoolAllocation",
          "FogMemAlloc",
          "FogAssert",
          "FogAssert",
          "FogAssert",
          "FogAssert"
        ],
        "LoD/1.09b": [
          "ReleasePoolAllocation",
          "FogMemAlloc",
          "FogAssert",
          "FogAssert",
          "FogAssert",
          "FogAssert"
        ],
        "LoD/1.09d": [
          "ReleasePoolAllocation",
          "FogMemAlloc",
          "FogAssert",
          "FogAssert",
          "FogAssert",
          "FogAssert"
        ],
        "LoD/1.10": [
          "ReleasePoolAllocation",
          "FogMemAlloc",
          "FogAssert",
          "FogAssert",
          "FogAssert",
          "FogAssert",
          "FogAssert",
          "FogAssert",
          "FogAssert",
          "FogAssert",
          "...+1 more"
        ]
      },
      "strings": {
        "LoD/1.07": [
          "\"pMcp->firstChar < 256\"",
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2MCPClient\\\\Src\\\\...",
          "\"pMcp->maxCharsAllowed < 256\"",
          "\"pMcp->totalChars < 256\"",
          "\"pMcp->count < 256\""
        ],
        "LoD/1.08": [
          "\"pMcp->firstChar < 256\"",
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2MCPClient\\\\Src\\\\...",
          "\"pMcp->maxCharsAllowed < 256\"",
          "\"pMcp->totalChars < 256\"",
          "\"pMcp->count < 256\""
        ],
        "LoD/1.09": [
          "\"pMcp->firstChar < 256\"",
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2MCPClient\\\\Src\\\\...",
          "\"pMcp->maxCharsAllowed < 256\"",
          "\"pMcp->totalChars < 256\"",
          "\"pMcp->count < 256\""
        ],
        "LoD/1.09b": [
          "\"pMcp->firstChar < 256\"",
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2MCPClient\\\\Src\\\\...",
          "\"pMcp->maxCharsAllowed < 256\"",
          "\"pMcp->totalChars < 256\"",
          "\"pMcp->count < 256\""
        ],
        "LoD/1.09d": [
          "\"pMcp->firstChar < 256\"",
          "\"C:\\\\Src\\\\Diablo2\\\\Source\\\\D2MCPClient\\\\Src\\\\McpCo...",
          "\"pMcp->maxCharsAllowed < 256\"",
          "\"pMcp->totalChars < 256\"",
          "\"pMcp->count < 256\""
        ],
        "LoD/1.10": [
          "\"pMcp->firstChar < 256\"",
          "\"C:\\\\projects\\\\D2\\\\head\\\\Diablo2\\\\Source\\\\D2MCPCli...",
          "\"pMcp->maxCharsAllowed < 256\"",
          "\"!\\\"Bad verb in McpClientSetCharacterList\\\"\"",
          "\"pMcp->totalChars < 256\"",
          "...+1 more"
        ]
      },
      "basic_block_counts": {
        "LoD/1.07": 12,
        "LoD/1.08": 12,
        "LoD/1.09": 12,
        "LoD/1.09b": 12,
        "LoD/1.09d": 12,
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
        "LoD/1.07": "88302f183dd2d1a705ce5a393823d59d",
        "LoD/1.08": "88302f183dd2d1a705ce5a393823d59d",
        "LoD/1.09": "88302f183dd2d1a705ce5a393823d59d",
        "LoD/1.09b": "88302f183dd2d1a705ce5a393823d59d",
        "LoD/1.09d": "88302f183dd2d1a705ce5a393823d59d",
        "LoD/1.10": "e0f795e40107031b2bb5f6f93d12566a"
      }
    },
    "d2mcpclient.dll_API_418889d9fcca": {
      "addresses": {
        "LoD/1.07": "0x6FA520B0",
        "LoD/1.08": "0x6FA520B0",
        "LoD/1.09": "0x6F9F1EF0",
        "LoD/1.09b": "0x6F9F1EF0",
        "LoD/1.09d": "0x6F9F1EF0",
        "LoD/1.10": "0x6F9F20E0"
      },
      "rvas": {
        "LoD/1.07": "0x20B0",
        "LoD/1.08": "0x20B0",
        "LoD/1.09": "0x1EF0",
        "LoD/1.09b": "0x1EF0",
        "LoD/1.09d": "0x1EF0",
        "LoD/1.10": "0x20E0"
      },
      "sizes": {
        "LoD/1.07": 175,
        "LoD/1.08": 175,
        "LoD/1.09": 267,
        "LoD/1.09b": 267,
        "LoD/1.09d": 267,
        "LoD/1.10": 154
      },
      "signature": "undefined BigIntTrimLeadingZerosAndCheckUnity(char * param_1)",
      "calling_convention": "__fastcall",
      "name_source": "LoD/1.08",
      "method": "API",
      "index": "API:418889d9fccae4a5772919d61b28442b",
      "callees": {
        "LoD/1.07": [
          "Ordinal_10047",
          "FogAssert",
          "FogAssert",
          "SendNetworkMessage"
        ],
        "LoD/1.08": [
          "Ordinal_10047",
          "FogAssert",
          "FogAssert",
          "SendNetworkMessage"
        ],
        "LoD/1.09": [
          "Ordinal_10047",
          "FogAssert",
          "FogAssert",
          "SendNetworkMessage"
        ],
        "LoD/1.09b": [
          "Ordinal_10047",
          "FogAssert",
          "FogAssert",
          "SendNetworkMessage"
        ],
        "LoD/1.09d": [
          "Ordinal_10047",
          "FogAssert",
          "FogAssert",
          "SendNetworkMessage"
        ],
        "LoD/1.10": [
          "Ordinal_10047",
          "FogAssert",
          "FogAssert",
          "Ordinal_10070"
        ]
      },
      "strings": {
        "LoD/1.07": [
          "\"dwSize < USHRT_MAX\"",
          "\"*lpdwSize < dwMaxSize\"",
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2MCPClient\\\\Src\\\\..."
        ],
        "LoD/1.08": [
          "\"dwSize < USHRT_MAX\"",
          "\"*lpdwSize < dwMaxSize\"",
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2MCPClient\\\\Src\\\\..."
        ],
        "LoD/1.09": [
          "\"dwSize < USHRT_MAX\"",
          "\"*lpdwSize < dwMaxSize\"",
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2MCPClient\\\\Src\\\\..."
        ],
        "LoD/1.09b": [
          "\"dwSize < USHRT_MAX\"",
          "\"*lpdwSize < dwMaxSize\"",
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2MCPClient\\\\Src\\\\..."
        ],
        "LoD/1.09d": [
          "\"dwSize < USHRT_MAX\"",
          "\"C:\\\\Src\\\\Diablo2\\\\Source\\\\D2MCPClient\\\\Src\\\\ToMCP...",
          "\"*lpdwSize < dwMaxSize\""
        ],
        "LoD/1.10": [
          "\"C:\\\\projects\\\\D2\\\\head\\\\Diablo2\\\\Source\\\\D2MCPCli...",
          "\"dwSize < USHRT_MAX\"",
          "\"*lpdwSize < dwMaxSize\""
        ]
      },
      "basic_block_counts": {
        "LoD/1.07": 5,
        "LoD/1.08": 5,
        "LoD/1.09": 5,
        "LoD/1.09b": 5,
        "LoD/1.09d": 5,
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
        "LoD/1.07": "c57fb7960febed2f1fcc7af0dae641de",
        "LoD/1.08": "c57fb7960febed2f1fcc7af0dae641de",
        "LoD/1.09": "9589645e971587e6737f8ee038205693",
        "LoD/1.09b": "9589645e971587e6737f8ee038205693",
        "LoD/1.09d": "9589645e971587e6737f8ee038205693",
        "LoD/1.10": "5c4aca56fc11594922e53d18c89e3b71"
      }
    },
    "d2mcpclient.dll_API_3ad69aa13ad6": {
      "addresses": {
        "LoD/1.07": "0x6FA51FE0",
        "LoD/1.08": "0x6FA51FE0",
        "LoD/1.09": "0x6F9F2000",
        "LoD/1.09b": "0x6F9F2000",
        "LoD/1.09d": "0x6F9F2000",
        "LoD/1.10": "0x6F9F2020"
      },
      "rvas": {
        "LoD/1.07": "0x1FE0",
        "LoD/1.08": "0x1FE0",
        "LoD/1.09": "0x2000",
        "LoD/1.09b": "0x2000",
        "LoD/1.09d": "0x2000",
        "LoD/1.10": "0x2020"
      },
      "sizes": {
        "LoD/1.07": 202,
        "LoD/1.08": 202,
        "LoD/1.09": 202,
        "LoD/1.09b": 202,
        "LoD/1.09d": 202,
        "LoD/1.10": 179
      },
      "signature": "undefined BigIntShiftLeft(void * this, undefined2 param_1)",
      "calling_convention": "__thiscall",
      "name_source": "LoD/1.08",
      "method": "API",
      "index": "API:6f11bd17b9d1008b39a411bad4212a10",
      "callees": {
        "LoD/1.07": [
          "Ordinal_10047",
          "Ordinal_10028",
          "FogAssert",
          "FogAssert",
          "SendNetworkMessage"
        ],
        "LoD/1.08": [
          "Ordinal_10047",
          "SetErrorHandlingDisabled",
          "FogAssert",
          "FogAssert",
          "SendNetworkMessage"
        ],
        "LoD/1.09": [
          "Ordinal_10047",
          "SetErrorHandlingDisabled",
          "FogAssert",
          "FogAssert",
          "SendNetworkMessage"
        ],
        "LoD/1.09b": [
          "Ordinal_10047",
          "SetErrorHandlingDisabled",
          "FogAssert",
          "FogAssert",
          "SendNetworkMessage"
        ],
        "LoD/1.09d": [
          "Ordinal_10047",
          "SetErrorHandlingDisabled",
          "FogAssert",
          "FogAssert",
          "SendNetworkMessage"
        ],
        "LoD/1.10": [
          "Ordinal_10047",
          "SetErrorHandlingDisabled",
          "FogAssert",
          "FogAssert",
          "Ordinal_10070"
        ]
      },
      "strings": {
        "LoD/1.07": [
          "\"dwSize < USHRT_MAX\"",
          "\"*lpdwSize < dwMaxSize\"",
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2MCPClient\\\\Src\\\\..."
        ],
        "LoD/1.08": [
          "\"dwSize < USHRT_MAX\"",
          "\"*lpdwSize < dwMaxSize\"",
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2MCPClient\\\\Src\\\\..."
        ],
        "LoD/1.09": [
          "\"dwSize < USHRT_MAX\"",
          "\"*lpdwSize < dwMaxSize\"",
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2MCPClient\\\\Src\\\\..."
        ],
        "LoD/1.09b": [
          "\"dwSize < USHRT_MAX\"",
          "\"*lpdwSize < dwMaxSize\"",
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2MCPClient\\\\Src\\\\..."
        ],
        "LoD/1.09d": [
          "\"dwSize < USHRT_MAX\"",
          "\"C:\\\\Src\\\\Diablo2\\\\Source\\\\D2MCPClient\\\\Src\\\\ToMCP...",
          "\"*lpdwSize < dwMaxSize\""
        ],
        "LoD/1.10": [
          "\"C:\\\\projects\\\\D2\\\\head\\\\Diablo2\\\\Source\\\\D2MCPCli...",
          "\"dwSize < USHRT_MAX\"",
          "\"*lpdwSize < dwMaxSize\""
        ]
      },
      "basic_block_counts": {
        "LoD/1.07": 5,
        "LoD/1.08": 5,
        "LoD/1.09": 5,
        "LoD/1.09b": 5,
        "LoD/1.09d": 5,
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
        "LoD/1.07": "54024d314ea8fa780f570c1ccfaf38c9",
        "LoD/1.08": "54024d314ea8fa780f570c1ccfaf38c9",
        "LoD/1.09": "54024d314ea8fa780f570c1ccfaf38c9",
        "LoD/1.09b": "54024d314ea8fa780f570c1ccfaf38c9",
        "LoD/1.09d": "54024d314ea8fa780f570c1ccfaf38c9",
        "LoD/1.10": "ff9ac373c61d8c4ad5defc3c70cbaaef"
      }
    },
    "d2mcpclient.dll_EXP_10004": {
      "addresses": {
        "LoD/1.07": "0x6FA52160",
        "LoD/1.08": "0x6FA52160",
        "LoD/1.09": "0x6F9F2180",
        "LoD/1.09b": "0x6F9F2180",
        "LoD/1.09d": "0x6F9F2180",
        "LoD/1.10": "0x6F9F2180"
      },
      "rvas": {
        "LoD/1.07": "0x2160",
        "LoD/1.08": "0x2160",
        "LoD/1.09": "0x2180",
        "LoD/1.09b": "0x2180",
        "LoD/1.09d": "0x2180",
        "LoD/1.10": "0x2180"
      },
      "sizes": {
        "LoD/1.07": 434,
        "LoD/1.08": 434,
        "LoD/1.09": 434,
        "LoD/1.09b": 434,
        "LoD/1.09d": 434,
        "LoD/1.10": 372
      },
      "name": "Ordinal_10004",
      "signature": "undefined Ordinal_10004(char * param_1, undefined2 param_2)",
      "calling_convention": "__fastcall",
      "name_source": "LoD/1.07",
      "method": "EXP",
      "index": "EXP:10004",
      "callees": {
        "LoD/1.07": [
          "Ordinal_10047",
          "FogAssert",
          "FogAssert",
          "FogAssert",
          "FogAssert",
          "SendNetworkMessage"
        ],
        "LoD/1.08": [
          "Ordinal_10047",
          "FogAssert",
          "FogAssert",
          "FogAssert",
          "FogAssert",
          "SendNetworkMessage"
        ],
        "LoD/1.09": [
          "Ordinal_10047",
          "FogAssert",
          "FogAssert",
          "FogAssert",
          "FogAssert",
          "SendNetworkMessage"
        ],
        "LoD/1.09b": [
          "Ordinal_10047",
          "FogAssert",
          "FogAssert",
          "FogAssert",
          "FogAssert",
          "SendNetworkMessage"
        ],
        "LoD/1.09d": [
          "Ordinal_10047",
          "FogAssert",
          "FogAssert",
          "FogAssert",
          "FogAssert",
          "SendNetworkMessage"
        ],
        "LoD/1.10": [
          "Ordinal_10047",
          "FogAssert",
          "FogAssert",
          "FogAssert",
          "FogAssert",
          "Ordinal_10070"
        ]
      },
      "strings": {
        "LoD/1.07": [
          "\"dwSize < USHRT_MAX\"",
          "\"*lpdwSize < dwMaxSize\"",
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2MCPClient\\\\Src\\\\..."
        ],
        "LoD/1.08": [
          "\"dwSize < USHRT_MAX\"",
          "\"*lpdwSize < dwMaxSize\"",
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2MCPClient\\\\Src\\\\..."
        ],
        "LoD/1.09": [
          "\"dwSize < USHRT_MAX\"",
          "\"*lpdwSize < dwMaxSize\"",
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2MCPClient\\\\Src\\\\..."
        ],
        "LoD/1.09b": [
          "\"dwSize < USHRT_MAX\"",
          "\"*lpdwSize < dwMaxSize\"",
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2MCPClient\\\\Src\\\\..."
        ],
        "LoD/1.09d": [
          "\"dwSize < USHRT_MAX\"",
          "\"C:\\\\Src\\\\Diablo2\\\\Source\\\\D2MCPClient\\\\Src\\\\ToMCP...",
          "\"*lpdwSize < dwMaxSize\""
        ],
        "LoD/1.10": [
          "\"C:\\\\projects\\\\D2\\\\head\\\\Diablo2\\\\Source\\\\D2MCPCli...",
          "\"dwSize < USHRT_MAX\"",
          "\"*lpdwSize < dwMaxSize\""
        ]
      },
      "basic_block_counts": {
        "LoD/1.07": 9,
        "LoD/1.08": 9,
        "LoD/1.09": 9,
        "LoD/1.09b": 9,
        "LoD/1.09d": 9,
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
        "LoD/1.07": "4629c0084f24f3afe073c55553e8575b",
        "LoD/1.08": "4629c0084f24f3afe073c55553e8575b",
        "LoD/1.09": "4629c0084f24f3afe073c55553e8575b",
        "LoD/1.09b": "4629c0084f24f3afe073c55553e8575b",
        "LoD/1.09d": "4629c0084f24f3afe073c55553e8575b",
        "LoD/1.10": "9a95d1c582b4a066470ac1bd2824f6ca"
      }
    },
    "d2mcpclient.dll_EXP_10005": {
      "addresses": {
        "LoD/1.07": "0x6FA52320",
        "LoD/1.08": "0x6FA52320",
        "LoD/1.09": "0x6F9F2340",
        "LoD/1.09b": "0x6F9F2340",
        "LoD/1.09d": "0x6F9F2340",
        "LoD/1.10": "0x6F9F2300"
      },
      "rvas": {
        "LoD/1.07": "0x2320",
        "LoD/1.08": "0x2320",
        "LoD/1.09": "0x2340",
        "LoD/1.09b": "0x2340",
        "LoD/1.09d": "0x2340",
        "LoD/1.10": "0x2300"
      },
      "sizes": {
        "LoD/1.07": 296,
        "LoD/1.08": 296,
        "LoD/1.09": 296,
        "LoD/1.09b": 296,
        "LoD/1.09d": 296,
        "LoD/1.10": 256
      },
      "name": "Ordinal_10005",
      "signature": "undefined Ordinal_10005(char * param_1, char * param_2, undefined2 param_3)",
      "calling_convention": "__fastcall",
      "name_source": "LoD/1.07",
      "method": "EXP",
      "index": "EXP:10005",
      "callees": {
        "LoD/1.07": [
          "Ordinal_10047",
          "FogAssert",
          "FogAssert",
          "FogAssert",
          "SendNetworkMessage"
        ],
        "LoD/1.08": [
          "Ordinal_10047",
          "FogAssert",
          "FogAssert",
          "FogAssert",
          "SendNetworkMessage"
        ],
        "LoD/1.09": [
          "Ordinal_10047",
          "FogAssert",
          "FogAssert",
          "FogAssert",
          "SendNetworkMessage"
        ],
        "LoD/1.09b": [
          "Ordinal_10047",
          "FogAssert",
          "FogAssert",
          "FogAssert",
          "SendNetworkMessage"
        ],
        "LoD/1.09d": [
          "Ordinal_10047",
          "FogAssert",
          "FogAssert",
          "FogAssert",
          "SendNetworkMessage"
        ],
        "LoD/1.10": [
          "Ordinal_10047",
          "FogAssert",
          "FogAssert",
          "FogAssert",
          "Ordinal_10070"
        ]
      },
      "strings": {
        "LoD/1.07": [
          "\"dwSize < USHRT_MAX\"",
          "\"*lpdwSize < dwMaxSize\"",
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2MCPClient\\\\Src\\\\..."
        ],
        "LoD/1.08": [
          "\"dwSize < USHRT_MAX\"",
          "\"*lpdwSize < dwMaxSize\"",
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2MCPClient\\\\Src\\\\..."
        ],
        "LoD/1.09": [
          "\"dwSize < USHRT_MAX\"",
          "\"*lpdwSize < dwMaxSize\"",
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2MCPClient\\\\Src\\\\..."
        ],
        "LoD/1.09b": [
          "\"dwSize < USHRT_MAX\"",
          "\"*lpdwSize < dwMaxSize\"",
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2MCPClient\\\\Src\\\\..."
        ],
        "LoD/1.09d": [
          "\"dwSize < USHRT_MAX\"",
          "\"C:\\\\Src\\\\Diablo2\\\\Source\\\\D2MCPClient\\\\Src\\\\ToMCP...",
          "\"*lpdwSize < dwMaxSize\""
        ],
        "LoD/1.10": [
          "\"C:\\\\projects\\\\D2\\\\head\\\\Diablo2\\\\Source\\\\D2MCPCli...",
          "\"dwSize < USHRT_MAX\"",
          "\"*lpdwSize < dwMaxSize\""
        ]
      },
      "basic_block_counts": {
        "LoD/1.07": 7,
        "LoD/1.08": 7,
        "LoD/1.09": 7,
        "LoD/1.09b": 7,
        "LoD/1.09d": 7,
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
        "LoD/1.07": "6aecb65fb52b1aec621b4fb1736f1351",
        "LoD/1.08": "6aecb65fb52b1aec621b4fb1736f1351",
        "LoD/1.09": "6aecb65fb52b1aec621b4fb1736f1351",
        "LoD/1.09b": "6aecb65fb52b1aec621b4fb1736f1351",
        "LoD/1.09d": "6aecb65fb52b1aec621b4fb1736f1351",
        "LoD/1.10": "ed0c74b08b6f5ac27780fa725cf91bc2"
      }
    },
    "d2mcpclient.dll_EXP_10006": {
      "addresses": {
        "LoD/1.07": "0x6FA52450",
        "LoD/1.08": "0x6FA52450",
        "LoD/1.09": "0x6F9F2470",
        "LoD/1.09b": "0x6F9F2470",
        "LoD/1.09d": "0x6F9F2470",
        "LoD/1.10": "0x6F9F2400"
      },
      "rvas": {
        "LoD/1.07": "0x2450",
        "LoD/1.08": "0x2450",
        "LoD/1.09": "0x2470",
        "LoD/1.09b": "0x2470",
        "LoD/1.09d": "0x2470",
        "LoD/1.10": "0x2400"
      },
      "sizes": {
        "LoD/1.07": 161,
        "LoD/1.08": 161,
        "LoD/1.09": 161,
        "LoD/1.09b": 161,
        "LoD/1.09d": 161,
        "LoD/1.10": 138
      },
      "name": "Ordinal_10006",
      "signature": "undefined Ordinal_10006(char * param_1, undefined2 param_2)",
      "calling_convention": "__fastcall",
      "name_source": "LoD/1.07",
      "method": "EXP",
      "index": "EXP:10006",
      "callees": {
        "LoD/1.07": [
          "Ordinal_10047",
          "FogAssert",
          "SendNetworkMessage"
        ],
        "LoD/1.08": [
          "Ordinal_10047",
          "FogAssert",
          "SendNetworkMessage"
        ],
        "LoD/1.09": [
          "Ordinal_10047",
          "FogAssert",
          "SendNetworkMessage"
        ],
        "LoD/1.09b": [
          "Ordinal_10047",
          "FogAssert",
          "SendNetworkMessage"
        ],
        "LoD/1.09d": [
          "Ordinal_10047",
          "FogAssert",
          "SendNetworkMessage"
        ],
        "LoD/1.10": [
          "Ordinal_10047",
          "FogAssert",
          "Ordinal_10070"
        ]
      },
      "strings": {
        "LoD/1.07": [
          "\"*lpdwSize < dwMaxSize\"",
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2MCPClient\\\\Src\\\\..."
        ],
        "LoD/1.08": [
          "\"*lpdwSize < dwMaxSize\"",
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2MCPClient\\\\Src\\\\..."
        ],
        "LoD/1.09": [
          "\"*lpdwSize < dwMaxSize\"",
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2MCPClient\\\\Src\\\\..."
        ],
        "LoD/1.09b": [
          "\"*lpdwSize < dwMaxSize\"",
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2MCPClient\\\\Src\\\\..."
        ],
        "LoD/1.09d": [
          "\"C:\\\\Src\\\\Diablo2\\\\Source\\\\D2MCPClient\\\\Src\\\\ToMCP...",
          "\"*lpdwSize < dwMaxSize\""
        ],
        "LoD/1.10": [
          "\"C:\\\\projects\\\\D2\\\\head\\\\Diablo2\\\\Source\\\\D2MCPCli...",
          "\"*lpdwSize < dwMaxSize\""
        ]
      },
      "basic_block_counts": {
        "LoD/1.07": 3,
        "LoD/1.08": 3,
        "LoD/1.09": 3,
        "LoD/1.09b": 3,
        "LoD/1.09d": 3,
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
        "LoD/1.07": "6cbceb5523c8c1dda842b7cf1840d074",
        "LoD/1.08": "6cbceb5523c8c1dda842b7cf1840d074",
        "LoD/1.09": "6cbceb5523c8c1dda842b7cf1840d074",
        "LoD/1.09b": "6cbceb5523c8c1dda842b7cf1840d074",
        "LoD/1.09d": "6cbceb5523c8c1dda842b7cf1840d074",
        "LoD/1.10": "609524e11534cb2ff02727194aa0b0cf"
      }
    },
    "d2mcpclient.dll_EXP_10007": {
      "addresses": {
        "LoD/1.07": "0x6FA52500",
        "LoD/1.08": "0x6FA52500",
        "LoD/1.09": "0x6F9F2520",
        "LoD/1.09b": "0x6F9F2520",
        "LoD/1.09d": "0x6F9F2520",
        "LoD/1.10": "0x6F9F2490"
      },
      "rvas": {
        "LoD/1.07": "0x2500",
        "LoD/1.08": "0x2500",
        "LoD/1.09": "0x2520",
        "LoD/1.09b": "0x2520",
        "LoD/1.09d": "0x2520",
        "LoD/1.10": "0x2490"
      },
      "sizes": {
        "LoD/1.07": 156,
        "LoD/1.08": 156,
        "LoD/1.09": 156,
        "LoD/1.09b": 156,
        "LoD/1.09d": 156,
        "LoD/1.10": 131
      },
      "name": "Ordinal_10007",
      "signature": "undefined Ordinal_10007(char * param_1, undefined2 param_2)",
      "calling_convention": "__fastcall",
      "name_source": "LoD/1.07",
      "method": "EXP",
      "index": "EXP:10007",
      "callees": {
        "LoD/1.07": [
          "Ordinal_10047",
          "FogAssert",
          "SendNetworkMessage"
        ],
        "LoD/1.08": [
          "Ordinal_10047",
          "FogAssert",
          "SendNetworkMessage"
        ],
        "LoD/1.09": [
          "Ordinal_10047",
          "FogAssert",
          "SendNetworkMessage"
        ],
        "LoD/1.09b": [
          "Ordinal_10047",
          "FogAssert",
          "SendNetworkMessage"
        ],
        "LoD/1.09d": [
          "Ordinal_10047",
          "FogAssert",
          "SendNetworkMessage"
        ],
        "LoD/1.10": [
          "Ordinal_10047",
          "FogAssert",
          "Ordinal_10070"
        ]
      },
      "strings": {
        "LoD/1.07": [
          "\"*lpdwSize < dwMaxSize\"",
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2MCPClient\\\\Src\\\\..."
        ],
        "LoD/1.08": [
          "\"*lpdwSize < dwMaxSize\"",
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2MCPClient\\\\Src\\\\..."
        ],
        "LoD/1.09": [
          "\"*lpdwSize < dwMaxSize\"",
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2MCPClient\\\\Src\\\\..."
        ],
        "LoD/1.09b": [
          "\"*lpdwSize < dwMaxSize\"",
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2MCPClient\\\\Src\\\\..."
        ],
        "LoD/1.09d": [
          "\"C:\\\\Src\\\\Diablo2\\\\Source\\\\D2MCPClient\\\\Src\\\\ToMCP...",
          "\"*lpdwSize < dwMaxSize\""
        ],
        "LoD/1.10": [
          "\"C:\\\\projects\\\\D2\\\\head\\\\Diablo2\\\\Source\\\\D2MCPCli...",
          "\"*lpdwSize < dwMaxSize\""
        ]
      },
      "basic_block_counts": {
        "LoD/1.07": 3,
        "LoD/1.08": 3,
        "LoD/1.09": 3,
        "LoD/1.09b": 3,
        "LoD/1.09d": 3,
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
        "LoD/1.07": "d737934cafc9963d95370dea5cb29dab",
        "LoD/1.08": "d737934cafc9963d95370dea5cb29dab",
        "LoD/1.09": "d737934cafc9963d95370dea5cb29dab",
        "LoD/1.09b": "d737934cafc9963d95370dea5cb29dab",
        "LoD/1.09d": "d737934cafc9963d95370dea5cb29dab",
        "LoD/1.10": "4b706c521d12e3a887c465d71b2379ec"
      }
    },
    "d2mcpclient.dll_EXP_10013": {
      "addresses": {
        "LoD/1.07": "0x6FA525A0",
        "LoD/1.08": "0x6FA525A0",
        "LoD/1.09": "0x6F9F25C0",
        "LoD/1.09b": "0x6F9F25C0",
        "LoD/1.09d": "0x6F9F25C0",
        "LoD/1.10": "0x6F9F2520",
        "LoD/1.11": "0x6FA26520",
        "LoD/1.11b": "0x6FA26D80",
        "LoD/1.12a": "0x6FA25FA0",
        "LoD/1.13c": "0x6FA26D80",
        "LoD/1.13d": "0x6FA265C0"
      },
      "rvas": {
        "LoD/1.07": "0x25A0",
        "LoD/1.08": "0x25A0",
        "LoD/1.09": "0x25C0",
        "LoD/1.09b": "0x25C0",
        "LoD/1.09d": "0x25C0",
        "LoD/1.10": "0x2520",
        "LoD/1.11": "0x6520",
        "LoD/1.11b": "0x6D80",
        "LoD/1.12a": "0x5FA0",
        "LoD/1.13c": "0x6D80",
        "LoD/1.13d": "0x65C0"
      },
      "sizes": {
        "LoD/1.07": 194,
        "LoD/1.08": 194,
        "LoD/1.09": 194,
        "LoD/1.09b": 194,
        "LoD/1.09d": 194,
        "LoD/1.10": 171,
        "LoD/1.11": 37,
        "LoD/1.11b": 37,
        "LoD/1.12a": 37,
        "LoD/1.13c": 37,
        "LoD/1.13d": 37
      },
      "name": "Ordinal_10013",
      "signature": "undefined Ordinal_10013(char * param_1, undefined2 param_2)",
      "calling_convention": "__fastcall",
      "name_source": "LoD/1.07",
      "method": "EXP",
      "index": "EXP:10013",
      "callees": {
        "LoD/1.07": [
          "Ordinal_10047",
          "FogAssert",
          "FogAssert",
          "SendNetworkMessage"
        ],
        "LoD/1.08": [
          "Ordinal_10047",
          "FogAssert",
          "FogAssert",
          "SendNetworkMessage"
        ],
        "LoD/1.09": [
          "Ordinal_10047",
          "FogAssert",
          "FogAssert",
          "SendNetworkMessage"
        ],
        "LoD/1.09b": [
          "Ordinal_10047",
          "FogAssert",
          "FogAssert",
          "SendNetworkMessage"
        ],
        "LoD/1.09d": [
          "Ordinal_10047",
          "FogAssert",
          "FogAssert",
          "SendNetworkMessage"
        ],
        "LoD/1.10": [
          "Ordinal_10047",
          "FogAssert",
          "FogAssert",
          "Ordinal_10070"
        ],
        "LoD/1.11": [
          "Ordinal_10070"
        ],
        "LoD/1.11b": [
          "Ordinal_10070"
        ],
        "LoD/1.12a": [
          "EncodeBufferWithContext"
        ],
        "LoD/1.13c": [
          "EncodeBufferWithContext"
        ],
        "LoD/1.13d": [
          "EncodeBufferWithContext"
        ]
      },
      "strings": {
        "LoD/1.07": [
          "\"dwSize < USHRT_MAX\"",
          "\"*lpdwSize < dwMaxSize\"",
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2MCPClient\\\\Src\\\\..."
        ],
        "LoD/1.08": [
          "\"dwSize < USHRT_MAX\"",
          "\"*lpdwSize < dwMaxSize\"",
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2MCPClient\\\\Src\\\\..."
        ],
        "LoD/1.09": [
          "\"dwSize < USHRT_MAX\"",
          "\"*lpdwSize < dwMaxSize\"",
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2MCPClient\\\\Src\\\\..."
        ],
        "LoD/1.09b": [
          "\"dwSize < USHRT_MAX\"",
          "\"*lpdwSize < dwMaxSize\"",
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2MCPClient\\\\Src\\\\..."
        ],
        "LoD/1.09d": [
          "\"dwSize < USHRT_MAX\"",
          "\"C:\\\\Src\\\\Diablo2\\\\Source\\\\D2MCPClient\\\\Src\\\\ToMCP...",
          "\"*lpdwSize < dwMaxSize\""
        ],
        "LoD/1.10": [
          "\"C:\\\\projects\\\\D2\\\\head\\\\Diablo2\\\\Source\\\\D2MCPCli...",
          "\"dwSize < USHRT_MAX\"",
          "\"*lpdwSize < dwMaxSize\""
        ]
      },
      "basic_block_counts": {
        "LoD/1.07": 5,
        "LoD/1.08": 5,
        "LoD/1.09": 5,
        "LoD/1.09b": 5,
        "LoD/1.09d": 5,
        "LoD/1.10": 7,
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
        "LoD/1.07": "4e2e1ed221f338acc8554dc818e43272",
        "LoD/1.08": "4e2e1ed221f338acc8554dc818e43272",
        "LoD/1.09": "4e2e1ed221f338acc8554dc818e43272",
        "LoD/1.09b": "4e2e1ed221f338acc8554dc818e43272",
        "LoD/1.09d": "4e2e1ed221f338acc8554dc818e43272",
        "LoD/1.10": "9e57c571226f186fc846a52757088521",
        "LoD/1.11": "27cf70e216d5f82ac091c77f63637746",
        "LoD/1.11b": "27cf70e216d5f82ac091c77f63637746",
        "LoD/1.12a": "27cf70e216d5f82ac091c77f63637746",
        "LoD/1.13c": "27cf70e216d5f82ac091c77f63637746",
        "LoD/1.13d": "27cf70e216d5f82ac091c77f63637746"
      }
    },
    "d2mcpclient.dll_EXP_10014": {
      "addresses": {
        "LoD/1.07": "0x6FA52670",
        "LoD/1.08": "0x6FA52670",
        "LoD/1.09": "0x6F9F2690",
        "LoD/1.09b": "0x6F9F2690",
        "LoD/1.09d": "0x6F9F2690",
        "LoD/1.10": "0x6F9F25D0",
        "LoD/1.11": "0x6FA268B0",
        "LoD/1.11b": "0x6FA270E0",
        "LoD/1.12a": "0x6FA262D0",
        "LoD/1.13c": "0x6FA270B0",
        "LoD/1.13d": "0x6FA26950"
      },
      "rvas": {
        "LoD/1.07": "0x2670",
        "LoD/1.08": "0x2670",
        "LoD/1.09": "0x2690",
        "LoD/1.09b": "0x2690",
        "LoD/1.09d": "0x2690",
        "LoD/1.10": "0x25D0",
        "LoD/1.11": "0x68B0",
        "LoD/1.11b": "0x70E0",
        "LoD/1.12a": "0x62D0",
        "LoD/1.13c": "0x70B0",
        "LoD/1.13d": "0x6950"
      },
      "sizes": {
        "LoD/1.07": 194,
        "LoD/1.08": 194,
        "LoD/1.09": 194,
        "LoD/1.09b": 194,
        "LoD/1.09d": 194,
        "LoD/1.10": 171,
        "LoD/1.11": 129,
        "LoD/1.11b": 129,
        "LoD/1.12a": 129,
        "LoD/1.13c": 129,
        "LoD/1.13d": 129
      },
      "name": "Ordinal_10014",
      "signature": "undefined Ordinal_10014(char * param_1, undefined2 param_2)",
      "calling_convention": "__fastcall",
      "name_source": "LoD/1.07",
      "method": "EXP",
      "index": "EXP:10014",
      "callees": {
        "LoD/1.07": [
          "Ordinal_10047",
          "FogAssert",
          "FogAssert",
          "SendNetworkMessage"
        ],
        "LoD/1.08": [
          "Ordinal_10047",
          "FogAssert",
          "FogAssert",
          "SendNetworkMessage"
        ],
        "LoD/1.09": [
          "Ordinal_10047",
          "FogAssert",
          "FogAssert",
          "SendNetworkMessage"
        ],
        "LoD/1.09b": [
          "Ordinal_10047",
          "FogAssert",
          "FogAssert",
          "SendNetworkMessage"
        ],
        "LoD/1.09d": [
          "Ordinal_10047",
          "FogAssert",
          "FogAssert",
          "SendNetworkMessage"
        ],
        "LoD/1.10": [
          "Ordinal_10047",
          "FogAssert",
          "FogAssert",
          "Ordinal_10070"
        ],
        "LoD/1.11": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "Ordinal_10070"
        ],
        "LoD/1.11b": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "Ordinal_10070"
        ],
        "LoD/1.12a": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "EncodeBufferWithContext"
        ],
        "LoD/1.13c": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "EncodeBufferWithContext"
        ],
        "LoD/1.13d": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "EncodeBufferWithContext"
        ]
      },
      "strings": {
        "LoD/1.07": [
          "\"dwSize < USHRT_MAX\"",
          "\"*lpdwSize < dwMaxSize\"",
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2MCPClient\\\\Src\\\\..."
        ],
        "LoD/1.08": [
          "\"dwSize < USHRT_MAX\"",
          "\"*lpdwSize < dwMaxSize\"",
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2MCPClient\\\\Src\\\\..."
        ],
        "LoD/1.09": [
          "\"dwSize < USHRT_MAX\"",
          "\"*lpdwSize < dwMaxSize\"",
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2MCPClient\\\\Src\\\\..."
        ],
        "LoD/1.09b": [
          "\"dwSize < USHRT_MAX\"",
          "\"*lpdwSize < dwMaxSize\"",
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2MCPClient\\\\Src\\\\..."
        ],
        "LoD/1.09d": [
          "\"dwSize < USHRT_MAX\"",
          "\"C:\\\\Src\\\\Diablo2\\\\Source\\\\D2MCPClient\\\\Src\\\\ToMCP...",
          "\"*lpdwSize < dwMaxSize\""
        ],
        "LoD/1.10": [
          "\"C:\\\\projects\\\\D2\\\\head\\\\Diablo2\\\\Source\\\\D2MCPCli...",
          "\"dwSize < USHRT_MAX\"",
          "\"*lpdwSize < dwMaxSize\""
        ]
      },
      "basic_block_counts": {
        "LoD/1.07": 5,
        "LoD/1.08": 5,
        "LoD/1.09": 5,
        "LoD/1.09b": 5,
        "LoD/1.09d": 5,
        "LoD/1.10": 7,
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
        "LoD/1.07": "4e2e1ed221f338acc8554dc818e43272",
        "LoD/1.08": "4e2e1ed221f338acc8554dc818e43272",
        "LoD/1.09": "4e2e1ed221f338acc8554dc818e43272",
        "LoD/1.09b": "4e2e1ed221f338acc8554dc818e43272",
        "LoD/1.09d": "4e2e1ed221f338acc8554dc818e43272",
        "LoD/1.10": "9e57c571226f186fc846a52757088521",
        "LoD/1.11": "3eac90692de3b7c4393f1c737342792a",
        "LoD/1.11b": "3eac90692de3b7c4393f1c737342792a",
        "LoD/1.12a": "3eac90692de3b7c4393f1c737342792a",
        "LoD/1.13c": "3eac90692de3b7c4393f1c737342792a",
        "LoD/1.13d": "3eac90692de3b7c4393f1c737342792a"
      }
    },
    "d2mcpclient.dll_EXP_10021": {
      "addresses": {
        "LoD/1.07": "0x6FA52740",
        "LoD/1.08": "0x6FA52740",
        "LoD/1.09": "0x6F9F2760",
        "LoD/1.09b": "0x6F9F2760",
        "LoD/1.09d": "0x6F9F2760",
        "LoD/1.10": "0x6F9F2680"
      },
      "rvas": {
        "LoD/1.07": "0x2740",
        "LoD/1.08": "0x2740",
        "LoD/1.09": "0x2760",
        "LoD/1.09b": "0x2760",
        "LoD/1.09d": "0x2760",
        "LoD/1.10": "0x2680"
      },
      "sizes": {
        "LoD/1.07": 92,
        "LoD/1.08": 92,
        "LoD/1.09": 92,
        "LoD/1.09b": 92,
        "LoD/1.09d": 92,
        "LoD/1.10": 92
      },
      "name": "Ordinal_10021",
      "signature": "undefined Ordinal_10021(undefined4 param_1, undefined2 param_2)",
      "calling_convention": "__fastcall",
      "name_source": "LoD/1.07",
      "method": "EXP",
      "index": "EXP:10021",
      "callees": {
        "LoD/1.07": [
          "Ordinal_10047",
          "SStrCopy",
          "SStrLen",
          "SendNetworkMessage"
        ],
        "LoD/1.08": [
          "Ordinal_10047",
          "Ordinal_501",
          "SStrLen",
          "SendNetworkMessage"
        ],
        "LoD/1.09": [
          "Ordinal_10047",
          "Ordinal_501",
          "SStrLen",
          "SendNetworkMessage"
        ],
        "LoD/1.09b": [
          "Ordinal_10047",
          "Ordinal_501",
          "SStrLen",
          "SendNetworkMessage"
        ],
        "LoD/1.09d": [
          "Ordinal_10047",
          "Ordinal_501",
          "SStrLen",
          "SendNetworkMessage"
        ],
        "LoD/1.10": [
          "Ordinal_10047",
          "Ordinal_501",
          "SStrLen",
          "Ordinal_10070"
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
        "LoD/1.07": "b55b2782bba7e9ea8f20ddb59efddb49",
        "LoD/1.08": "b55b2782bba7e9ea8f20ddb59efddb49",
        "LoD/1.09": "b55b2782bba7e9ea8f20ddb59efddb49",
        "LoD/1.09b": "b55b2782bba7e9ea8f20ddb59efddb49",
        "LoD/1.09d": "b55b2782bba7e9ea8f20ddb59efddb49",
        "LoD/1.10": "89aec81431196482b1dfc69d3665404a"
      }
    },
    "d2mcpclient.dll_EXP_10062": {
      "addresses": {
        "LoD/1.07": "0x6FA527A0",
        "LoD/1.08": "0x6FA527A0",
        "LoD/1.09": "0x6F9F27C0",
        "LoD/1.09b": "0x6F9F27C0",
        "LoD/1.09d": "0x6F9F27C0",
        "LoD/1.10": "0x6F9F26E0",
        "LoD/1.11": "0x6FA264B0",
        "LoD/1.11b": "0x6FA26C90",
        "LoD/1.12a": "0x6FA26030",
        "LoD/1.13c": "0x6FA26D50",
        "LoD/1.13d": "0x6FA26500"
      },
      "rvas": {
        "LoD/1.07": "0x27A0",
        "LoD/1.08": "0x27A0",
        "LoD/1.09": "0x27C0",
        "LoD/1.09b": "0x27C0",
        "LoD/1.09d": "0x27C0",
        "LoD/1.10": "0x26E0",
        "LoD/1.11": "0x64B0",
        "LoD/1.11b": "0x6C90",
        "LoD/1.12a": "0x6030",
        "LoD/1.13c": "0x6D50",
        "LoD/1.13d": "0x6500"
      },
      "sizes": {
        "LoD/1.07": 75,
        "LoD/1.08": 75,
        "LoD/1.09": 75,
        "LoD/1.09b": 75,
        "LoD/1.09d": 75,
        "LoD/1.10": 75,
        "LoD/1.11": 49,
        "LoD/1.11b": 37,
        "LoD/1.12a": 37,
        "LoD/1.13c": 46,
        "LoD/1.13d": 37
      },
      "name": "Ordinal_10062",
      "signature": "undefined Ordinal_10062(undefined4 param_1)",
      "calling_convention": "__fastcall",
      "name_source": "LoD/1.07",
      "method": "EXP",
      "index": "EXP:10062",
      "callees": {
        "LoD/1.07": [
          "Ordinal_10047",
          "SStrCopy",
          "SStrLen",
          "SendNetworkMessage"
        ],
        "LoD/1.08": [
          "Ordinal_10047",
          "Ordinal_501",
          "SStrLen",
          "SendNetworkMessage"
        ],
        "LoD/1.09": [
          "Ordinal_10047",
          "Ordinal_501",
          "SStrLen",
          "SendNetworkMessage"
        ],
        "LoD/1.09b": [
          "Ordinal_10047",
          "Ordinal_501",
          "SStrLen",
          "SendNetworkMessage"
        ],
        "LoD/1.09d": [
          "Ordinal_10047",
          "Ordinal_501",
          "SStrLen",
          "SendNetworkMessage"
        ],
        "LoD/1.10": [
          "Ordinal_10047",
          "Ordinal_501",
          "SStrLen",
          "Ordinal_10070"
        ],
        "LoD/1.11": [
          "Ordinal_10070"
        ],
        "LoD/1.11b": [
          "Ordinal_10070"
        ],
        "LoD/1.12a": [
          "EncodeBufferWithContext"
        ],
        "LoD/1.13c": [
          "EncodeBufferWithContext"
        ],
        "LoD/1.13d": [
          "EncodeBufferWithContext"
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
        "LoD/1.07": "7acb7b63fffa2e9aa67acdb02a1ae017",
        "LoD/1.08": "7acb7b63fffa2e9aa67acdb02a1ae017",
        "LoD/1.09": "7acb7b63fffa2e9aa67acdb02a1ae017",
        "LoD/1.09b": "7acb7b63fffa2e9aa67acdb02a1ae017",
        "LoD/1.09d": "7acb7b63fffa2e9aa67acdb02a1ae017",
        "LoD/1.10": "549f56d9de0e9ca6c46bd550d19b4b97",
        "LoD/1.11": "4279ccfee5b4a0c14e808a53f9c93ba5",
        "LoD/1.11b": "27cf70e216d5f82ac091c77f63637746",
        "LoD/1.12a": "27cf70e216d5f82ac091c77f63637746",
        "LoD/1.13c": "8cf6081513f31f17087d887ea495c3ca",
        "LoD/1.13d": "27cf70e216d5f82ac091c77f63637746"
      }
    },
    "d2mcpclient.dll_EXP_10022": {
      "addresses": {
        "LoD/1.07": "0x6FA527F0",
        "LoD/1.08": "0x6FA527F0",
        "LoD/1.09": "0x6F9F2810",
        "LoD/1.09b": "0x6F9F2810",
        "LoD/1.09d": "0x6F9F2810",
        "LoD/1.10": "0x6F9F2730",
        "LoD/1.11": "0x6FA26A30"
      },
      "rvas": {
        "LoD/1.07": "0x27F0",
        "LoD/1.08": "0x27F0",
        "LoD/1.09": "0x2810",
        "LoD/1.09b": "0x2810",
        "LoD/1.09d": "0x2810",
        "LoD/1.10": "0x2730",
        "LoD/1.11": "0x6A30"
      },
      "sizes": {
        "LoD/1.07": 273,
        "LoD/1.08": 273,
        "LoD/1.09": 273,
        "LoD/1.09b": 273,
        "LoD/1.09d": 273,
        "LoD/1.10": 238,
        "LoD/1.11": 93
      },
      "name": "Ordinal_10022",
      "signature": "undefined Ordinal_10022(char * param_1, char * param_2)",
      "calling_convention": "__fastcall",
      "name_source": "LoD/1.07",
      "method": "EXP",
      "index": "EXP:10022",
      "callees": {
        "LoD/1.07": [
          "Ordinal_10047",
          "FogAssert",
          "FogAssert",
          "FogAssert",
          "SendNetworkMessage"
        ],
        "LoD/1.08": [
          "Ordinal_10047",
          "FogAssert",
          "FogAssert",
          "FogAssert",
          "SendNetworkMessage"
        ],
        "LoD/1.09": [
          "Ordinal_10047",
          "FogAssert",
          "FogAssert",
          "FogAssert",
          "SendNetworkMessage"
        ],
        "LoD/1.09b": [
          "Ordinal_10047",
          "FogAssert",
          "FogAssert",
          "FogAssert",
          "SendNetworkMessage"
        ],
        "LoD/1.09d": [
          "Ordinal_10047",
          "FogAssert",
          "FogAssert",
          "FogAssert",
          "SendNetworkMessage"
        ],
        "LoD/1.10": [
          "Ordinal_10047",
          "FogAssert",
          "FogAssert",
          "FogAssert",
          "Ordinal_10070"
        ],
        "LoD/1.11": [
          "Ordinal_10070"
        ]
      },
      "strings": {
        "LoD/1.07": [
          "\"dwSize < USHRT_MAX\"",
          "\"*lpdwSize < dwMaxSize\"",
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2MCPClient\\\\Src\\\\..."
        ],
        "LoD/1.08": [
          "\"dwSize < USHRT_MAX\"",
          "\"*lpdwSize < dwMaxSize\"",
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2MCPClient\\\\Src\\\\..."
        ],
        "LoD/1.09": [
          "\"dwSize < USHRT_MAX\"",
          "\"*lpdwSize < dwMaxSize\"",
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2MCPClient\\\\Src\\\\..."
        ],
        "LoD/1.09b": [
          "\"dwSize < USHRT_MAX\"",
          "\"*lpdwSize < dwMaxSize\"",
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2MCPClient\\\\Src\\\\..."
        ],
        "LoD/1.09d": [
          "\"dwSize < USHRT_MAX\"",
          "\"C:\\\\Src\\\\Diablo2\\\\Source\\\\D2MCPClient\\\\Src\\\\ToMCP...",
          "\"*lpdwSize < dwMaxSize\""
        ],
        "LoD/1.10": [
          "\"C:\\\\projects\\\\D2\\\\head\\\\Diablo2\\\\Source\\\\D2MCPCli...",
          "\"dwSize < USHRT_MAX\"",
          "\"*lpdwSize < dwMaxSize\""
        ]
      },
      "basic_block_counts": {
        "LoD/1.07": 7,
        "LoD/1.08": 7,
        "LoD/1.09": 7,
        "LoD/1.09b": 7,
        "LoD/1.09d": 7,
        "LoD/1.10": 11,
        "LoD/1.11": 1
      },
      "loop_counts": {
        "LoD/1.07": 0,
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0,
        "LoD/1.11": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "bd65d68255f96469db85938d0df01972",
        "LoD/1.08": "bd65d68255f96469db85938d0df01972",
        "LoD/1.09": "bd65d68255f96469db85938d0df01972",
        "LoD/1.09b": "bd65d68255f96469db85938d0df01972",
        "LoD/1.09d": "bd65d68255f96469db85938d0df01972",
        "LoD/1.10": "abb28b8f90522557ae28f1a00d1490ca",
        "LoD/1.11": "e1e6665f63af39e13482dd75650e8ebc"
      }
    },
    "d2mcpclient.dll_EXP_10023": {
      "addresses": {
        "LoD/1.07": "0x6FA52910",
        "LoD/1.08": "0x6FA52910",
        "LoD/1.09": "0x6F9F2930",
        "LoD/1.09b": "0x6F9F2930",
        "LoD/1.09d": "0x6F9F2930",
        "LoD/1.10": "0x6F9F2820",
        "LoD/1.11": "0x6FA26240",
        "LoD/1.11b": "0x6FA26930",
        "LoD/1.12a": "0x6FA272F0",
        "LoD/1.13c": "0x6FA26990",
        "LoD/1.13d": "0x6FA26250"
      },
      "rvas": {
        "LoD/1.07": "0x2910",
        "LoD/1.08": "0x2910",
        "LoD/1.09": "0x2930",
        "LoD/1.09b": "0x2930",
        "LoD/1.09d": "0x2930",
        "LoD/1.10": "0x2820",
        "LoD/1.11": "0x6240",
        "LoD/1.11b": "0x6930",
        "LoD/1.12a": "0x72F0",
        "LoD/1.13c": "0x6990",
        "LoD/1.13d": "0x6250"
      },
      "sizes": {
        "LoD/1.07": 175,
        "LoD/1.08": 175,
        "LoD/1.09": 175,
        "LoD/1.09b": 175,
        "LoD/1.09d": 175,
        "LoD/1.10": 154,
        "LoD/1.11": 88,
        "LoD/1.11b": 88,
        "LoD/1.12a": 88,
        "LoD/1.13c": 88,
        "LoD/1.13d": 88
      },
      "name": "Ordinal_10023",
      "signature": "undefined Ordinal_10023(char * param_1)",
      "calling_convention": "__fastcall",
      "name_source": "LoD/1.07",
      "method": "EXP",
      "index": "EXP:10023",
      "callees": {
        "LoD/1.07": [
          "Ordinal_10047",
          "FogAssert",
          "FogAssert",
          "SendNetworkMessage"
        ],
        "LoD/1.08": [
          "Ordinal_10047",
          "FogAssert",
          "FogAssert",
          "SendNetworkMessage"
        ],
        "LoD/1.09": [
          "Ordinal_10047",
          "FogAssert",
          "FogAssert",
          "SendNetworkMessage"
        ],
        "LoD/1.09b": [
          "Ordinal_10047",
          "FogAssert",
          "FogAssert",
          "SendNetworkMessage"
        ],
        "LoD/1.09d": [
          "Ordinal_10047",
          "FogAssert",
          "FogAssert",
          "SendNetworkMessage"
        ],
        "LoD/1.10": [
          "Ordinal_10047",
          "FogAssert",
          "FogAssert",
          "Ordinal_10070"
        ],
        "LoD/1.11": [
          "ValidatePointerAndProcessLinkedList"
        ],
        "LoD/1.11b": [
          "ValidatePointerAndProcessLinkedList"
        ],
        "LoD/1.12a": [
          "ValidatePointerAndProcessLinkedList"
        ],
        "LoD/1.13c": [
          "ValidatePointerAndProcessLinkedList"
        ],
        "LoD/1.13d": [
          "ValidatePointerAndProcessLinkedList"
        ]
      },
      "strings": {
        "LoD/1.07": [
          "\"dwSize < USHRT_MAX\"",
          "\"*lpdwSize < dwMaxSize\"",
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2MCPClient\\\\Src\\\\..."
        ],
        "LoD/1.08": [
          "\"dwSize < USHRT_MAX\"",
          "\"*lpdwSize < dwMaxSize\"",
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2MCPClient\\\\Src\\\\..."
        ],
        "LoD/1.09": [
          "\"dwSize < USHRT_MAX\"",
          "\"*lpdwSize < dwMaxSize\"",
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2MCPClient\\\\Src\\\\..."
        ],
        "LoD/1.09b": [
          "\"dwSize < USHRT_MAX\"",
          "\"*lpdwSize < dwMaxSize\"",
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2MCPClient\\\\Src\\\\..."
        ],
        "LoD/1.09d": [
          "\"dwSize < USHRT_MAX\"",
          "\"C:\\\\Src\\\\Diablo2\\\\Source\\\\D2MCPClient\\\\Src\\\\ToMCP...",
          "\"*lpdwSize < dwMaxSize\""
        ],
        "LoD/1.10": [
          "\"C:\\\\projects\\\\D2\\\\head\\\\Diablo2\\\\Source\\\\D2MCPCli...",
          "\"dwSize < USHRT_MAX\"",
          "\"*lpdwSize < dwMaxSize\""
        ]
      },
      "basic_block_counts": {
        "LoD/1.07": 5,
        "LoD/1.08": 5,
        "LoD/1.09": 5,
        "LoD/1.09b": 5,
        "LoD/1.09d": 5,
        "LoD/1.10": 7,
        "LoD/1.11": 8,
        "LoD/1.11b": 8,
        "LoD/1.12a": 8,
        "LoD/1.13c": 8,
        "LoD/1.13d": 8
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
        "LoD/1.07": "c57fb7960febed2f1fcc7af0dae641de",
        "LoD/1.08": "c57fb7960febed2f1fcc7af0dae641de",
        "LoD/1.09": "c57fb7960febed2f1fcc7af0dae641de",
        "LoD/1.09b": "c57fb7960febed2f1fcc7af0dae641de",
        "LoD/1.09d": "c57fb7960febed2f1fcc7af0dae641de",
        "LoD/1.10": "5c4aca56fc11594922e53d18c89e3b71",
        "LoD/1.11": "077dadc4465b398108a3f83937a87e08",
        "LoD/1.11b": "077dadc4465b398108a3f83937a87e08",
        "LoD/1.12a": "077dadc4465b398108a3f83937a87e08",
        "LoD/1.13c": "077dadc4465b398108a3f83937a87e08",
        "LoD/1.13d": "077dadc4465b398108a3f83937a87e08"
      }
    },
    "d2mcpclient.dll_EXP_10024": {
      "addresses": {
        "LoD/1.07": "0x6FA529C0",
        "LoD/1.08": "0x6FA529C0",
        "LoD/1.09": "0x6F9F29E0",
        "LoD/1.09b": "0x6F9F29E0",
        "LoD/1.09d": "0x6F9F29E0",
        "LoD/1.10": "0x6F9F28C0"
      },
      "rvas": {
        "LoD/1.07": "0x29C0",
        "LoD/1.08": "0x29C0",
        "LoD/1.09": "0x29E0",
        "LoD/1.09b": "0x29E0",
        "LoD/1.09d": "0x29E0",
        "LoD/1.10": "0x28C0"
      },
      "sizes": {
        "LoD/1.07": 34,
        "LoD/1.08": 34,
        "LoD/1.09": 34,
        "LoD/1.09b": 34,
        "LoD/1.09d": 34,
        "LoD/1.10": 34
      },
      "name": "Ordinal_10024",
      "signature": "undefined Ordinal_10024(void)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.07",
      "method": "EXP",
      "index": "EXP:10024",
      "callees": {
        "LoD/1.07": [
          "Ordinal_10047",
          "SendNetworkMessage"
        ],
        "LoD/1.08": [
          "Ordinal_10047",
          "SendNetworkMessage"
        ],
        "LoD/1.09": [
          "Ordinal_10047",
          "SendNetworkMessage"
        ],
        "LoD/1.09b": [
          "Ordinal_10047",
          "SendNetworkMessage"
        ],
        "LoD/1.09d": [
          "Ordinal_10047",
          "SendNetworkMessage"
        ],
        "LoD/1.10": [
          "Ordinal_10047",
          "Ordinal_10070"
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
        "LoD/1.07": "4dc1e368fbb77e2e45fe537826167e64",
        "LoD/1.08": "4dc1e368fbb77e2e45fe537826167e64",
        "LoD/1.09": "4dc1e368fbb77e2e45fe537826167e64",
        "LoD/1.09b": "4dc1e368fbb77e2e45fe537826167e64",
        "LoD/1.09d": "4dc1e368fbb77e2e45fe537826167e64",
        "LoD/1.10": "4dc1e368fbb77e2e45fe537826167e64"
      }
    },
    "d2mcpclient.dll_EXP_10025": {
      "addresses": {
        "LoD/1.07": "0x6FA529F0",
        "LoD/1.08": "0x6FA529F0",
        "LoD/1.09": "0x6F9F2A10",
        "LoD/1.09b": "0x6F9F2A10",
        "LoD/1.09d": "0x6F9F2A10",
        "LoD/1.10": "0x6F9F28F0"
      },
      "rvas": {
        "LoD/1.07": "0x29F0",
        "LoD/1.08": "0x29F0",
        "LoD/1.09": "0x2A10",
        "LoD/1.09b": "0x2A10",
        "LoD/1.09d": "0x2A10",
        "LoD/1.10": "0x28F0"
      },
      "sizes": {
        "LoD/1.07": 34,
        "LoD/1.08": 34,
        "LoD/1.09": 34,
        "LoD/1.09b": 34,
        "LoD/1.09d": 34,
        "LoD/1.10": 34
      },
      "name": "Ordinal_10025",
      "signature": "undefined Ordinal_10025(void)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.07",
      "method": "EXP",
      "index": "EXP:10025",
      "callees": {
        "LoD/1.07": [
          "Ordinal_10047",
          "SendNetworkMessage"
        ],
        "LoD/1.08": [
          "Ordinal_10047",
          "SendNetworkMessage"
        ],
        "LoD/1.09": [
          "Ordinal_10047",
          "SendNetworkMessage"
        ],
        "LoD/1.09b": [
          "Ordinal_10047",
          "SendNetworkMessage"
        ],
        "LoD/1.09d": [
          "Ordinal_10047",
          "SendNetworkMessage"
        ],
        "LoD/1.10": [
          "Ordinal_10047",
          "Ordinal_10070"
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
        "LoD/1.07": "4dc1e368fbb77e2e45fe537826167e64",
        "LoD/1.08": "4dc1e368fbb77e2e45fe537826167e64",
        "LoD/1.09": "4dc1e368fbb77e2e45fe537826167e64",
        "LoD/1.09b": "4dc1e368fbb77e2e45fe537826167e64",
        "LoD/1.09d": "4dc1e368fbb77e2e45fe537826167e64",
        "LoD/1.10": "4dc1e368fbb77e2e45fe537826167e64"
      }
    },
    "d2mcpclient.dll_EXP_10026": {
      "addresses": {
        "LoD/1.07": "0x6FA52A20",
        "LoD/1.08": "0x6FA52A20",
        "LoD/1.09": "0x6F9F2A40",
        "LoD/1.09b": "0x6F9F2A40",
        "LoD/1.09d": "0x6F9F2A40",
        "LoD/1.10": "0x6F9F2920",
        "LoD/1.11": "0x6FA26820",
        "LoD/1.11b": "0x6FA26FC0",
        "LoD/1.12a": "0x6FA26100",
        "LoD/1.13c": "0x6FA27020",
        "LoD/1.13d": "0x6FA26830"
      },
      "rvas": {
        "LoD/1.07": "0x2A20",
        "LoD/1.08": "0x2A20",
        "LoD/1.09": "0x2A40",
        "LoD/1.09b": "0x2A40",
        "LoD/1.09d": "0x2A40",
        "LoD/1.10": "0x2920",
        "LoD/1.11": "0x6820",
        "LoD/1.11b": "0x6FC0",
        "LoD/1.12a": "0x6100",
        "LoD/1.13c": "0x7020",
        "LoD/1.13d": "0x6830"
      },
      "sizes": {
        "LoD/1.07": 34,
        "LoD/1.08": 34,
        "LoD/1.09": 34,
        "LoD/1.09b": 34,
        "LoD/1.09d": 34,
        "LoD/1.10": 34,
        "LoD/1.11": 132,
        "LoD/1.11b": 132,
        "LoD/1.12a": 132,
        "LoD/1.13c": 132,
        "LoD/1.13d": 132
      },
      "name": "Ordinal_10026",
      "signature": "undefined Ordinal_10026(void)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.07",
      "method": "EXP",
      "index": "EXP:10026",
      "callees": {
        "LoD/1.07": [
          "Ordinal_10047",
          "SendNetworkMessage"
        ],
        "LoD/1.08": [
          "Ordinal_10047",
          "SendNetworkMessage"
        ],
        "LoD/1.09": [
          "Ordinal_10047",
          "SendNetworkMessage"
        ],
        "LoD/1.09b": [
          "Ordinal_10047",
          "SendNetworkMessage"
        ],
        "LoD/1.09d": [
          "Ordinal_10047",
          "SendNetworkMessage"
        ],
        "LoD/1.10": [
          "Ordinal_10047",
          "Ordinal_10070"
        ],
        "LoD/1.11": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "Ordinal_10070"
        ],
        "LoD/1.11b": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "Ordinal_10070"
        ],
        "LoD/1.12a": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "EncodeBufferWithContext"
        ],
        "LoD/1.13c": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "EncodeBufferWithContext"
        ],
        "LoD/1.13d": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "EncodeBufferWithContext"
        ]
      },
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1,
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
        "LoD/1.07": "4dc1e368fbb77e2e45fe537826167e64",
        "LoD/1.08": "4dc1e368fbb77e2e45fe537826167e64",
        "LoD/1.09": "4dc1e368fbb77e2e45fe537826167e64",
        "LoD/1.09b": "4dc1e368fbb77e2e45fe537826167e64",
        "LoD/1.09d": "4dc1e368fbb77e2e45fe537826167e64",
        "LoD/1.10": "4dc1e368fbb77e2e45fe537826167e64",
        "LoD/1.11": "8252aa4cfd5abd8a12915fcc6c911fb6",
        "LoD/1.11b": "8252aa4cfd5abd8a12915fcc6c911fb6",
        "LoD/1.12a": "8252aa4cfd5abd8a12915fcc6c911fb6",
        "LoD/1.13c": "8252aa4cfd5abd8a12915fcc6c911fb6",
        "LoD/1.13d": "8252aa4cfd5abd8a12915fcc6c911fb6"
      }
    },
    "d2mcpclient.dll_EXP_10027": {
      "addresses": {
        "LoD/1.07": "0x6FA52A50",
        "LoD/1.08": "0x6FA52A50",
        "LoD/1.09": "0x6F9F2A70",
        "LoD/1.09b": "0x6F9F2A70",
        "LoD/1.09d": "0x6F9F2A70",
        "LoD/1.10": "0x6F9F2950",
        "LoD/1.11": "0x6FA26580",
        "LoD/1.11b": "0x6FA26D50",
        "LoD/1.12a": "0x6FA26000",
        "LoD/1.13c": "0x6FA26DE0"
      },
      "rvas": {
        "LoD/1.07": "0x2A50",
        "LoD/1.08": "0x2A50",
        "LoD/1.09": "0x2A70",
        "LoD/1.09b": "0x2A70",
        "LoD/1.09d": "0x2A70",
        "LoD/1.10": "0x2950",
        "LoD/1.11": "0x6580",
        "LoD/1.11b": "0x6D50",
        "LoD/1.12a": "0x6000",
        "LoD/1.13c": "0x6DE0"
      },
      "sizes": {
        "LoD/1.07": 52,
        "LoD/1.08": 52,
        "LoD/1.09": 52,
        "LoD/1.09b": 52,
        "LoD/1.09d": 52,
        "LoD/1.10": 52,
        "LoD/1.11": 37,
        "LoD/1.11b": 37,
        "LoD/1.12a": 37,
        "LoD/1.13c": 37
      },
      "name": "Ordinal_10027",
      "signature": "undefined Ordinal_10027(undefined4 param_1, undefined2 param_2)",
      "calling_convention": "__fastcall",
      "name_source": "LoD/1.07",
      "method": "EXP",
      "index": "EXP:10027",
      "callees": {
        "LoD/1.07": [
          "Ordinal_10047",
          "SendNetworkMessage"
        ],
        "LoD/1.08": [
          "Ordinal_10047",
          "SendNetworkMessage"
        ],
        "LoD/1.09": [
          "Ordinal_10047",
          "SendNetworkMessage"
        ],
        "LoD/1.09b": [
          "Ordinal_10047",
          "SendNetworkMessage"
        ],
        "LoD/1.09d": [
          "Ordinal_10047",
          "SendNetworkMessage"
        ],
        "LoD/1.10": [
          "Ordinal_10047",
          "Ordinal_10070"
        ],
        "LoD/1.11": [
          "Ordinal_10070"
        ],
        "LoD/1.11b": [
          "Ordinal_10070"
        ],
        "LoD/1.12a": [
          "EncodeBufferWithContext"
        ],
        "LoD/1.13c": [
          "EncodeBufferWithContext"
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
        "LoD/1.13c": 1
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
        "LoD/1.13c": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "d419fded7bff840c4336a0bf6548dc99",
        "LoD/1.08": "d419fded7bff840c4336a0bf6548dc99",
        "LoD/1.09": "d419fded7bff840c4336a0bf6548dc99",
        "LoD/1.09b": "d419fded7bff840c4336a0bf6548dc99",
        "LoD/1.09d": "d419fded7bff840c4336a0bf6548dc99",
        "LoD/1.10": "ed5da95d88be84daa2a56f36e48ed47c",
        "LoD/1.11": "27cf70e216d5f82ac091c77f63637746",
        "LoD/1.11b": "27cf70e216d5f82ac091c77f63637746",
        "LoD/1.12a": "27cf70e216d5f82ac091c77f63637746",
        "LoD/1.13c": "27cf70e216d5f82ac091c77f63637746"
      }
    },
    "d2mcpclient.dll_EXP_10049": {
      "addresses": {
        "LoD/1.07": "0x6FA52A90",
        "LoD/1.08": "0x6FA52A90",
        "LoD/1.09": "0x6F9F2AB0",
        "LoD/1.09b": "0x6F9F2AB0",
        "LoD/1.09d": "0x6F9F2AB0",
        "LoD/1.10": "0x6F9F2990",
        "LoD/1.11": "0x6FA26B30",
        "LoD/1.11b": "0x6FA272D0",
        "LoD/1.12a": "0x6FA264C0",
        "LoD/1.13c": "0x6FA27330",
        "LoD/1.13d": "0x6FA26B40"
      },
      "rvas": {
        "LoD/1.07": "0x2A90",
        "LoD/1.08": "0x2A90",
        "LoD/1.09": "0x2AB0",
        "LoD/1.09b": "0x2AB0",
        "LoD/1.09d": "0x2AB0",
        "LoD/1.10": "0x2990",
        "LoD/1.11": "0x6B30",
        "LoD/1.11b": "0x72D0",
        "LoD/1.12a": "0x64C0",
        "LoD/1.13c": "0x7330",
        "LoD/1.13d": "0x6B40"
      },
      "sizes": {
        "LoD/1.07": 34,
        "LoD/1.08": 34,
        "LoD/1.09": 34,
        "LoD/1.09b": 34,
        "LoD/1.09d": 34,
        "LoD/1.10": 34,
        "LoD/1.11": 212,
        "LoD/1.11b": 212,
        "LoD/1.12a": 212,
        "LoD/1.13c": 212,
        "LoD/1.13d": 212
      },
      "name": "Ordinal_10049",
      "signature": "undefined Ordinal_10049(void)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.07",
      "method": "EXP",
      "index": "EXP:10049",
      "callees": {
        "LoD/1.07": [
          "Ordinal_10047",
          "SendNetworkMessage"
        ],
        "LoD/1.08": [
          "Ordinal_10047",
          "SendNetworkMessage"
        ],
        "LoD/1.09": [
          "Ordinal_10047",
          "SendNetworkMessage"
        ],
        "LoD/1.09b": [
          "Ordinal_10047",
          "SendNetworkMessage"
        ],
        "LoD/1.09d": [
          "Ordinal_10047",
          "SendNetworkMessage"
        ],
        "LoD/1.10": [
          "Ordinal_10047",
          "Ordinal_10070"
        ],
        "LoD/1.11": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "Ordinal_10070"
        ],
        "LoD/1.11b": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "Ordinal_10070"
        ],
        "LoD/1.12a": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "EncodeBufferWithContext"
        ],
        "LoD/1.13c": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "EncodeBufferWithContext"
        ],
        "LoD/1.13d": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "EncodeBufferWithContext"
        ]
      },
      "basic_block_counts": {
        "LoD/1.07": 1,
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1,
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
        "LoD/1.07": "4dc1e368fbb77e2e45fe537826167e64",
        "LoD/1.08": "4dc1e368fbb77e2e45fe537826167e64",
        "LoD/1.09": "4dc1e368fbb77e2e45fe537826167e64",
        "LoD/1.09b": "4dc1e368fbb77e2e45fe537826167e64",
        "LoD/1.09d": "4dc1e368fbb77e2e45fe537826167e64",
        "LoD/1.10": "4dc1e368fbb77e2e45fe537826167e64",
        "LoD/1.11": "27db101cec1a2fdf237e4b40c6a3d744",
        "LoD/1.11b": "27db101cec1a2fdf237e4b40c6a3d744",
        "LoD/1.12a": "27db101cec1a2fdf237e4b40c6a3d744",
        "LoD/1.13c": "27db101cec1a2fdf237e4b40c6a3d744",
        "LoD/1.13d": "27db101cec1a2fdf237e4b40c6a3d744"
      }
    },
    "d2mcpclient.dll_EXP_10054": {
      "addresses": {
        "LoD/1.07": "0x6FA52AC0",
        "LoD/1.08": "0x6FA52AC0",
        "LoD/1.09": "0x6F9F2AE0",
        "LoD/1.09b": "0x6F9F2AE0",
        "LoD/1.09d": "0x6F9F2AE0",
        "LoD/1.10": "0x6F9F29C0"
      },
      "rvas": {
        "LoD/1.07": "0x2AC0",
        "LoD/1.08": "0x2AC0",
        "LoD/1.09": "0x2AE0",
        "LoD/1.09b": "0x2AE0",
        "LoD/1.09d": "0x2AE0",
        "LoD/1.10": "0x29C0"
      },
      "sizes": {
        "LoD/1.07": 34,
        "LoD/1.08": 34,
        "LoD/1.09": 34,
        "LoD/1.09b": 34,
        "LoD/1.09d": 34,
        "LoD/1.10": 34
      },
      "name": "Ordinal_10054",
      "signature": "undefined Ordinal_10054(void)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.07",
      "method": "EXP",
      "index": "EXP:10054",
      "callees": {
        "LoD/1.07": [
          "Ordinal_10047",
          "SendNetworkMessage"
        ],
        "LoD/1.08": [
          "Ordinal_10047",
          "SendNetworkMessage"
        ],
        "LoD/1.09": [
          "Ordinal_10047",
          "SendNetworkMessage"
        ],
        "LoD/1.09b": [
          "Ordinal_10047",
          "SendNetworkMessage"
        ],
        "LoD/1.09d": [
          "Ordinal_10047",
          "SendNetworkMessage"
        ],
        "LoD/1.10": [
          "Ordinal_10047",
          "Ordinal_10070"
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
        "LoD/1.07": "4dc1e368fbb77e2e45fe537826167e64",
        "LoD/1.08": "4dc1e368fbb77e2e45fe537826167e64",
        "LoD/1.09": "4dc1e368fbb77e2e45fe537826167e64",
        "LoD/1.09b": "4dc1e368fbb77e2e45fe537826167e64",
        "LoD/1.09d": "4dc1e368fbb77e2e45fe537826167e64",
        "LoD/1.10": "4dc1e368fbb77e2e45fe537826167e64"
      }
    },
    "d2mcpclient.dll_EXP_10056": {
      "addresses": {
        "LoD/1.07": "0x6FA52AF0",
        "LoD/1.08": "0x6FA52AF0",
        "LoD/1.09": "0x6F9F2B10",
        "LoD/1.09b": "0x6F9F2B10",
        "LoD/1.09d": "0x6F9F2B10",
        "LoD/1.10": "0x6F9F29F0"
      },
      "rvas": {
        "LoD/1.07": "0x2AF0",
        "LoD/1.08": "0x2AF0",
        "LoD/1.09": "0x2B10",
        "LoD/1.09b": "0x2B10",
        "LoD/1.09d": "0x2B10",
        "LoD/1.10": "0x29F0"
      },
      "sizes": {
        "LoD/1.07": 46,
        "LoD/1.08": 46,
        "LoD/1.09": 46,
        "LoD/1.09b": 46,
        "LoD/1.09d": 46,
        "LoD/1.10": 46
      },
      "name": "Ordinal_10056",
      "signature": "undefined Ordinal_10056(void)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.07",
      "method": "EXP",
      "index": "EXP:10056",
      "callees": {
        "LoD/1.07": [
          "Ordinal_10047",
          "SendNetworkMessage"
        ],
        "LoD/1.08": [
          "Ordinal_10047",
          "SendNetworkMessage"
        ],
        "LoD/1.09": [
          "Ordinal_10047",
          "SendNetworkMessage"
        ],
        "LoD/1.09b": [
          "Ordinal_10047",
          "SendNetworkMessage"
        ],
        "LoD/1.09d": [
          "Ordinal_10047",
          "SendNetworkMessage"
        ],
        "LoD/1.10": [
          "Ordinal_10047",
          "Ordinal_10070"
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
        "LoD/1.07": "197b74476697200da50c13c9364a2760",
        "LoD/1.08": "197b74476697200da50c13c9364a2760",
        "LoD/1.09": "197b74476697200da50c13c9364a2760",
        "LoD/1.09b": "197b74476697200da50c13c9364a2760",
        "LoD/1.09d": "197b74476697200da50c13c9364a2760",
        "LoD/1.10": "197b74476697200da50c13c9364a2760"
      }
    },
    "d2mcpclient.dll_EXP_10059": {
      "addresses": {
        "LoD/1.07": "0x6FA52B20",
        "LoD/1.08": "0x6FA52B20",
        "LoD/1.09": "0x6F9F2B40",
        "LoD/1.09b": "0x6F9F2B40",
        "LoD/1.09d": "0x6F9F2B40",
        "LoD/1.10": "0x6F9F2A20"
      },
      "rvas": {
        "LoD/1.07": "0x2B20",
        "LoD/1.08": "0x2B20",
        "LoD/1.09": "0x2B40",
        "LoD/1.09b": "0x2B40",
        "LoD/1.09d": "0x2B40",
        "LoD/1.10": "0x2A20"
      },
      "sizes": {
        "LoD/1.07": 196,
        "LoD/1.08": 196,
        "LoD/1.09": 196,
        "LoD/1.09b": 196,
        "LoD/1.09d": 196,
        "LoD/1.10": 173
      },
      "name": "Ordinal_10059",
      "signature": "undefined Ordinal_10059(void * this, undefined4 param_1)",
      "calling_convention": "__thiscall",
      "name_source": "LoD/1.07",
      "method": "EXP",
      "index": "EXP:10059",
      "callees": {
        "LoD/1.07": [
          "Ordinal_10047",
          "FogAssert",
          "FogAssert",
          "SendNetworkMessage"
        ],
        "LoD/1.08": [
          "Ordinal_10047",
          "FogAssert",
          "FogAssert",
          "SendNetworkMessage"
        ],
        "LoD/1.09": [
          "Ordinal_10047",
          "FogAssert",
          "FogAssert",
          "SendNetworkMessage"
        ],
        "LoD/1.09b": [
          "Ordinal_10047",
          "FogAssert",
          "FogAssert",
          "SendNetworkMessage"
        ],
        "LoD/1.09d": [
          "Ordinal_10047",
          "FogAssert",
          "FogAssert",
          "SendNetworkMessage"
        ],
        "LoD/1.10": [
          "Ordinal_10047",
          "FogAssert",
          "FogAssert",
          "Ordinal_10070"
        ]
      },
      "strings": {
        "LoD/1.07": [
          "\"dwSize < USHRT_MAX\"",
          "\"*lpdwSize < dwMaxSize\"",
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2MCPClient\\\\Src\\\\..."
        ],
        "LoD/1.08": [
          "\"dwSize < USHRT_MAX\"",
          "\"*lpdwSize < dwMaxSize\"",
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2MCPClient\\\\Src\\\\..."
        ],
        "LoD/1.09": [
          "\"dwSize < USHRT_MAX\"",
          "\"*lpdwSize < dwMaxSize\"",
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2MCPClient\\\\Src\\\\..."
        ],
        "LoD/1.09b": [
          "\"dwSize < USHRT_MAX\"",
          "\"*lpdwSize < dwMaxSize\"",
          "\"C:\\\\Projects\\\\Diablo2\\\\Source\\\\D2MCPClient\\\\Src\\\\..."
        ],
        "LoD/1.09d": [
          "\"dwSize < USHRT_MAX\"",
          "\"C:\\\\Src\\\\Diablo2\\\\Source\\\\D2MCPClient\\\\Src\\\\ToMCP...",
          "\"*lpdwSize < dwMaxSize\""
        ],
        "LoD/1.10": [
          "\"C:\\\\projects\\\\D2\\\\head\\\\Diablo2\\\\Source\\\\D2MCPCli...",
          "\"dwSize < USHRT_MAX\"",
          "\"*lpdwSize < dwMaxSize\""
        ]
      },
      "basic_block_counts": {
        "LoD/1.07": 5,
        "LoD/1.08": 5,
        "LoD/1.09": 5,
        "LoD/1.09b": 5,
        "LoD/1.09d": 5,
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
        "LoD/1.07": "2a8515602708e81a9b3159008aa4692e",
        "LoD/1.08": "2a8515602708e81a9b3159008aa4692e",
        "LoD/1.09": "2a8515602708e81a9b3159008aa4692e",
        "LoD/1.09b": "2a8515602708e81a9b3159008aa4692e",
        "LoD/1.09d": "2a8515602708e81a9b3159008aa4692e",
        "LoD/1.10": "dd3416174ba27a4a3c5f0ae74152ed0d"
      }
    },
    "d2mcpclient.dll_InetNtoaToStaticBuffer": {
      "addresses": {
        "LoD/1.07": "0x6FA52BF0",
        "LoD/1.08": "0x6FA52BF0",
        "LoD/1.09": "0x6F9F2C10",
        "LoD/1.09b": "0x6F9F2C10",
        "LoD/1.09d": "0x6F9F2C10",
        "LoD/1.10": "0x6F9F2AD0",
        "LoD/1.11": "0x6FA25D70",
        "LoD/1.11b": "0x6FA25DA6",
        "LoD/1.12a": "0x6FA25E0A",
        "LoD/1.13c": "0x6FA25E16",
        "LoD/1.13d": "0x6FA25D76"
      },
      "rvas": {
        "LoD/1.07": "0x2BF0",
        "LoD/1.08": "0x2BF0",
        "LoD/1.09": "0x2C10",
        "LoD/1.09b": "0x2C10",
        "LoD/1.09d": "0x2C10",
        "LoD/1.10": "0x2AD0",
        "LoD/1.11": "0x5D70",
        "LoD/1.11b": "0x5DA6",
        "LoD/1.12a": "0x5E0A",
        "LoD/1.13c": "0x5E16",
        "LoD/1.13d": "0x5D76"
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
      "name": "InetNtoaToStaticBuffer",
      "signature": "char * InetNtoaToStaticBuffer(in_addr inAddr)",
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
    "d2mcpclient.dll_GetPeerName": {
      "addresses": {
        "LoD/1.07": "0x6FA52BF6",
        "LoD/1.08": "0x6FA52BF6",
        "LoD/1.09": "0x6F9F2C16",
        "LoD/1.09b": "0x6F9F2C16",
        "LoD/1.09d": "0x6F9F2C16",
        "LoD/1.10": "0x6F9F2AD6",
        "LoD/1.11": "0x6FA25DCA",
        "LoD/1.11b": "0x6FA25DCA",
        "LoD/1.12a": "0x6FA25E34",
        "LoD/1.13c": "0x6FA25E3A",
        "LoD/1.13d": "0x6FA25DCA"
      },
      "rvas": {
        "LoD/1.07": "0x2BF6",
        "LoD/1.08": "0x2BF6",
        "LoD/1.09": "0x2C16",
        "LoD/1.09b": "0x2C16",
        "LoD/1.09d": "0x2C16",
        "LoD/1.10": "0x2AD6",
        "LoD/1.11": "0x5DCA",
        "LoD/1.11b": "0x5DCA",
        "LoD/1.12a": "0x5E34",
        "LoD/1.13c": "0x5E3A",
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
      "name": "GetPeerName",
      "signature": "bool GetPeerName(int nSocketContext, sockaddr * pSockAddr, int * pnAddrLen)",
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
    "d2mcpclient.dll_SendNetworkData": {
      "addresses": {
        "LoD/1.07": "0x6FA52BFC",
        "LoD/1.08": "0x6FA52BFC",
        "LoD/1.09": "0x6F9F2C1C",
        "LoD/1.09b": "0x6F9F2C1C",
        "LoD/1.09d": "0x6F9F2C1C",
        "LoD/1.10": "0x6F9F2ADC",
        "LoD/1.11": "0x6FA25D6A",
        "LoD/1.11b": "0x6FA25D64",
        "LoD/1.12a": "0x6FA25DDA",
        "LoD/1.13c": "0x6FA25DD4",
        "LoD/1.13d": "0x6FA25D6A"
      },
      "rvas": {
        "LoD/1.07": "0x2BFC",
        "LoD/1.08": "0x2BFC",
        "LoD/1.09": "0x2C1C",
        "LoD/1.09b": "0x2C1C",
        "LoD/1.09d": "0x2C1C",
        "LoD/1.10": "0x2ADC",
        "LoD/1.11": "0x5D6A",
        "LoD/1.11b": "0x5D64",
        "LoD/1.12a": "0x5DDA",
        "LoD/1.13c": "0x5DD4",
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
      "name": "SendNetworkData",
      "signature": "bool SendNetworkData(int nConn, char * szBuffer, ushort wLength)",
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
    "d2mcpclient.dll_SignalResourceStop": {
      "addresses": {
        "LoD/1.07": "0x6FA52C02",
        "LoD/1.08": "0x6FA52C02",
        "LoD/1.09": "0x6F9F2C22",
        "LoD/1.09b": "0x6F9F2C22",
        "LoD/1.09d": "0x6F9F2C22",
        "LoD/1.10": "0x6F9F2AE2",
        "LoD/1.11": "0x6FA25DB2",
        "LoD/1.11b": "0x6FA25DB2",
        "LoD/1.12a": "0x6FA25DEC",
        "LoD/1.13c": "0x6FA25DFE",
        "LoD/1.13d": "0x6FA25D94"
      },
      "rvas": {
        "LoD/1.07": "0x2C02",
        "LoD/1.08": "0x2C02",
        "LoD/1.09": "0x2C22",
        "LoD/1.09b": "0x2C22",
        "LoD/1.09d": "0x2C22",
        "LoD/1.10": "0x2AE2",
        "LoD/1.11": "0x5DB2",
        "LoD/1.11b": "0x5DB2",
        "LoD/1.12a": "0x5DEC",
        "LoD/1.13c": "0x5DFE",
        "LoD/1.13d": "0x5D94"
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
      "name": "SignalResourceStop",
      "signature": "void SignalResourceStop(void * pResource)",
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
    "d2mcpclient.dll_GetStructPositionXY": {
      "addresses": {
        "LoD/1.07": "0x6FA52C08",
        "LoD/1.08": "0x6FA52C08",
        "LoD/1.09": "0x6F9F2C28",
        "LoD/1.09b": "0x6F9F2C28",
        "LoD/1.09d": "0x6F9F2C28",
        "LoD/1.10": "0x6F9F2AE8",
        "LoD/1.11": "0x6FA25D8E",
        "LoD/1.11b": "0x6FA25D88",
        "LoD/1.12a": "0x6FA25E16",
        "LoD/1.13c": "0x6FA25E22",
        "LoD/1.13d": "0x6FA25DB2"
      },
      "rvas": {
        "LoD/1.07": "0x2C08",
        "LoD/1.08": "0x2C08",
        "LoD/1.09": "0x2C28",
        "LoD/1.09b": "0x2C28",
        "LoD/1.09d": "0x2C28",
        "LoD/1.10": "0x2AE8",
        "LoD/1.11": "0x5D8E",
        "LoD/1.11b": "0x5D88",
        "LoD/1.12a": "0x5E16",
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
      "name": "GetStructPositionXY",
      "signature": "int GetStructPositionXY(void * pStruct, uint * pdwOutX, uint * pdwOutY)",
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
    "d2mcpclient.dll_GetField0x110": {
      "addresses": {
        "LoD/1.07": "0x6FA52C0E",
        "LoD/1.08": "0x6FA52C0E",
        "LoD/1.09": "0x6F9F2C2E",
        "LoD/1.09b": "0x6F9F2C2E",
        "LoD/1.09d": "0x6F9F2C2E",
        "LoD/1.10": "0x6F9F2AEE",
        "LoD/1.11": "0x6FA25D88",
        "LoD/1.11b": "0x6FA25D82",
        "LoD/1.12a": "0x6FA25DE0",
        "LoD/1.13c": "0x6FA25DF2",
        "LoD/1.13d": "0x6FA25D88"
      },
      "rvas": {
        "LoD/1.07": "0x2C0E",
        "LoD/1.08": "0x2C0E",
        "LoD/1.09": "0x2C2E",
        "LoD/1.09b": "0x2C2E",
        "LoD/1.09d": "0x2C2E",
        "LoD/1.10": "0x2AEE",
        "LoD/1.11": "0x5D88",
        "LoD/1.11b": "0x5D82",
        "LoD/1.12a": "0x5DE0",
        "LoD/1.13c": "0x5DF2",
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
      "name": "GetField0x110",
      "signature": "int GetField0x110(void * pStruct)",
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
    "d2mcpclient.dll_InitializeWorkerThread": {
      "addresses": {
        "LoD/1.07": "0x6FA52C14",
        "LoD/1.08": "0x6FA52C14",
        "LoD/1.09": "0x6F9F2C34",
        "LoD/1.09b": "0x6F9F2C34",
        "LoD/1.09d": "0x6F9F2C34",
        "LoD/1.10": "0x6F9F2AF4",
        "LoD/1.11": "0x6FA25D76",
        "LoD/1.11b": "0x6FA25D70",
        "LoD/1.12a": "0x6FA25E04",
        "LoD/1.13c": "0x6FA25DE0",
        "LoD/1.13d": "0x6FA25D70"
      },
      "rvas": {
        "LoD/1.07": "0x2C14",
        "LoD/1.08": "0x2C14",
        "LoD/1.09": "0x2C34",
        "LoD/1.09b": "0x2C34",
        "LoD/1.09d": "0x2C34",
        "LoD/1.10": "0x2AF4",
        "LoD/1.11": "0x5D76",
        "LoD/1.11b": "0x5D70",
        "LoD/1.12a": "0x5E04",
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
      "name": "InitializeWorkerThread",
      "signature": "void InitializeWorkerThread(int * pContext)",
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
    "d2mcpclient.dll_SetUnitTargetPosition": {
      "addresses": {
        "LoD/1.07": "0x6FA52C1A",
        "LoD/1.08": "0x6FA52C1A",
        "LoD/1.09": "0x6F9F2C3A",
        "LoD/1.09b": "0x6F9F2C3A",
        "LoD/1.09d": "0x6F9F2C3A",
        "LoD/1.10": "0x6F9F2AFA",
        "LoD/1.11": "0x6FA25DB8",
        "LoD/1.11b": "0x6FA25DB8",
        "LoD/1.12a": "0x6FA25E22",
        "LoD/1.13c": "0x6FA25E28",
        "LoD/1.13d": "0x6FA25DB8"
      },
      "rvas": {
        "LoD/1.07": "0x2C1A",
        "LoD/1.08": "0x2C1A",
        "LoD/1.09": "0x2C3A",
        "LoD/1.09b": "0x2C3A",
        "LoD/1.09d": "0x2C3A",
        "LoD/1.10": "0x2AFA",
        "LoD/1.11": "0x5DB8",
        "LoD/1.11b": "0x5DB8",
        "LoD/1.12a": "0x5E22",
        "LoD/1.13c": "0x5E28",
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
      "name": "SetUnitTargetPosition",
      "signature": "void SetUnitTargetPosition(void * pUnit, int nTargetX, int nTargetY)",
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
    "d2mcpclient.dll_CreateNetSession": {
      "addresses": {
        "LoD/1.07": "0x6FA52C20",
        "LoD/1.08": "0x6FA52C20",
        "LoD/1.09": "0x6F9F2C40",
        "LoD/1.09b": "0x6F9F2C40",
        "LoD/1.09d": "0x6F9F2C40",
        "LoD/1.10": "0x6F9F2B00",
        "LoD/1.11": "0x6FA25D94",
        "LoD/1.11b": "0x6FA25D8E",
        "LoD/1.12a": "0x6FA25E3A",
        "LoD/1.13c": "0x6FA25DE6",
        "LoD/1.13d": "0x6FA25D82"
      },
      "rvas": {
        "LoD/1.07": "0x2C20",
        "LoD/1.08": "0x2C20",
        "LoD/1.09": "0x2C40",
        "LoD/1.09b": "0x2C40",
        "LoD/1.09d": "0x2C40",
        "LoD/1.10": "0x2B00",
        "LoD/1.11": "0x5D94",
        "LoD/1.11b": "0x5D8E",
        "LoD/1.12a": "0x5E3A",
        "LoD/1.13c": "0x5DE6",
        "LoD/1.13d": "0x5D82"
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
      "name": "CreateNetSession",
      "signature": "void * CreateNetSession(char * szIpAddr, int nPort, char * szDescription)",
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
    "d2mcpclient.dll_DestroyNetworkContext": {
      "addresses": {
        "LoD/1.07": "0x6FA52C26",
        "LoD/1.08": "0x6FA52C26",
        "LoD/1.09": "0x6F9F2C46",
        "LoD/1.09b": "0x6F9F2C46",
        "LoD/1.09d": "0x6F9F2C46",
        "LoD/1.10": "0x6F9F2B06",
        "LoD/1.11": "0x6FA25DA6",
        "LoD/1.11b": "0x6FA25DA0",
        "LoD/1.12a": "0x6FA25DFE",
        "LoD/1.13c": "0x6FA25E10",
        "LoD/1.13d": "0x6FA25DA6"
      },
      "rvas": {
        "LoD/1.07": "0x2C26",
        "LoD/1.08": "0x2C26",
        "LoD/1.09": "0x2C46",
        "LoD/1.09b": "0x2C46",
        "LoD/1.09d": "0x2C46",
        "LoD/1.10": "0x2B06",
        "LoD/1.11": "0x5DA6",
        "LoD/1.11b": "0x5DA0",
        "LoD/1.12a": "0x5DFE",
        "LoD/1.13c": "0x5E10",
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
      "name": "DestroyNetworkContext",
      "signature": "void DestroyNetworkContext(void * pContext)",
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
    "d2mcpclient.dll_DequeueQueueData": {
      "addresses": {
        "LoD/1.07": "0x6FA52C2C",
        "LoD/1.08": "0x6FA52C2C",
        "LoD/1.09": "0x6F9F2C4C",
        "LoD/1.09b": "0x6F9F2C4C",
        "LoD/1.09d": "0x6F9F2C4C",
        "LoD/1.10": "0x6F9F2B0C",
        "LoD/1.11": "0x6FA25DA0",
        "LoD/1.11b": "0x6FA25D9A",
        "LoD/1.12a": "0x6FA25DF8",
        "LoD/1.13c": "0x6FA25E0A",
        "LoD/1.13d": "0x6FA25DA0"
      },
      "rvas": {
        "LoD/1.07": "0x2C2C",
        "LoD/1.08": "0x2C2C",
        "LoD/1.09": "0x2C4C",
        "LoD/1.09b": "0x2C4C",
        "LoD/1.09d": "0x2C4C",
        "LoD/1.10": "0x2B0C",
        "LoD/1.11": "0x5DA0",
        "LoD/1.11b": "0x5D9A",
        "LoD/1.12a": "0x5DF8",
        "LoD/1.13c": "0x5E0A",
        "LoD/1.13d": "0x5DA0"
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
      "name": "DequeueQueueData",
      "signature": "ushort DequeueQueueData(void * pContext, byte * pbDest, ushort wMaxSize)",
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
    "d2mcpclient.dll_FogAssert": {
      "addresses": {
        "LoD/1.07": "0x6FA52C32",
        "LoD/1.08": "0x6FA52C32",
        "LoD/1.09": "0x6F9F2C52",
        "LoD/1.09b": "0x6F9F2C52",
        "LoD/1.09d": "0x6F9F2C52",
        "LoD/1.10": "0x6F9F2B12",
        "LoD/1.11": "0x6FA25DBE",
        "LoD/1.11b": "0x6FA25DBE",
        "LoD/1.12a": "0x6FA25E28",
        "LoD/1.13c": "0x6FA25E2E",
        "LoD/1.13d": "0x6FA25DBE"
      },
      "rvas": {
        "LoD/1.07": "0x2C32",
        "LoD/1.08": "0x2C32",
        "LoD/1.09": "0x2C52",
        "LoD/1.09b": "0x2C52",
        "LoD/1.09d": "0x2C52",
        "LoD/1.10": "0x2B12",
        "LoD/1.11": "0x5DBE",
        "LoD/1.11b": "0x5DBE",
        "LoD/1.12a": "0x5E28",
        "LoD/1.13c": "0x5E2E",
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
    "d2mcpclient.dll_FogMemAlloc": {
      "addresses": {
        "LoD/1.07": "0x6FA52C38",
        "LoD/1.08": "0x6FA52C38",
        "LoD/1.09": "0x6F9F2C58",
        "LoD/1.09b": "0x6F9F2C58",
        "LoD/1.09d": "0x6F9F2C58",
        "LoD/1.10": "0x6F9F2B18",
        "LoD/1.11": "0x6FA25DC4",
        "LoD/1.11b": "0x6FA25DC4",
        "LoD/1.12a": "0x6FA25E2E",
        "LoD/1.13c": "0x6FA25E34",
        "LoD/1.13d": "0x6FA25DC4"
      },
      "rvas": {
        "LoD/1.07": "0x2C38",
        "LoD/1.08": "0x2C38",
        "LoD/1.09": "0x2C58",
        "LoD/1.09b": "0x2C58",
        "LoD/1.09d": "0x2C58",
        "LoD/1.10": "0x2B18",
        "LoD/1.11": "0x5DC4",
        "LoD/1.11b": "0x5DC4",
        "LoD/1.12a": "0x5E2E",
        "LoD/1.13c": "0x5E34",
        "LoD/1.13d": "0x5DC4"
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
    "d2mcpclient.dll_ReleasePoolAllocation": {
      "addresses": {
        "LoD/1.07": "0x6FA52C3E",
        "LoD/1.08": "0x6FA52C3E",
        "LoD/1.09": "0x6F9F2C5E",
        "LoD/1.09b": "0x6F9F2C5E",
        "LoD/1.09d": "0x6F9F2C5E",
        "LoD/1.10": "0x6F9F2B1E",
        "LoD/1.11": "0x6FA25D64",
        "LoD/1.11b": "0x6FA25D6A",
        "LoD/1.12a": "0x6FA25DD4",
        "LoD/1.13c": "0x6FA25DDA",
        "LoD/1.13d": "0x6FA25D64"
      },
      "rvas": {
        "LoD/1.07": "0x2C3E",
        "LoD/1.08": "0x2C3E",
        "LoD/1.09": "0x2C5E",
        "LoD/1.09b": "0x2C5E",
        "LoD/1.09d": "0x2C5E",
        "LoD/1.10": "0x2B1E",
        "LoD/1.11": "0x5D64",
        "LoD/1.11b": "0x5D6A",
        "LoD/1.12a": "0x5DD4",
        "LoD/1.13c": "0x5DDA",
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
    "d2mcpclient.dll_SendNetworkMessage": {
      "addresses": {
        "LoD/1.07": "0x6FA52C44",
        "LoD/1.08": "0x6FA52C44",
        "LoD/1.09": "0x6F9F2C64",
        "LoD/1.09b": "0x6F9F2C64",
        "LoD/1.09d": "0x6F9F2C64",
        "LoD/1.10": "0x6F9F2B24",
        "LoD/1.11": "0x6FA25D7C",
        "LoD/1.11b": "0x6FA25D76",
        "LoD/1.12a": "0x6FA25DE6",
        "LoD/1.13c": "0x6FA25DF8",
        "LoD/1.13d": "0x6FA25D8E"
      },
      "rvas": {
        "LoD/1.07": "0x2C44",
        "LoD/1.08": "0x2C44",
        "LoD/1.09": "0x2C64",
        "LoD/1.09b": "0x2C64",
        "LoD/1.09d": "0x2C64",
        "LoD/1.10": "0x2B24",
        "LoD/1.11": "0x5D7C",
        "LoD/1.11b": "0x5D76",
        "LoD/1.12a": "0x5DE6",
        "LoD/1.13c": "0x5DF8",
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
      "name": "SendNetworkMessage",
      "signature": "bool SendNetworkMessage(void * pConnection, void * pMsgData, ushort wMsgSize)",
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
    "d2mcpclient.dll_SStrCopy": {
      "addresses": {
        "LoD/1.07": "0x6FA52C4A",
        "LoD/1.08": "0x6FA52C4A",
        "LoD/1.09": "0x6F9F2C6A",
        "LoD/1.09b": "0x6F9F2C6A",
        "LoD/1.09d": "0x6F9F2C6A",
        "LoD/1.10": "0x6F9F2B2A",
        "LoD/1.11": "0x6FA25D9A",
        "LoD/1.11b": "0x6FA25D94",
        "LoD/1.12a": "0x6FA25DF2",
        "LoD/1.13c": "0x6FA25E04",
        "LoD/1.13d": "0x6FA25D9A"
      },
      "rvas": {
        "LoD/1.07": "0x2C4A",
        "LoD/1.08": "0x2C4A",
        "LoD/1.09": "0x2C6A",
        "LoD/1.09b": "0x2C6A",
        "LoD/1.09d": "0x2C6A",
        "LoD/1.10": "0x2B2A",
        "LoD/1.11": "0x5D9A",
        "LoD/1.11b": "0x5D94",
        "LoD/1.12a": "0x5DF2",
        "LoD/1.13c": "0x5E04",
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
    "d2mcpclient.dll_SStrLen": {
      "addresses": {
        "LoD/1.07": "0x6FA52C50",
        "LoD/1.08": "0x6FA52C50",
        "LoD/1.09": "0x6F9F2C70",
        "LoD/1.09b": "0x6F9F2C70",
        "LoD/1.09d": "0x6F9F2C70",
        "LoD/1.10": "0x6F9F2B30",
        "LoD/1.11": "0x6FA25D82",
        "LoD/1.11b": "0x6FA25D7C",
        "LoD/1.12a": "0x6FA25E1C",
        "LoD/1.13c": "0x6FA25DEC",
        "LoD/1.13d": "0x6FA25D7C"
      },
      "rvas": {
        "LoD/1.07": "0x2C50",
        "LoD/1.08": "0x2C50",
        "LoD/1.09": "0x2C70",
        "LoD/1.09b": "0x2C70",
        "LoD/1.09d": "0x2C70",
        "LoD/1.10": "0x2B30",
        "LoD/1.11": "0x5D82",
        "LoD/1.11b": "0x5D7C",
        "LoD/1.12a": "0x5E1C",
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
    "d2mcpclient.dll_MNE_91b5192dddb8": {
      "addresses": {
        "LoD/1.07": "0x6FA52C56",
        "LoD/1.08": "0x6FA52C56",
        "LoD/1.09": "0x6F9F2C76",
        "LoD/1.09b": "0x6F9F2C76",
        "LoD/1.09d": "0x6F9F2C76",
        "LoD/1.10": "0x6F9F2B36"
      },
      "rvas": {
        "LoD/1.07": "0x2C56",
        "LoD/1.08": "0x2C56",
        "LoD/1.09": "0x2C76",
        "LoD/1.09b": "0x2C76",
        "LoD/1.09d": "0x2C76",
        "LoD/1.10": "0x2B36"
      },
      "sizes": {
        "LoD/1.07": 45,
        "LoD/1.08": 45,
        "LoD/1.09": 45,
        "LoD/1.09b": 45,
        "LoD/1.09d": 45,
        "LoD/1.10": 45
      },
      "signature": "undefined InitializeGlobalConstructors(void)",
      "calling_convention": "__stdcall",
      "comment": "Initialize global constructors and destructors during DLL loading.\n\nAlgorithm:\n1. Check if optional InitializeSubsystem function pointer exists (0x1002e468)\n2. If present, call the InitializeSubsystem function\n3. Call constructor array iterator with constructor table range (0x1002a008 to 0x1002a010)\n4. Call destructor array iterator with destructor table range (0x1002a000 to 0x1002a004)\n5. Return to caller (DllMain)\n\nParameters:\nNone\n\nReturns:\nvoid - No return value, initialization always completes\n\nSpecial Cases:\n- If g_pfnInitializeSubsystem is NULL, step 2 is skipped safely\n- Constructor/destructor arrays may be empty (start == end), iterator handles gracefully\n- Function called during DLL_PROCESS_ATTACH in DllMain\n\nMagic Numbers Reference:\n0x1002e468 - g_pfnInitializeSubsystem function pointer storage\n0x1002a008 - g_ppfnStaticCtorsStart (constructor array beginning)\n0x1002a010 - g_ppfnStaticCtorsEnd (constructor array end)\n0x1002a000 - g_ppfnStaticDtorsStart (destructor array beginning) \n0x1002a004 - g_ppfnStaticDtorsEnd (destructor array end)",
      "name_source": "LoD/1.08",
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
    "d2mcpclient.dll_MNE_cd85d17a6b19": {
      "addresses": {
        "LoD/1.07": "0x6FA52C83",
        "LoD/1.08": "0x6FA52C83",
        "LoD/1.09": "0x6F9F2CA3",
        "LoD/1.09b": "0x6F9F2CA3",
        "LoD/1.09d": "0x6F9F2CA3",
        "LoD/1.10": "0x6F9F2B63",
        "LoD/1.11": "0x6FA21187",
        "LoD/1.11b": "0x6FA21187",
        "LoD/1.12a": "0x6FA21187",
        "LoD/1.13c": "0x6FA21187",
        "LoD/1.13d": "0x6FA214C4"
      },
      "rvas": {
        "LoD/1.07": "0x2C83",
        "LoD/1.08": "0x2C83",
        "LoD/1.09": "0x2CA3",
        "LoD/1.09b": "0x2CA3",
        "LoD/1.09d": "0x2CA3",
        "LoD/1.10": "0x2B63",
        "LoD/1.11": "0x1187",
        "LoD/1.11b": "0x1187",
        "LoD/1.12a": "0x1187",
        "LoD/1.13c": "0x1187",
        "LoD/1.13d": "0x14C4"
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
      "signature": "void ReportError(uint dwErrorCode)",
      "calling_convention": "__cdecl",
      "comment": "Simple error reporting wrapper that forwards error codes with default parameters.\n\nAlgorithm:\n1. Accept the error code parameter from the caller\n2. Forward the error code to FUN_6ff2b2cd along with two zero parameters\n3. Return immediately after the function call\n\nParameters:\ndwErrorCode (uint) - Error code to be reported or logged\n\nReturns:\nvoid - No return value (noreturn function based on callers)",
      "name_source": "LoD/1.08",
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
    "d2mcpclient.dll___exit": {
      "addresses": {
        "LoD/1.07": "0x6FA52C94",
        "LoD/1.08": "0x6FA52C94",
        "LoD/1.09": "0x6F9F2CB4",
        "LoD/1.09b": "0x6F9F2CB4",
        "LoD/1.09d": "0x6F9F2CB4",
        "LoD/1.10": "0x6F9F2B74",
        "LoD/1.11": "0x6FA21198",
        "LoD/1.11b": "0x6FA21198",
        "LoD/1.12a": "0x6FA21198",
        "LoD/1.13c": "0x6FA21198",
        "LoD/1.13d": "0x6FA214D5"
      },
      "rvas": {
        "LoD/1.07": "0x2C94",
        "LoD/1.08": "0x2C94",
        "LoD/1.09": "0x2CB4",
        "LoD/1.09b": "0x2CB4",
        "LoD/1.09d": "0x2CB4",
        "LoD/1.10": "0x2B74",
        "LoD/1.11": "0x1198",
        "LoD/1.11b": "0x1198",
        "LoD/1.12a": "0x1198",
        "LoD/1.13c": "0x1198",
        "LoD/1.13d": "0x14D5"
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
    "d2mcpclient.dll_MNE_7a5e6ed384be": {
      "addresses": {
        "LoD/1.07": "0x6FA52CA5",
        "LoD/1.08": "0x6FA52CA5",
        "LoD/1.09": "0x6F9F2CC5",
        "LoD/1.09b": "0x6F9F2CC5",
        "LoD/1.09d": "0x6F9F2CC5",
        "LoD/1.10": "0x6F9F2B85",
        "LoD/1.11": "0x6FA211A9",
        "LoD/1.11b": "0x6FA211A9",
        "LoD/1.12a": "0x6FA211A9",
        "LoD/1.13c": "0x6FA211A9",
        "LoD/1.13d": "0x6FA214E6"
      },
      "rvas": {
        "LoD/1.07": "0x2CA5",
        "LoD/1.08": "0x2CA5",
        "LoD/1.09": "0x2CC5",
        "LoD/1.09b": "0x2CC5",
        "LoD/1.09d": "0x2CC5",
        "LoD/1.10": "0x2B85",
        "LoD/1.11": "0x11A9",
        "LoD/1.11b": "0x11A9",
        "LoD/1.12a": "0x11A9",
        "LoD/1.13c": "0x11A9",
        "LoD/1.13d": "0x14E6"
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
      "signature": "void InitializeCleanupSequence(void)",
      "calling_convention": "__stdcall",
      "comment": "Initialize cleanup sequence during DLL detach operation.\n\nAlgorithm:\n1. Call FUN_1001f12e with parameters (0, 0, 1) to start cleanup sequence\n2. Return immediately after cleanup initialization\n\nParameters:\nNone - Function takes no parameters\n\nReturns:\nvoid - No return value (cleanup initialization is fire-and-forget)\n\nSpecial Cases:\nCalled only during DLL_PROCESS_DETACH when DAT_1003c940 cleanup flag is clear\nPart of orderly shutdown sequence before main cleanup functions execute\n\nMagic Numbers Reference:\n0x0 - First parameter to FUN_1001f12e (cleanup mode indicator)\n0x0 - Second parameter to FUN_1001f12e (flags/options)  \n0x1 - Third parameter to FUN_1001f12e (initialization phase identifier)",
      "name_source": "LoD/1.08",
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
    "d2mcpclient.dll_MNE_eb17d7abe573": {
      "addresses": {
        "LoD/1.07": "0x6FA52CB4",
        "LoD/1.08": "0x6FA52CB4",
        "LoD/1.09": "0x6F9F2CD4",
        "LoD/1.09b": "0x6F9F2CD4",
        "LoD/1.09d": "0x6F9F2CD4",
        "LoD/1.10": "0x6F9F2B94"
      },
      "rvas": {
        "LoD/1.07": "0x2CB4",
        "LoD/1.08": "0x2CB4",
        "LoD/1.09": "0x2CD4",
        "LoD/1.09b": "0x2CD4",
        "LoD/1.09d": "0x2CD4",
        "LoD/1.10": "0x2B94"
      },
      "sizes": {
        "LoD/1.07": 163,
        "LoD/1.08": 163,
        "LoD/1.09": 163,
        "LoD/1.09b": 163,
        "LoD/1.09d": 163,
        "LoD/1.10": 163
      },
      "signature": "void ProcessCleanupAndExit(uint dwExitCode, int nQuickExit, int nTerminateFlag)",
      "calling_convention": "__cdecl",
      "comment": "Handles DLL/process cleanup operations with selective termination modes.\n\nAlgorithm:\n1. Call setup function FUN_6ff2b372() to initialize cleanup state\n2. Check global termination flag g_dwTerminationActiveFlag - if set to 1, terminate immediately with TerminateProcess\n3. Set global cleanup flag g_dwCleanupFlag = 1 to signal cleanup is active  \n4. Store terminate flag as byte in g_bTerminateFlagStore for later reference\n5. If nQuickExit == 0 (full cleanup mode):\n   - Process dynamic function pointer buffer from g_pbDynamicBufferEnd to g_pbDynamicBufferStart\n   - Call each non-null function pointer in reverse order (typical destructor pattern)\n   - Call static cleanup function pointer arrays from g_ppStaticCleanupArrayStart to g_ppStaticCleanupArrayEnd\n6. Always call final cleanup function pointer arrays from g_ppFinalCleanupArrayStart to g_ppFinalCleanupArrayEnd\n7. If nTerminateFlag == 0: set g_dwTerminationActiveFlag = 1 and call ExitProcess (no return)\n8. Otherwise: call FUN_6ff2b37b() final cleanup and return to caller\n\nParameters:\ndwExitCode (uint): Exit code passed to ExitProcess/TerminateProcess (0-255)\nnQuickExit (int): Cleanup mode flag - 0 = full cleanup with dynamic destructors, non-zero = skip dynamic cleanup\nnTerminateFlag (int): Termination mode - 0 = ExitProcess (no return), non-zero = return to caller\n\nReturns:\nvoid: No return value when nTerminateFlag == 0 (calls ExitProcess)\n      Returns normally when nTerminateFlag != 0 after cleanup\n\nSpecial Cases:\n- If g_dwTerminationActiveFlag already set to 1: bypasses all cleanup, calls TerminateProcess immediately\n- If g_pbDynamicBufferStart is null: skips dynamic buffer processing safely\n- If dynamic buffer traversal reaches invalid range: stops gracefully at g_pbDynamicBufferStart boundary\n- Function pointer arrays are called via CallFunctionPointerArray which handles null ranges safely\n\nMagic Numbers:\n0x1 - Cleanup active flag value stored in g_dwCleanupFlag and g_dwTerminationActiveFlag\n0x4 - Pointer size decrement for buffer traversal (32-bit function pointers)\n\nError Handling:\n- Uses TerminateProcess for immediate shutdown when termination flag pre-set\n- Uses ExitProcess for normal process termination after cleanup\n- Function pointer null checks prevent crashes during dynamic cleanup traversal\n- Buffer boundary checks prevent memory access violations during traversal",
      "name_source": "LoD/1.08",
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
    "d2mcpclient.dll_MNE_f23ef2b3a6cf": {
      "addresses": {
        "LoD/1.07": "0x6FA53F58",
        "LoD/1.08": "0x6FA53F58",
        "LoD/1.09": "0x6F9F3F78",
        "LoD/1.09b": "0x6F9F3F78",
        "LoD/1.09d": "0x6F9F3F78",
        "LoD/1.10": "0x6F9F3E38",
        "LoD/1.11": "0x6FA22892",
        "LoD/1.11b": "0x6FA2349D",
        "LoD/1.12a": "0x6FA234D5",
        "LoD/1.13c": "0x6FA234D5",
        "LoD/1.13d": "0x6FA21DBD"
      },
      "rvas": {
        "LoD/1.07": "0x3F58",
        "LoD/1.08": "0x3F58",
        "LoD/1.09": "0x3F78",
        "LoD/1.09b": "0x3F78",
        "LoD/1.09d": "0x3F78",
        "LoD/1.10": "0x3E38",
        "LoD/1.11": "0x2892",
        "LoD/1.11b": "0x349D",
        "LoD/1.12a": "0x34D5",
        "LoD/1.13c": "0x34D5",
        "LoD/1.13d": "0x1DBD"
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
      "signature": "void ReleaseMemoryAllocationLock(void)",
      "calling_convention": "__stdcall",
      "comment": "Releases the critical section lock used for memory allocation operations.\n\nAlgorithm:\n1. Release critical section index 9 via ReleaseCriticalSectionByIndex\n2. Return to caller\n\nParameters:\nNone\n\nReturns:\nvoid - No return value\n\nSpecial Cases:\nCritical section index 9 is hardcoded and appears to be specifically allocated for memory allocation synchronization. This function is called by ReallocateMemoryWithStrategy to release the lock after memory operations complete.",
      "name_source": "LoD/1.08",
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
    "d2mcpclient.dll_MNE_f1060dff4c8b": {
      "addresses": {
        "LoD/1.07": "0x6FA52D6B",
        "LoD/1.08": "0x6FA52D6B",
        "LoD/1.09": "0x6F9F2D8B",
        "LoD/1.09b": "0x6F9F2D8B",
        "LoD/1.09d": "0x6F9F2D8B",
        "LoD/1.10": "0x6F9F2C4B"
      },
      "rvas": {
        "LoD/1.07": "0x2D6B",
        "LoD/1.08": "0x2D6B",
        "LoD/1.09": "0x2D8B",
        "LoD/1.09b": "0x2D8B",
        "LoD/1.09d": "0x2D8B",
        "LoD/1.10": "0x2C4B"
      },
      "sizes": {
        "LoD/1.07": 26,
        "LoD/1.08": 26,
        "LoD/1.09": 26,
        "LoD/1.09b": 26,
        "LoD/1.09d": 26,
        "LoD/1.10": 26
      },
      "signature": "void RunConstructorArray(void * * ppfnStart, void * * ppfnEnd)",
      "calling_convention": "__cdecl",
      "comment": "Executes an array of constructor or initialization function pointers in sequence.\n\nAlgorithm:\n1. Iterate through function pointer array from ppfnStart to ppfnEnd (exclusive)\n2. For each 4-byte aligned function pointer entry:\n   a. Load the function pointer value into EAX\n   b. Test if pointer is non-null (TEST EAX,EAX) \n   c. Skip null pointers (JZ to increment)\n   d. Call the function pointer (CALL EAX) with no parameters\n3. Advance to next function pointer (ADD ESI,0x4)\n4. Continue until reaching end pointer (CMP ESI,[ESP+0xc])\n5. Return when all valid function pointers have been executed\n\nParameters:\n- ppfnStart (void * *): Pointer to start of function pointer array\n- ppfnEnd (void * *): Pointer to end of function pointer array (exclusive)\n\nReturns:\n- void: No return value\n\nSpecial Cases:\n- Null function pointers are safely skipped without error\n- Empty array (ppfnStart == ppfnEnd) exits immediately\n- No parameter validation - assumes valid array bounds\n\nError Handling:\n- No explicit error handling\n- Relies on caller to provide valid array bounds\n- Function calls are made with no error checking",
      "name_source": "LoD/1.08",
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
    "d2mcpclient.dll_MNE_966ae3d3931d": {
      "addresses": {
        "LoD/1.07": "0x6FA52D85",
        "LoD/1.08": "0x6FA52D85",
        "LoD/1.09": "0x6F9F2DA5",
        "LoD/1.09b": "0x6F9F2DA5",
        "LoD/1.09d": "0x6F9F2DA5",
        "LoD/1.10": "0x6F9F2C65"
      },
      "rvas": {
        "LoD/1.07": "0x2D85",
        "LoD/1.08": "0x2D85",
        "LoD/1.09": "0x2DA5",
        "LoD/1.09b": "0x2DA5",
        "LoD/1.09d": "0x2DA5",
        "LoD/1.10": "0x2C65"
      },
      "sizes": {
        "LoD/1.07": 217,
        "LoD/1.08": 217,
        "LoD/1.09": 217,
        "LoD/1.09b": 217,
        "LoD/1.09d": 217,
        "LoD/1.10": 217
      },
      "signature": "bool DllMain(void * phinstDLL, uint dwReason)",
      "calling_convention": "__stdcall",
      "comment": "DLL entry point that handles process and thread attach/detach notifications.\n\nAlgorithm:\n1. Check dwReason parameter to determine DLL notification type\n2. DLL_PROCESS_ATTACH (1): Initialize DLL when process loads\n   a. Call GetVersion() to get Windows version and store in global\n   b. Extract version components: major (low byte), minor (second byte), build (high word)\n   c. Store version data in separate globals for compatibility checks\n   d. Call initialization routine to verify DLL can load\n   e. Get command line with GetCommandLineA() for argument parsing\n   f. Initialize core subsystems in sequence\n   g. Increment process reference counter\n3. DLL_PROCESS_DETACH (0): Cleanup when process unloads\n   a. Check if process reference counter is positive\n   b. Decrement process reference counter\n   c. Check cleanup flag and call cleanup routine if needed\n   d. Shutdown subsystems in reverse order\n4. DLL_THREAD_DETACH (3): Handle thread cleanup\n   a. Call thread-specific cleanup routine with NULL parameter\n5. Return appropriate status code\n\nParameters:\nphinstDLL (void *): HINSTANCE handle to DLL instance (Windows opaque handle type)\n  IMPLICIT: Parameter passed but not used in this implementation\ndwReason (uint): Reason for calling DLL entry point\n  - 1 (DLL_PROCESS_ATTACH): Process is loading DLL\n  - 0 (DLL_PROCESS_DETACH): Process is unloading DLL  \n  - 3 (DLL_THREAD_DETACH): Thread is exiting\n\nReturns:\nbool: Success status\n  - true (1): DLL initialization/cleanup succeeded\n  - false (0): DLL initialization failed, prevent DLL loading\n\nSpecial Cases:\n- DLL_PROCESS_ATTACH: Returns false if version check or initialization fails\n- DLL_PROCESS_DETACH: Only performs cleanup if reference counter > 0\n- DLL_THREAD_ATTACH (2): Not handled, falls through to return true\n- Invalid dwReason values: Fall through to return true\n\nMagic Numbers Reference:\n0x1 - DLL_PROCESS_ATTACH constant\n0x0 - DLL_PROCESS_DETACH constant  \n0x3 - DLL_THREAD_DETACH constant\n0xff - Byte mask for extracting version components\n0x8 - Bit shift for extracting minor version (second byte)\n0x10 - Bit shift for extracting build number (high word)\n0x100 - Multiplier for combining major and minor version\n\nError Handling:\n- Version API failure: Continues with uninitialized version globals\n- Initialization failure: Returns false to prevent DLL loading\n- Cleanup errors: No error propagation, always returns true for detach\n\nType Design Notes:\n- HINSTANCE parameter correctly typed as void* (Windows opaque handle convention)\n- SSA temporaries (fResult, nTempResult) used for intermediate calculations",
      "name_source": "LoD/1.08",
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
    "d2mcpclient.dll_MNE_bafce56213ce": {
      "addresses": {
        "LoD/1.07": "0x6FA52E5E",
        "LoD/1.08": "0x6FA52E5E",
        "LoD/1.09": "0x6F9F2E7E",
        "LoD/1.09b": "0x6F9F2E7E",
        "LoD/1.09d": "0x6F9F2E7E",
        "LoD/1.10": "0x6F9F2D3E"
      },
      "rvas": {
        "LoD/1.07": "0x2E5E",
        "LoD/1.08": "0x2E5E",
        "LoD/1.09": "0x2E7E",
        "LoD/1.09b": "0x2E7E",
        "LoD/1.09d": "0x2E7E",
        "LoD/1.10": "0x2D3E"
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
    "d2mcpclient.dll___amsg_exit": {
      "addresses": {
        "LoD/1.07": "0x6FA52EFB",
        "LoD/1.08": "0x6FA52EFB",
        "LoD/1.09": "0x6F9F2F1B",
        "LoD/1.09b": "0x6F9F2F1B",
        "LoD/1.09d": "0x6F9F2F1B",
        "LoD/1.10": "0x6F9F2DDB",
        "LoD/1.11": "0x6FA2141D",
        "LoD/1.11b": "0x6FA2141D",
        "LoD/1.12a": "0x6FA2141D",
        "LoD/1.13c": "0x6FA2141D",
        "LoD/1.13d": "0x6FA2175A"
      },
      "rvas": {
        "LoD/1.07": "0x2EFB",
        "LoD/1.08": "0x2EFB",
        "LoD/1.09": "0x2F1B",
        "LoD/1.09b": "0x2F1B",
        "LoD/1.09d": "0x2F1B",
        "LoD/1.10": "0x2DDB",
        "LoD/1.11": "0x141D",
        "LoD/1.11b": "0x141D",
        "LoD/1.12a": "0x141D",
        "LoD/1.13c": "0x141D",
        "LoD/1.13d": "0x175A"
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
    "d2mcpclient.dll_MNE_e1bb2af96e76": {
      "addresses": {
        "LoD/1.07": "0x6FA52F2E",
        "LoD/1.08": "0x6FA52F2E",
        "LoD/1.09": "0x6F9F2F4E",
        "LoD/1.09b": "0x6F9F2F4E",
        "LoD/1.09d": "0x6F9F2F4E",
        "LoD/1.10": "0x6F9F2E0E"
      },
      "rvas": {
        "LoD/1.07": "0x2F2E",
        "LoD/1.08": "0x2F2E",
        "LoD/1.09": "0x2F4E",
        "LoD/1.09b": "0x2F4E",
        "LoD/1.09d": "0x2F4E",
        "LoD/1.10": "0x2E0E"
      },
      "sizes": {
        "LoD/1.07": 41,
        "LoD/1.08": 41,
        "LoD/1.09": 41,
        "LoD/1.09b": 41,
        "LoD/1.09d": 41,
        "LoD/1.10": 41
      },
      "signature": "void InitializeCriticalSections(void)",
      "calling_convention": "__stdcall",
      "comment": "Initialize four critical sections for thread synchronization.\n\nAlgorithm:\n1. Load InitializeCriticalSection function pointer into ESI register for optimization\n2. Initialize first critical section (g_pCriticalSection1) by calling InitializeCriticalSection\n3. Initialize second critical section (g_pCriticalSection2) by calling InitializeCriticalSection  \n4. Initialize third critical section (g_pCriticalSection3) by calling InitializeCriticalSection\n5. Initialize fourth critical section (g_pCriticalSection4) by calling InitializeCriticalSection\n6. Restore ESI register and return\n\nParameters:\nNone\n\nReturns:\nvoid - No return value\n\nSpecial Cases:\nFunction uses register optimization by loading InitializeCriticalSection function pointer \nonce into ESI and calling through the register four times instead of direct calls.\n\nGlobal Variables Referenced:\ng_pCriticalSection1 (0x6ff3650c) - Points to first critical section structure\ng_pCriticalSection2 (0x6ff364fc) - Points to second critical section structure  \ng_pCriticalSection3 (0x6ff364ec) - Points to third critical section structure\ng_pCriticalSection4 (0x6ff364cc) - Points to fourth critical section structure\n\nCalling Context:\nCalled during thread local storage initialization as part of multithreading setup.",
      "name_source": "LoD/1.08",
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
    "d2mcpclient.dll_MNE_a0707ad44a57": {
      "addresses": {
        "LoD/1.07": "0x6FA52F57",
        "LoD/1.08": "0x6FA52F57",
        "LoD/1.09": "0x6F9F2F77",
        "LoD/1.09b": "0x6F9F2F77",
        "LoD/1.09d": "0x6F9F2F77",
        "LoD/1.10": "0x6F9F2E37"
      },
      "rvas": {
        "LoD/1.07": "0x2F57",
        "LoD/1.08": "0x2F57",
        "LoD/1.09": "0x2F77",
        "LoD/1.09b": "0x2F77",
        "LoD/1.09d": "0x2F77",
        "LoD/1.10": "0x2E37"
      },
      "sizes": {
        "LoD/1.07": 108,
        "LoD/1.08": 108,
        "LoD/1.09": 108,
        "LoD/1.09b": 108,
        "LoD/1.09d": 108,
        "LoD/1.10": 108
      },
      "signature": "void CleanupCriticalSections(void)",
      "calling_convention": "__stdcall",
      "comment": "Cleanup and destroy all thread synchronization critical sections.\n\nAlgorithm:\n1. Initialize pointer to start of critical section array (0x6ff364c8)\n2. Loop through array of critical section pointers until end (0x6ff36588)\n3. For each entry, check if pointer is non-null\n4. Skip predefined special critical sections (PTR_DAT_6ff3650c, PTR_DAT_6ff364fc, PTR_DAT_6ff364ec, PTR_DAT_6ff364cc)\n5. If not special section, delete critical section and call cleanup function FUN_6ff2cac5\n6. Advance to next array entry (increment by 4 bytes)\n7. After main loop, explicitly cleanup the four special critical sections\n8. Return to caller\n\nParameters:\nNone - function operates on global critical section array\n\nReturns:\nvoid - no return value, cleanup function\n\nSpecial Cases:\n- Four special critical sections skipped in main loop but cleaned up explicitly at end\n- Array spans 0x320 bytes (200 pointer entries) from 0x6ff364c8 to 0x6ff36588\n- DeleteCriticalSection function pointer loaded from [0x6ff330d8]\n\nMagic Numbers Reference:\n0x6ff364c8 - Start address of critical section pointer array\n0x6ff36588 - End address of critical section pointer array  \n0x6ff3650c - Special critical section 1 (PTR_DAT_6ff3650c)\n0x6ff364fc - Special critical section 2 (PTR_DAT_6ff364fc)\n0x6ff364ec - Special critical section 3 (PTR_DAT_6ff364ec)\n0x6ff364cc - Special critical section 4 (PTR_DAT_6ff364cc)\n0x6ff330d8 - Function pointer to DeleteCriticalSection\n0x4 - Pointer size increment for array iteration\n\nError Handling:\nNone - assumes all pointers valid, DeleteCriticalSection handles invalid input",
      "name_source": "LoD/1.08",
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
    "d2mcpclient.dll_MNE_5ba7875cbad7": {
      "addresses": {
        "LoD/1.07": "0x6FA52FC3",
        "LoD/1.08": "0x6FA52FC3",
        "LoD/1.09": "0x6F9F2FE3",
        "LoD/1.09b": "0x6F9F2FE3",
        "LoD/1.09d": "0x6F9F2FE3",
        "LoD/1.10": "0x6F9F2EA3"
      },
      "rvas": {
        "LoD/1.07": "0x2FC3",
        "LoD/1.08": "0x2FC3",
        "LoD/1.09": "0x2FE3",
        "LoD/1.09b": "0x2FE3",
        "LoD/1.09d": "0x2FE3",
        "LoD/1.10": "0x2EA3"
      },
      "sizes": {
        "LoD/1.07": 97,
        "LoD/1.08": 97,
        "LoD/1.09": 97,
        "LoD/1.09b": 97,
        "LoD/1.09d": 97,
        "LoD/1.10": 97
      },
      "signature": "void AcquireCriticalSectionByIndex(int nCriticalSectionIndex)",
      "calling_convention": "__cdecl",
      "comment": "Thread-safe lazy initialization and acquisition of critical section by array index\n\nAlgorithm:\n1. Calculate pointer to critical section slot in global array g_ppCriticalSections\n2. Check if critical section at index is already initialized (non-null)\n3. If uninitialized, allocate 0x18 bytes for CRITICAL_SECTION structure\n4. If allocation fails, call AmsgExit(0x11) to terminate process\n5. Acquire global initialization lock via recursive call AcquireCriticalSectionByIndex(0x11)\n6. Double-check critical section is still null (race condition protection)\n7. If still null, initialize critical section with InitializeCriticalSection\n8. Store initialized critical section pointer in global array\n9. If another thread initialized it first, free duplicate allocation with DeallocateMemory\n10. Release global initialization lock via FUN_6ff2c45f(0x11)\n11. Enter the requested critical section with EnterCriticalSection\n\nParameters:\nnCriticalSectionIndex - Index into global critical section array g_ppCriticalSections\nIMPLICIT: Uses global initialization lock at index 0x11 for thread-safe lazy initialization\n\nReturns:\nvoid - Function does not return a value, critical section is held upon return\n\nSpecial Cases:\nLock index 0x11 (17) is reserved for the global initialization synchronization lock\nProcess terminates with AmsgExit(0x11) if critical section allocation fails\nDouble-checked locking pattern prevents race conditions during initialization\n\nMagic Numbers Reference:\n0x18 (24 decimal) - Size of Windows CRITICAL_SECTION structure in bytes\n0x11 (17 decimal) - Reserved index for global initialization lock",
      "name_source": "LoD/1.08",
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
    "d2mcpclient.dll_MNE_e83d10405144": {
      "addresses": {
        "LoD/1.07": "0x6FA53024",
        "LoD/1.08": "0x6FA53024",
        "LoD/1.09": "0x6F9F3044",
        "LoD/1.09b": "0x6F9F3044",
        "LoD/1.09d": "0x6F9F3044",
        "LoD/1.10": "0x6F9F2F04",
        "LoD/1.11": "0x6FA214EE",
        "LoD/1.11b": "0x6FA214EE",
        "LoD/1.12a": "0x6FA214EE",
        "LoD/1.13c": "0x6FA214EE",
        "LoD/1.13d": "0x6FA2182B"
      },
      "rvas": {
        "LoD/1.07": "0x3024",
        "LoD/1.08": "0x3024",
        "LoD/1.09": "0x3044",
        "LoD/1.09b": "0x3044",
        "LoD/1.09d": "0x3044",
        "LoD/1.10": "0x2F04",
        "LoD/1.11": "0x14EE",
        "LoD/1.11b": "0x14EE",
        "LoD/1.12a": "0x14EE",
        "LoD/1.13c": "0x14EE",
        "LoD/1.13d": "0x182B"
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
      "signature": "void ReleaseCriticalSectionByIndex(uint dwLockIndex)",
      "calling_convention": "__cdecl",
      "comment": "Releases a CRT critical section lock by its index.\n\nClassification: Leaf function - wrapper around Win32 LeaveCriticalSection.\n\nAlgorithm:\n1. Index into g_apCrtLocks array using dwLockIndex\n2. Call LeaveCriticalSection on the retrieved CRITICAL_SECTION pointer\n\nParameters:\n  dwLockIndex (uint) - Zero-based index into g_apCrtLocks array\n\nReturns:\n  void\n\nSpecial Cases:\n  - No bounds checking on index; caller must ensure valid range\n  - Must be paired with prior CRT_EnterCritSectByIndex call\n\nGlobal Data:\n  g_apCrtLocks (0x6fc38644) - Array of LPCRITICAL_SECTION pointers\n\nCalled By: 12 functions including CRT_EnterCritSectByIndex, CRT_LeaveCritSectExit",
      "name_source": "LoD/1.08",
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
    "d2mcpclient.dll_MNE_1563254ce315": {
      "addresses": {
        "LoD/1.07": "0x6FA53039",
        "LoD/1.08": "0x6FA53039",
        "LoD/1.09": "0x6F9F3059",
        "LoD/1.09b": "0x6F9F3059",
        "LoD/1.09d": "0x6F9F3059",
        "LoD/1.10": "0x6F9F2F19"
      },
      "rvas": {
        "LoD/1.07": "0x3039",
        "LoD/1.08": "0x3039",
        "LoD/1.09": "0x3059",
        "LoD/1.09b": "0x3059",
        "LoD/1.09d": "0x3059",
        "LoD/1.10": "0x2F19"
      },
      "sizes": {
        "LoD/1.07": 84,
        "LoD/1.08": 84,
        "LoD/1.09": 84,
        "LoD/1.09b": 84,
        "LoD/1.09d": 84,
        "LoD/1.10": 84
      },
      "signature": "bool InitializeThreadLocalStorage(void)",
      "calling_convention": "__stdcall",
      "comment": "Initialize thread-local storage for per-thread context management\n\nAlgorithm:\n1. Call cleanup routine to prepare for TLS initialization\n2. Allocate TLS slot using TlsAlloc(), store in global g_dwTlsSlotIndex  \n3. Check if TLS allocation succeeded (index != 0xFFFFFFFF)\n4. Allocate ThreadContext structure memory (116 bytes) via custom allocator\n5. Verify ThreadContext allocation succeeded (pointer not NULL)\n6. Associate ThreadContext with TLS slot using TlsSetValue()\n7. Verify TLS value was set successfully\n8. Initialize ThreadContext structure with InitializeThreadContext()\n9. Get current thread ID and store in context structure\n10. Set context flags field to 0xFFFFFFFF (all flags enabled)\n11. Store thread ID in first field of context structure\n12. Return success status\n\nParameters:\nNone\n\nReturns:\nbool: true (1) on successful TLS initialization, false (0) on any failure\n\nSpecial Cases:\nIf TLS allocation fails (returns 0xFFFFFFFF), function exits immediately with failure\nIf memory allocation fails, function exits with failure  \nIf TLS value cannot be set, function exits with failure\nEach failure condition branches to common exit_failure label\n\nMagic Numbers Reference:\n0x74 (116 decimal): Size of ThreadContext structure allocation\n0xFFFFFFFF: Invalid TLS index return value indicating allocation failure\n0xFFFFFFFF: Flag mask for enabling all context flags\n\nError Handling:\nTLS allocation failure: return 0\nMemory allocation failure: return 0  \nTLS value set failure: return 0\nAll errors result in immediate function exit with false return value",
      "name_source": "LoD/1.08",
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
    "d2mcpclient.dll_MNE_83d07e3c014d": {
      "addresses": {
        "LoD/1.07": "0x6FA5308D",
        "LoD/1.08": "0x6FA5308D",
        "LoD/1.09": "0x6F9F30AD",
        "LoD/1.09b": "0x6F9F30AD",
        "LoD/1.09d": "0x6F9F30AD",
        "LoD/1.10": "0x6F9F2F6D",
        "LoD/1.11": "0x6FA234A6",
        "LoD/1.11b": "0x6FA234A6",
        "LoD/1.12a": "0x6FA234DE",
        "LoD/1.13c": "0x6FA234DE",
        "LoD/1.13d": "0x6FA237E6"
      },
      "rvas": {
        "LoD/1.07": "0x308D",
        "LoD/1.08": "0x308D",
        "LoD/1.09": "0x30AD",
        "LoD/1.09b": "0x30AD",
        "LoD/1.09d": "0x30AD",
        "LoD/1.10": "0x2F6D",
        "LoD/1.11": "0x34A6",
        "LoD/1.11b": "0x34A6",
        "LoD/1.12a": "0x34DE",
        "LoD/1.13c": "0x34DE",
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
      "signature": "void TlsCleanupSlot(void)",
      "calling_convention": "__stdcall",
      "comment": "Cleans up TLS (Thread Local Storage) resources and calls additional cleanup\n\nAlgorithm:\n1. Call FUN_6ff2c392() for additional cleanup operations\n2. Load current TLS slot index from g_dwTlsSlotIndex global variable\n3. Compare slot index against invalid value 0xffffffff \n4. If slot is valid (not 0xffffffff), proceed with TLS cleanup\n5. Call TlsFree() with the valid slot index to release TLS slot\n6. Set g_dwTlsSlotIndex to 0xffffffff to mark as invalid\n7. Return to caller\n\nParameters:\nNone\n\nReturns:\nvoid - No return value\n\nSpecial Cases:\nIf g_dwTlsSlotIndex is already 0xffffffff (invalid), skip TLS cleanup\n\nMagic Numbers Reference:\n0xffffffff (4294967295) - Invalid TLS slot index constant used by Windows API\n\nError Handling:\nNo explicit error handling - relies on TlsFree() API behavior",
      "name_source": "LoD/1.08",
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
    "d2mcpclient.dll_MNE_a1900c49d3b8": {
      "addresses": {
        "LoD/1.07": "0x6FA530AB",
        "LoD/1.08": "0x6FA530AB",
        "LoD/1.09": "0x6F9F30CB",
        "LoD/1.09b": "0x6F9F30CB",
        "LoD/1.09d": "0x6F9F30CB",
        "LoD/1.10": "0x6F9F2F8B",
        "LoD/1.11": "0x6FA218CB",
        "LoD/1.11b": "0x6FA218CB",
        "LoD/1.12a": "0x6FA218CB",
        "LoD/1.13c": "0x6FA218CB",
        "LoD/1.13d": "0x6FA21C07"
      },
      "rvas": {
        "LoD/1.07": "0x30AB",
        "LoD/1.08": "0x30AB",
        "LoD/1.09": "0x30CB",
        "LoD/1.09b": "0x30CB",
        "LoD/1.09d": "0x30CB",
        "LoD/1.10": "0x2F8B",
        "LoD/1.11": "0x18CB",
        "LoD/1.11b": "0x18CB",
        "LoD/1.12a": "0x18CB",
        "LoD/1.13c": "0x18CB",
        "LoD/1.13d": "0x1C07"
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
      "signature": "void InitializeThreadContext(ThreadContext * pThreadContext)",
      "calling_convention": "__cdecl",
      "comment": "Initialize thread-specific context structure with SEH error handler table.\n\nAlgorithm:\n1. Store pointer to global SEH error code table in reserved2 field (offset 0x50)\n2. Set reserved1[0xc] field (offset 0x14) to 1 to mark context as initialized\n3. Set reserved1[0xd] through reserved1[0xf] fields to 0 for cleanup\n4. Return to caller with context structure initialized\n\nParameters:\npThreadContext - Pointer to ThreadContext structure to initialize\n\nReturns:\nvoid - No return value, initializes context structure in-place\n\nSpecial Cases:\nMagic number 0x1 at offset 0x14 indicates successful initialization state\n\nStructure Layout:\nOffset | Size | Field Name    | Type     | Description\n-------|------|---------------|----------|----------------------------------\n0x14   | 4    | reserved1[12] | byte     | Initialization flag (1=initialized)\n0x15   | 1    | reserved1[13] | byte     | Clear to 0 during initialization\n0x16   | 1    | reserved1[14] | byte     | Clear to 0 during initialization  \n0x17   | 1    | reserved1[15] | byte     | Clear to 0 during initialization\n0x50   | 4    | reserved2[0]  | uint *   | Pointer to SEH error code table",
      "name_source": "LoD/1.08",
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
    "d2mcpclient.dll_MNE_6dad5d067638": {
      "addresses": {
        "LoD/1.07": "0x6FA530BE",
        "LoD/1.08": "0x6FA530BE",
        "LoD/1.09": "0x6F9F30DE",
        "LoD/1.09b": "0x6F9F30DE",
        "LoD/1.09d": "0x6F9F30DE",
        "LoD/1.10": "0x6F9F2F9E",
        "LoD/1.11": "0x6FA218DE",
        "LoD/1.11b": "0x6FA218DE",
        "LoD/1.12a": "0x6FA218DE",
        "LoD/1.13c": "0x6FA218DE",
        "LoD/1.13d": "0x6FA21C1A"
      },
      "rvas": {
        "LoD/1.07": "0x30BE",
        "LoD/1.08": "0x30BE",
        "LoD/1.09": "0x30DE",
        "LoD/1.09b": "0x30DE",
        "LoD/1.09d": "0x30DE",
        "LoD/1.10": "0x2F9E",
        "LoD/1.11": "0x18DE",
        "LoD/1.11b": "0x18DE",
        "LoD/1.12a": "0x18DE",
        "LoD/1.13c": "0x18DE",
        "LoD/1.13d": "0x1C1A"
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
      "signature": "DWORD * GetOrCreateThreadContext(void)",
      "calling_convention": "__stdcall",
      "comment": "Gets or creates the thread-specific context for the current thread.\n\nAlgorithm:\n1. Preserve current thread error state using GetLastError()\n2. Attempt to retrieve existing ThreadContext from TLS using g_dwTlsSlotIndex\n3. If no context exists (NULL pointer):\n   a. Allocate new ThreadContext structure (116 bytes) via FUN_6ff2cbae\n   b. If allocation successful, store context in TLS using TlsSetValue\n   c. If TLS storage successful:\n      - Initialize the context structure using InitializeThreadContext\n      - Get current thread ID and store in context->reserved0 (offset 0x0)\n      - Set context flags to 0xFFFFFFFF (offset 0x4)\n   d. If allocation or TLS storage fails, call AmsgExit(0x10) to terminate\n4. Restore original error state using SetLastError()\n5. Return pointer to ThreadContext structure\n\nParameters:\nNone\n\nReturns:\nThreadContext* - Pointer to thread-specific context structure\n                 Never returns NULL (terminates process on failure)\n\nSpecial Cases:\n- Process termination via AmsgExit(0x10) if memory allocation fails\n- Process termination if TLS storage assignment fails\n- Error code preservation ensures GetLastError() state is unchanged\n\nMagic Numbers Reference:\n0x74 (116 decimal) - Size of ThreadContext structure allocation\n0x10 (16 decimal) - Exit code for thread context allocation failure\n0xFFFFFFFF - Default flag value set in ThreadContext.dwFlags\n\nStructure Layout:\nOffset | Size | Field Name | Type  | Description\n-------|------|------------|-------|------------------------------------------\n0x0    | 4    | reserved0  | DWORD | Thread ID storage (misleading field name)\n0x4    | 4    | dwFlags    | DWORD | Thread context flags (set to 0xFFFFFFFF)\n...    | ...  | ...        | ...   | (Additional fields initialized by InitializeThreadContext)",
      "name_source": "LoD/1.08",
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
    "d2mcpclient.dll_MNE_17d5e4a2ea8e": {
      "addresses": {
        "LoD/1.07": "0x6FA53125",
        "LoD/1.08": "0x6FA53125",
        "LoD/1.09": "0x6F9F3145",
        "LoD/1.09b": "0x6F9F3145",
        "LoD/1.09d": "0x6F9F3145",
        "LoD/1.10": "0x6F9F3005"
      },
      "rvas": {
        "LoD/1.07": "0x3125",
        "LoD/1.08": "0x3125",
        "LoD/1.09": "0x3145",
        "LoD/1.09b": "0x3145",
        "LoD/1.09d": "0x3145",
        "LoD/1.10": "0x3005"
      },
      "sizes": {
        "LoD/1.07": 160,
        "LoD/1.08": 160,
        "LoD/1.09": 160,
        "LoD/1.09b": 160,
        "LoD/1.09d": 160,
        "LoD/1.10": 160
      },
      "signature": "void CleanupThreadContext(ThreadContext * pThreadContext)",
      "calling_convention": "__cdecl",
      "comment": "Cleanup thread context structure by deallocating all associated memory buffers.\n\nAlgorithm:\n1. Validate TLS slot index is initialized (not 0xffffffff)\n2. Determine thread context pointer from parameter or TLS storage\n3. Deallocate memory pointers in reserved1 field at offsets 0x1c, 0x20, 0x28, 0x30, 0x38, 0x3c\n4. Check if reserved2 field points to non-default error code array\n5. Deallocate custom error code array if not using global default\n6. Deallocate the thread context structure itself\n7. Clear TLS slot by setting to NULL\n\nParameters:\npThreadContext: Pointer to ThreadContext structure to cleanup, or NULL to retrieve from TLS\n\nReturns:\nvoid - No return value\n\nSpecial Cases:\nIf pThreadContext is NULL, retrieves current thread context from TLS storage\nIf TLS slot is invalid (0xffffffff), function returns immediately\nDefault error codes array (g_adwSehErrorCodes) at 0x6ff36908 is not deallocated\n\nMagic Numbers Reference:\n0xffffffff - Invalid TLS slot index indicating uninitialized TLS\n0x1c, 0x20, 0x28, 0x30, 0x38, 0x3c - Offsets to memory buffer pointers in reserved1\n0x6ff36908 - Address of global default SEH error codes array (g_adwSehErrorCodes)",
      "name_source": "LoD/1.08",
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
    "d2mcpclient.dll_MNE_1352fc0555ea": {
      "addresses": {
        "LoD/1.07": "0x6FA531C5",
        "LoD/1.08": "0x6FA531C5",
        "LoD/1.09": "0x6F9F31E5",
        "LoD/1.09b": "0x6F9F31E5",
        "LoD/1.09d": "0x6F9F31E5",
        "LoD/1.10": "0x6F9F30A5"
      },
      "rvas": {
        "LoD/1.07": "0x31C5",
        "LoD/1.08": "0x31C5",
        "LoD/1.09": "0x31E5",
        "LoD/1.09b": "0x31E5",
        "LoD/1.09d": "0x31E5",
        "LoD/1.10": "0x30A5"
      },
      "sizes": {
        "LoD/1.07": 444,
        "LoD/1.08": 444,
        "LoD/1.09": 444,
        "LoD/1.09b": 444,
        "LoD/1.09d": 444,
        "LoD/1.10": 444
      },
      "signature": "void InitializeStdIoStreams(void)",
      "calling_convention": "__stdcall",
      "comment": "Initializes C runtime standard I/O stream descriptors for stdin/stdout/stderr\n\nAlgorithm:\n1. Allocate 0x480 bytes for initial StreamIO descriptor block (32 streams)\n2. Initialize all 32 stream descriptors with default state (closed, flags 0x0A)\n3. Call GetStartupInfoA to retrieve process startup information\n4. If startup info contains inherited handles (cbReserved2 != 0):\n   a. Parse handle table from lpReserved2 pointer\n   b. Limit handle count to 0x800 maximum for memory safety\n   c. Allocate additional StreamIO blocks if needed (32 streams per block)\n   d. For each inherited handle: validate handle and flags, set stream descriptor\n5. For streams 0, 1, 2 (stdin/stdout/stderr): if not inherited, get standard handles\n6. Set handle type flags based on GetFileType: 0x08 for pipes, 0x40 for character devices\n7. Call SetHandleCount with total allocated handle count\n\nParameters:\nNone\n\nReturns:\nNone (void function)\n\nSpecial Cases:\n- Memory allocation failure triggers AmsgExit(0x1B) - fatal error\n- Invalid handles (0xFFFFFFFF) are marked with 0x81 flags  \n- Handle count clamped to 0x800 maximum to prevent excessive memory allocation\n- Stream indices use bit operations: bucket = index >> 5, offset = index & 0x1F\n\nMagic Numbers:\n0x480 = 1152 bytes = 32 * 36 byte StreamIO structures per allocation block\n0x20 = 32 streams per descriptor block  \n0x24 = 36 bytes = size of StreamIO structure\n0x800 = 2048 maximum inherited handles supported\n0x1B = 27 decimal = exit code for memory allocation failure\n0xFFFFFFF6 = STD_INPUT_HANDLE (-10)\n0xFFFFFFF5 = STD_OUTPUT_HANDLE (-11) \n0xFFFFFFF4 = STD_ERROR_HANDLE (-12)\n0x81 = stream flags for standard handles (binary mode + allocated)\n0x80 = STREAM_ALLOCATED flag\n0x40 = STREAM_CHARACTER_DEVICE flag (console)\n0x08 = STREAM_PIPE flag\n0x01 = inherited handle valid flag in startup info\n0x0A = 10 decimal = default stream flags (line buffered)\n\nStructure Layout:\nOffset | Size | Field Name | Type | Description\n-------|------|------------|------|------------\n0x00   | 4    | pBase      | void*| File handle or buffer pointer  \n0x04   | 1    | nPosition  | byte | Stream status flags\n0x05   | 1    | (padding)  | byte | Line buffer mode (0x0A = LF)\n0x08   | 4    | pCurrent   | void*| Current position in buffer\n0x0C   | 24   | (other)    | -    | Additional StreamIO fields\n\nFlag Bits:\n0x01 = STREAM_VALID (handle inherited and valid)\n0x08 = STREAM_PIPE (pipe handle type)  \n0x40 = STREAM_CHARACTER (character device - console)\n0x80 = STREAM_ALLOCATED (descriptor allocated and active)\n0x81 = STREAM_STANDARD (standard handle - stdin/stdout/stderr)",
      "name_source": "LoD/1.08",
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
    "d2mcpclient.dll_MNE_b7026c232ba5": {
      "addresses": {
        "LoD/1.07": "0x6FA53381",
        "LoD/1.08": "0x6FA53381",
        "LoD/1.09": "0x6F9F33A1",
        "LoD/1.09b": "0x6F9F33A1",
        "LoD/1.09d": "0x6F9F33A1",
        "LoD/1.10": "0x6F9F3261"
      },
      "rvas": {
        "LoD/1.07": "0x3381",
        "LoD/1.08": "0x3381",
        "LoD/1.09": "0x33A1",
        "LoD/1.09b": "0x33A1",
        "LoD/1.09d": "0x33A1",
        "LoD/1.10": "0x3261"
      },
      "sizes": {
        "LoD/1.07": 84,
        "LoD/1.08": 84,
        "LoD/1.09": 84,
        "LoD/1.09b": 84,
        "LoD/1.09d": 84,
        "LoD/1.10": 84
      },
      "signature": "void CleanupStreamDescriptors(void)",
      "calling_convention": "__stdcall",
      "comment": "Cleanup and deallocate all StreamIO descriptor arrays during DLL shutdown.\n\nAlgorithm:\n1. Initialize pointer to global stream descriptor array at 0x6ff3b440\n2. For each descriptor pointer in the array (up to 0x6ff3b540):\n   a. Check if descriptor pointer is non-null\n   b. If valid, iterate through 32 StreamIO structures (0x20 entries)\n   c. For each StreamIO structure, check critical section at offset -4 from dwFlags\n   d. If critical section exists, call DeleteCriticalSection to cleanup\n   e. Advance to next StreamIO structure (0x24 byte stride)\n3. After processing all structures in descriptor, deallocate entire descriptor memory\n4. Set descriptor pointer to null to prevent double-free\n5. Move to next descriptor pointer and repeat\n\nParameters:\nNone\n\nReturns:\nvoid - No return value\n\nSpecial Cases:\n- Handles null descriptor pointers safely by skipping\n- Uses boundary checking (pStreamEnd < pStreamEnd + 0x20) for validation\n- Critical section cleanup only performed if critical section field is non-null\n- Memory deallocation performed after all critical sections cleaned up\n\nMagic Numbers Reference:\n- 0x20 (32): Number of StreamIO structures per descriptor array\n- 0x24 (36): Size of each StreamIO structure in bytes\n- 0x6ff3b440: Base address of global stream descriptor array\n- 0x6ff3b540: End address of global stream descriptor array\n- -0x4: Offset from dwFlags field to critical section field in StreamIO structure\n\nStructure Layout:\nStreamIO (36 bytes):\nOffset | Size | Field Name        | Type                    | Description\n+0x00  | 4    | pCriticalSection  | _RTL_CRITICAL_SECTION*  | Synchronization object\n+0x04  | 4    | dwFlags          | uint                    | Stream status flags\n+0x08  | 28   | (remaining)      | byte[28]               | Additional stream data",
      "name_source": "LoD/1.08",
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
    "d2mcpclient.dll_MNE_6e538b3bbbee": {
      "addresses": {
        "LoD/1.07": "0x6FA533D5",
        "LoD/1.08": "0x6FA533D5",
        "LoD/1.09": "0x6F9F33F5",
        "LoD/1.09b": "0x6F9F33F5",
        "LoD/1.09d": "0x6F9F33F5",
        "LoD/1.10": "0x6F9F32B5"
      },
      "rvas": {
        "LoD/1.07": "0x33D5",
        "LoD/1.08": "0x33D5",
        "LoD/1.09": "0x33F5",
        "LoD/1.09b": "0x33F5",
        "LoD/1.09d": "0x33F5",
        "LoD/1.10": "0x32B5"
      },
      "sizes": {
        "LoD/1.07": 185,
        "LoD/1.08": 185,
        "LoD/1.09": 185,
        "LoD/1.09b": 185,
        "LoD/1.09d": 185,
        "LoD/1.10": 185
      },
      "signature": "void InitializeEnvironmentVariables(void)",
      "calling_convention": "__stdcall",
      "comment": "Initialize environment variables by parsing command line arguments or environment data.\n\nAlgorithm:\n1. Check if initialization flag (DAT_1003cde8) is zero and call FUN_100217c1() if needed\n2. Count non-assignment entries by iterating through string array at DAT_1003c8b4\n3. Skip entries containing '=' character (assignment operators)\n4. Allocate memory for pointer array to hold (count + 1) string pointers\n5. Store allocated array pointer in global _DAT_1003c924\n6. Validate allocation succeeded, exit with error code 9 if failed\n7. Iterate through string array again, copying non-assignment entries\n8. For each valid entry, allocate buffer and copy string using FUN_10020190\n9. Increment array pointer after each successful copy\n10. Free original string data at DAT_1003c8b4 and set to NULL\n11. Null-terminate the new pointer array\n12. Set completion flag _DAT_1003cde4 to 1\n\nParameters:\nNone\n\nReturns:\nvoid - Function performs initialization and exits on allocation failure\n\nSpecial Cases:\n- Exit with AmsgExit(9) if memory allocation fails\n- Skip entries containing '=' character (environment variable assignments)\n- DAT_1003c8b4 contains original string data, freed after processing\n- _DAT_1003c924 stores the resulting array of string pointers\n- _DAT_1003cde4 flag indicates completion status\n\nMagic Numbers:\n0x9 (9) - Error exit code for memory allocation failure\n0x3D (61) - ASCII value for '=' character used to filter assignments",
      "name_source": "LoD/1.08",
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
    "d2mcpclient.dll_MNE_78c0be793b20": {
      "addresses": {
        "LoD/1.07": "0x6FA5348E",
        "LoD/1.08": "0x6FA5348E",
        "LoD/1.09": "0x6F9F34AE",
        "LoD/1.09b": "0x6F9F34AE",
        "LoD/1.09d": "0x6F9F34AE",
        "LoD/1.10": "0x6F9F336E"
      },
      "rvas": {
        "LoD/1.07": "0x348E",
        "LoD/1.08": "0x348E",
        "LoD/1.09": "0x34AE",
        "LoD/1.09b": "0x34AE",
        "LoD/1.09d": "0x34AE",
        "LoD/1.10": "0x336E"
      },
      "sizes": {
        "LoD/1.07": 153,
        "LoD/1.08": 153,
        "LoD/1.09": 153,
        "LoD/1.09b": 153,
        "LoD/1.09d": 153,
        "LoD/1.10": 153
      },
      "signature": "void InitializeModuleData(void)",
      "calling_convention": "__stdcall",
      "comment": "Initialize module data structures and process filename to create dynamic table\n\nAlgorithm:\n1. Check global initialization flag (DAT_1003cde8); call FUN_100217c1() if uninitialized\n2. Get current module filename using GetModuleFileNameA into 260-byte global buffer\n3. Store filename pointer in global variable _DAT_1003c934 for future reference\n4. Select filename source: use override from DAT_1003ce10 if available, otherwise use module filename\n5. Call FUN_1001f501 first time with null pointers to query table size requirements\n6. Allocate memory: dwCount * 4 bytes for main table + dwDataSize bytes for auxiliary data\n7. Validate allocation success; exit with code 8 if malloc fails\n8. Call FUN_1001f501 second time to populate allocated table and auxiliary data\n9. Store table pointer in global _DAT_1003c91c and adjusted count in _DAT_1003c918\n\nParameters:\nNone - function called during DLL initialization\n\nReturns:\nvoid - sets global variables _DAT_1003c91c (table pointer) and _DAT_1003c918 (count-1)\n\nSpecial Cases:\n- Exit code 8: Memory allocation failure\n- Override filename: DAT_1003ce10 takes precedence if first byte non-zero\n- Count adjustment: _DAT_1003c918 stores count decremented by 1\n\nMagic Numbers Reference:\n0x104 (260 decimal): Maximum path length for GetModuleFileNameA buffer\n0x8: Exit code for memory allocation failure\n0x4: Size multiplier for table entries (DWORD/uint size)",
      "name_source": "LoD/1.08",
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
    "d2mcpclient.dll_MNE_50cd6b6fd69b": {
      "addresses": {
        "LoD/1.07": "0x6FA53527",
        "LoD/1.08": "0x6FA53527",
        "LoD/1.09": "0x6F9F3547",
        "LoD/1.09b": "0x6F9F3547",
        "LoD/1.09d": "0x6F9F3547",
        "LoD/1.10": "0x6F9F3407"
      },
      "rvas": {
        "LoD/1.07": "0x3527",
        "LoD/1.08": "0x3527",
        "LoD/1.09": "0x3547",
        "LoD/1.09b": "0x3547",
        "LoD/1.09d": "0x3547",
        "LoD/1.10": "0x3407"
      },
      "sizes": {
        "LoD/1.07": 436,
        "LoD/1.08": 436,
        "LoD/1.09": 436,
        "LoD/1.09b": 436,
        "LoD/1.09d": 436,
        "LoD/1.10": 436
      },
      "signature": "void ParseCommandLineArguments(char * lpszCmdLine, char * * lpszArgv, char * szOutputBuffer, int * pnArgc, int * pnTotalChars)",
      "calling_convention": "__cdecl",
      "comment": "Parses command line string into individual arguments with quote and escape handling\n\nAlgorithm:\n1. Initialize output counters: set argc=1, totalChars=0\n2. Store first argument pointer in argv[0] if argv provided\n3. Check if command line starts with quote (0x22):\n   a. If quoted: Parse until closing quote, handle escape sequences\n   b. If unquoted: Parse until space (0x20) or tab (0x09)\n4. Use character lookup table at 0x1003cbc0 bit 4 to identify escapable chars\n5. Skip whitespace between arguments using space/tab delimiters\n6. For each argument found:\n   a. Store argument pointer in argv array if provided\n   b. Increment argc counter\n   c. Handle backslash escape sequences (\\\\ becomes \\)\n   d. Toggle quote mode on unescaped quotes, handle doubled quotes (\"\")\n   e. Copy characters to output buffer if provided\n   f. Null-terminate argument in output buffer\n7. Null-terminate argv array and increment argc for final count\n\nParameters:\n- cmdLine: Input command line string to parse\n- argv: Array to store pointers to parsed arguments (NULL = count only)\n- outputBuffer: Buffer to store null-terminated argument strings (NULL = count only)\n- argc: Pointer to receive argument count (includes program name)\n- totalChars: Pointer to receive total characters needed for all arguments\n\nReturns:\n- void (results returned through output parameters)\n\nSpecial Cases:\n- If argv is NULL: Only counts arguments without storing pointers\n- If outputBuffer is NULL: Only counts characters without copying\n- Empty quotes \"\" create empty argument\n- Backslash at end of line becomes literal backslash\n- Doubled quotes (\"\") inside quoted string become single quote\n\nMagic Numbers Reference:\n- 0x22 (34): Double quote character for argument quoting\n- 0x20 (32): Space character - argument delimiter\n- 0x09 (9): Tab character - argument delimiter  \n- 0x5C (92): Backslash character for escape sequences\n- 0x1003cbc0: Character classification table base address\n- 0x4: Bit mask for escapable character flag in lookup table\n\nCharacter Classification Table:\nThe lookup table at 0x1003cbc0 contains character class flags where\nbit 4 (value 0x4) indicates characters that require escape handling.\nThis typically includes characters like quotes, backslashes, and \nother shell metacharacters that need special processing.",
      "name_source": "LoD/1.08",
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
    "d2mcpclient.dll_MNE_ee22dcb18299": {
      "addresses": {
        "LoD/1.07": "0x6FA536DB",
        "LoD/1.08": "0x6FA536DB",
        "LoD/1.09": "0x6F9F36FB",
        "LoD/1.09b": "0x6F9F36FB",
        "LoD/1.09d": "0x6F9F36FB",
        "LoD/1.10": "0x6F9F35BB"
      },
      "rvas": {
        "LoD/1.07": "0x36DB",
        "LoD/1.08": "0x36DB",
        "LoD/1.09": "0x36FB",
        "LoD/1.09b": "0x36FB",
        "LoD/1.09d": "0x36FB",
        "LoD/1.10": "0x35BB"
      },
      "sizes": {
        "LoD/1.07": 306,
        "LoD/1.08": 306,
        "LoD/1.09": 306,
        "LoD/1.09b": 306,
        "LoD/1.09d": 306,
        "LoD/1.10": 306
      },
      "signature": "char * GetEnvironmentStringsConverted(void)",
      "calling_convention": "__stdcall",
      "comment": "Retrieves and converts environment strings to ANSI format with automatic Unicode/ANSI detection.\n\nAlgorithm:\n1. Check global state flag DAT_1003ca4c for preferred string format\n2. If state is 0 (uninitialized), attempt Unicode path first via GetEnvironmentStringsW()\n3. If Unicode strings available, set state to 1 (Unicode mode) and process wide strings\n4. If Unicode fails, fall back to ANSI path via GetEnvironmentStrings() and set state to 2\n5. For Unicode processing: iterate through null-terminated string array to calculate total length\n6. Convert wide character count to byte count and call WideCharToMultiByte() for size estimation\n7. Allocate buffer using malloc() with required size\n8. Perform actual conversion using WideCharToMultiByte() to allocated buffer\n9. If conversion fails, free buffer and return NULL\n10. For ANSI processing: iterate through ANSI string array to calculate total length\n11. Allocate buffer and copy strings using FUN_100217e0 (memory copy function)\n12. Free original environment strings using appropriate API (W or A version)\n13. Return allocated buffer containing converted environment strings\n\nParameters:\nNone - function takes no parameters\n\nReturns:\nchar * - Pointer to allocated buffer containing environment strings in ANSI format\nNULL - If environment strings unavailable or memory allocation/conversion fails\n\nSpecial Cases:\nState flag values: 0 = uninitialized, 1 = Unicode mode, 2 = ANSI mode\nReturns NULL for invalid state values or API failures\nCaller responsible for freeing returned buffer\n\nMagic Numbers Reference:\n0x1003ca4c - Global state flag for environment string format preference\n0 - Uninitialized state\n1 - Unicode (wide character) mode  \n2 - ANSI (multibyte character) mode\n\nError Handling:\nGetEnvironmentStringsW() failure - Falls back to ANSI mode\nGetEnvironmentStrings() failure - Returns NULL immediately\nmalloc() failure - Returns NULL  \nWideCharToMultiByte() failure - Frees allocated buffer and returns NULL\nInvalid state flag - Returns NULL",
      "name_source": "LoD/1.08",
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
    "d2mcpclient.dll_MNE_d8be7433da89": {
      "addresses": {
        "LoD/1.07": "0x6FA5380D",
        "LoD/1.08": "0x6FA5380D",
        "LoD/1.09": "0x6F9F382D",
        "LoD/1.09b": "0x6F9F382D",
        "LoD/1.09d": "0x6F9F382D",
        "LoD/1.10": "0x6F9F36ED"
      },
      "rvas": {
        "LoD/1.07": "0x380D",
        "LoD/1.08": "0x380D",
        "LoD/1.09": "0x382D",
        "LoD/1.09b": "0x382D",
        "LoD/1.09d": "0x382D",
        "LoD/1.10": "0x36ED"
      },
      "sizes": {
        "LoD/1.07": 45,
        "LoD/1.08": 45,
        "LoD/1.09": 45,
        "LoD/1.09b": 45,
        "LoD/1.09d": 45,
        "LoD/1.10": 45
      },
      "signature": "void GetPEMachineType(BYTE * pbMachineType)",
      "calling_convention": "__cdecl",
      "comment": "Extracts the processor architecture machine type from the current module's PE header.\n\nAlgorithm:\n1. Zero the output buffer to ensure clean state\n2. Get handle to current module using GetModuleHandleA(NULL)\n3. Validate PE signature by checking for MZ header (0x5A4D)\n4. Read PE header offset from DOS header at offset 0x3C\n5. Validate PE header offset is non-zero\n6. Calculate COFF header address: module base + PE offset + COFF header\n7. Extract 2-byte machine type from COFF header at offset +0x18\n8. Store machine type bytes in little-endian format in output buffer\n\nParameters:\npbMachineType: BYTE * - Pointer to 2-byte buffer to receive machine type value\n               Buffer receives little-endian machine type (IMAGE_FILE_MACHINE_* constants)\n\nReturns:\nvoid - No return value, machine type written to output buffer\n       If PE validation fails, buffer remains zeroed\n\nMagic Numbers Reference:\n0x5A4D - PE MZ signature (\"MZ\" in ASCII, marks valid DOS/PE executable)\n0x3C   - Offset in DOS header containing PE header file offset\n0x18   - Offset in PE COFF header containing machine type field\n\nError Handling:\n- Invalid module handle: Function exits, buffer remains zeroed\n- Invalid MZ signature: Function exits, buffer remains zeroed  \n- Zero PE header offset: Function exits, buffer remains zeroed\n- All error conditions leave output buffer in clean zeroed state\n\nPE Structure Layout:\nOffset | Size | Field Name    | Type   | Description\n-------|------|---------------|--------|----------------------------------\n0x00   | 2    | e_magic       | WORD   | MZ signature (0x5A4D)\n0x3C   | 4    | e_lfanew      | LONG   | Offset to PE header\n...    | ...  | ...           | ...    | DOS header continues\nPE+0x00| 4    | Signature     | DWORD  | PE signature (PE\\0\\0)\nPE+0x04| 2    | Machine       | WORD   | Target machine type\nPE+0x06| 2    | Sections      | WORD   | Number of sections\n\nMachine Type Constants:\n0x014C - IMAGE_FILE_MACHINE_I386 (Intel 386 or later, x86)\n0x8664 - IMAGE_FILE_MACHINE_AMD64 (AMD x64 architecture)\n0x01C4 - IMAGE_FILE_MACHINE_ARMNT (ARM little-endian)\n0xAA64 - IMAGE_FILE_MACHINE_ARM64 (ARM64 little-endian)",
      "name_source": "LoD/1.08",
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
    "d2mcpclient.dll_STR_8315eedfd35b": {
      "addresses": {
        "LoD/1.07": "0x6FA5383A",
        "LoD/1.08": "0x6FA5383A",
        "LoD/1.09": "0x6F9F385A",
        "LoD/1.09b": "0x6F9F385A",
        "LoD/1.09d": "0x6F9F385A",
        "LoD/1.10": "0x6F9F371A"
      },
      "rvas": {
        "LoD/1.07": "0x383A",
        "LoD/1.08": "0x383A",
        "LoD/1.09": "0x385A",
        "LoD/1.09b": "0x385A",
        "LoD/1.09d": "0x385A",
        "LoD/1.10": "0x371A"
      },
      "sizes": {
        "LoD/1.07": 328,
        "LoD/1.08": 328,
        "LoD/1.09": 328,
        "LoD/1.09b": 328,
        "LoD/1.09d": 328,
        "LoD/1.10": 328
      },
      "signature": "int DetermineHeapCompatibilityMode(void)",
      "calling_convention": "__stdcall",
      "comment": "Determines heap compatibility mode based on OS version and environment configuration\n\nAlgorithm:\n1. Call StackProbe() to validate stack space\n2. Initialize version info structure (dwVersionInfoSize = 0x94)\n3. Call GetVersionExA() to retrieve OS version information\n4. Check if OS is Windows NT 5.0+ (dwMajorVersion == 2 AND dwMinorVersion >= 5)\n5. If modern OS: return compatibility mode 1 (standard heap)\n6. If legacy OS: retrieve __MSVCRT_HEAP_SELECT environment variable\n7. Convert environment variable value to uppercase using case conversion loop\n8. Compare against \"__GLOBAL_HEAP_SELECTED\" string (0x16 bytes)\n9. If exact match: use environment buffer as search source\n10. If no match: get module filename via GetModuleFileNameA()\n11. Convert module filename to uppercase using case conversion loop  \n12. Search for module name within environment variable value using _strstr()\n13. If found: locate comma delimiter using FindCharacterInString()\n14. Parse comma-delimited value by null-terminating at semicolon (0x3b)\n15. Invoke network handler with parsed value and parameters (0x0, 0xa)\n16. Return network handler result code (1, 2, or 3)\n17. If parsing fails: call GetPEMachineType() as fallback detection\n18. Calculate final result: 3 - (bZero < 6) where bZero comes from PE analysis\n\nParameters:\nNone\n\nReturns:\n1 - Standard heap mode (modern OS or network handler success)\n2 - Alternative heap mode (network handler alternate result)\n3 - Legacy compatibility mode (network handler legacy result or PE fallback)\n\nSpecial Cases:\n- GetVersionExA() failure: falls through to environment variable processing\n- Environment variable \"__MSVCRT_HEAP_SELECT\" not found: uses PE machine type detection\n- String parsing encounters semicolon (0x3b): null-terminates for parameter isolation\n- Network handler parameter 0xa (10) indicates specific heap selection mode\n\nMagic Numbers Reference:\n0x94 (148) - Size of OSVERSIONINFOA structure\n0x1090 (4240) - Maximum environment variable buffer size  \n0x104 (260) - Maximum module filename buffer size (MAX_PATH)\n0x16 (22) - Length of \"__GLOBAL_HEAP_SELECTED\" comparison string\n0x2c (44) - ASCII comma character for delimiter search\n0x3b (59) - ASCII semicolon character for value termination\n0xa (10) - Network handler mode parameter for heap selection\n0x20 (32) - ASCII case conversion offset (uppercase = lowercase - 32)\n0x61 (97) - ASCII 'a' lower bound for case conversion  \n0x7a (122) - ASCII 'z' upper bound for case conversion\n0x2 (2) - Expected dwMajorVersion for Windows NT\n0x5 (5) - Minimum dwMinorVersion for modern Windows (5.0+)\n\nError Handling:\n- GetVersionExA() failure: continues with legacy compatibility processing\n- Environment variable retrieval failure: uses PE machine type analysis\n- String search failure: bypasses network handler invocation\n- Network handler failure: falls back to PE machine type detection\n\nStructure Layout:\nOSVERSIONINFOA at [EBP + 0xffffff68]:\nOffset | Size | Field Name        | Type  | Description\n0x00   | 4    | dwOSVersionInfoSize | DWORD | Structure size (0x94)\n0x04   | 4    | dwMajorVersion      | DWORD | OS major version number  \n0x08   | 4    | dwMinorVersion      | DWORD | OS minor version number\n0x0C   | 4    | dwBuildNumber       | DWORD | OS build number\n0x10   | 4    | dwPlatformId        | DWORD | Platform identifier\n0x14   | 128  | szCSDVersion        | CHAR[128] | Service pack string",
      "name_source": "LoD/1.08",
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
    "d2mcpclient.dll_MNE_15aa81e73603": {
      "addresses": {
        "LoD/1.07": "0x6FA53982",
        "LoD/1.08": "0x6FA53982",
        "LoD/1.09": "0x6F9F39A2",
        "LoD/1.09b": "0x6F9F39A2",
        "LoD/1.09d": "0x6F9F39A2",
        "LoD/1.10": "0x6F9F3862"
      },
      "rvas": {
        "LoD/1.07": "0x3982",
        "LoD/1.08": "0x3982",
        "LoD/1.09": "0x39A2",
        "LoD/1.09b": "0x39A2",
        "LoD/1.09d": "0x39A2",
        "LoD/1.10": "0x3862"
      },
      "sizes": {
        "LoD/1.07": 93,
        "LoD/1.08": 93,
        "LoD/1.09": 93,
        "LoD/1.09b": 93,
        "LoD/1.09d": 93,
        "LoD/1.10": 93
      },
      "signature": "int InitializeHeapAndAllocator(int nReason)",
      "calling_convention": "__cdecl",
      "comment": "Initialize heap and allocator subsystem during DLL initialization.\n\nAlgorithm:\n1. Create heap with HEAP_NO_SERIALIZE flag based on DLL attachment reason\n2. Store heap handle in global variable g_hHeapHandle\n3. Retrieve allocation strategy from allocator subsystem (FUN_6ff2e2b1)\n4. Store allocation strategy in global variable g_dwAllocationStrategy\n5. Initialize allocator based on strategy value:\n   - Strategy 3: Call FUN_6ff2e7d3(0x3f8) for 1016-byte allocation pool\n   - Strategy 2: Call FUN_6ff2f31a() for default allocation pool\n   - Other strategies: Return success immediately (no allocator needed)\n6. Verify allocator initialization succeeded (non-NULL return)\n7. Return success if all initialization completed\n8. Clean up heap and return failure if allocator initialization failed\n\nParameters:\nnReason (int): DLL attachment reason from DllMain (DLL_PROCESS_ATTACH, etc.)\n               Used to determine heap serialization policy\n\nReturns:\n1 - Successful initialization of heap and allocator subsystem\n0 - Initialization failed (heap creation failed or allocator init failed)\n\nSpecial Cases:\n- If nReason is 0 (DLL_PROCESS_DETACH), heap created with HEAP_NO_SERIALIZE\n- Strategy values other than 2 or 3 skip allocator initialization\n- NULL heap handle causes immediate failure return\n\nMagic Numbers Reference:\n0x1000 - Initial heap commit size (4096 bytes)\n0x3f8 - Allocation pool size for strategy 3 (1016 bytes)\n2 - Default allocation strategy requiring FUN_6ff2f31a initialization  \n3 - Pool allocation strategy requiring FUN_6ff2e7d3 initialization\n\nError Handling:\n- HeapCreate failure returns NULL handle, function returns 0\n- Allocator initialization failure triggers HeapDestroy cleanup before return 0\n- Invalid strategy values (not 2 or 3) treated as success case",
      "name_source": "LoD/1.08",
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
    "d2mcpclient.dll_MNE_c2ccec134924": {
      "addresses": {
        "LoD/1.07": "0x6FA539DF",
        "LoD/1.08": "0x6FA539DF",
        "LoD/1.09": "0x6F9F39FF",
        "LoD/1.09b": "0x6F9F39FF",
        "LoD/1.09d": "0x6F9F39FF",
        "LoD/1.10": "0x6F9F38BF"
      },
      "rvas": {
        "LoD/1.07": "0x39DF",
        "LoD/1.08": "0x39DF",
        "LoD/1.09": "0x39FF",
        "LoD/1.09b": "0x39FF",
        "LoD/1.09d": "0x39FF",
        "LoD/1.10": "0x38BF"
      },
      "sizes": {
        "LoD/1.07": 168,
        "LoD/1.08": 168,
        "LoD/1.09": 168,
        "LoD/1.09b": 168,
        "LoD/1.09d": 168,
        "LoD/1.10": 168
      },
      "signature": "void CleanupMemoryAllocations(void)",
      "calling_convention": "__stdcall",
      "comment": "Releases all allocated memory and destroys heap handles during application shutdown.\n\nAlgorithm:\n\n1. Check global allocation strategy (g_dwAllocationStrategy)\n2. If strategy == 3 (array-based allocation):\n   a. Loop through all allocation entries (g_dwAllocationCount)\n   b. For each entry at g_pAllocationTable + (index * 20) + 0xc:\n      - Call VirtualFree twice with MEM_DECOMMIT (0x4000) and MEM_RELEASE (0x8000)\n      - Call HeapFree on associated heap memory block\n   c. Free the entire allocation table with HeapFree\n3. If strategy == 2 (linked list allocation):\n   a. Traverse circular linked list starting at PTR_LOOP_6ff36b70\n   b. For each node with valid memory pointer at offset 0x10:\n      - Call VirtualFree with MEM_RELEASE (0x8000) \n   c. Continue until returning to head node\n4. Destroy the main heap handle with HeapDestroy\n\nParameters:\n\nNone\n\nReturns:\n\nNone (void function)\n\nMagic Numbers Reference:\n\n0x3 - Array-based allocation strategy constant\n0x2 - Linked list allocation strategy constant  \n0xc - Offset to memory pointers within allocation entry structure\n0x14 (20) - Size of each MemoryAllocation structure entry\n0x100000 (1MB) - Virtual memory size to decommit\n0x4000 - MEM_DECOMMIT flag for VirtualFree\n0x8000 - MEM_RELEASE flag for VirtualFree\n0x10 (16) - Offset to memory pointer in linked list node\n\nStructure Layout:\n\nMemoryAllocation (20 bytes):\nOffset | Size | Field Name        | Type   | Description\n-------|------|-------------------|--------|---------------------------\n0x00   | 4    | dwReserved1       | uint   | Reserved field\n0x04   | 4    | dwReserved2       | uint   | Reserved field  \n0x08   | 4    | dwReserved3       | uint   | Reserved field\n0x0c   | 4    | pVirtualMemory    | void*  | Virtual memory base address\n0x10   | 4    | pHeapMemory       | void*  | Heap allocation pointer\n\nGlobal Variables:\n\ng_dwAllocationStrategy - Current memory allocation strategy (2 or 3)\ng_dwAllocationCount - Number of entries in allocation table\ng_pAllocationTable - Pointer to MemoryAllocation array\ng_hHeapHandle - Handle to main application heap\nPTR_LOOP_6ff36b70 - Head node of circular linked list for strategy 2",
      "name_source": "LoD/1.08",
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
    "d2mcpclient.dll_MNE_9765460a3049": {
      "addresses": {
        "LoD/1.07": "0x6FA53A87",
        "LoD/1.08": "0x6FA53A87",
        "LoD/1.09": "0x6F9F3AA7",
        "LoD/1.09b": "0x6F9F3AA7",
        "LoD/1.09d": "0x6F9F3AA7",
        "LoD/1.10": "0x6F9F3967",
        "LoD/1.11": "0x6FA22743",
        "LoD/1.11b": "0x6FA22743",
        "LoD/1.12a": "0x6FA22764",
        "LoD/1.13c": "0x6FA22764",
        "LoD/1.13d": "0x6FA22A83"
      },
      "rvas": {
        "LoD/1.07": "0x3A87",
        "LoD/1.08": "0x3A87",
        "LoD/1.09": "0x3AA7",
        "LoD/1.09b": "0x3AA7",
        "LoD/1.09d": "0x3AA7",
        "LoD/1.10": "0x3967",
        "LoD/1.11": "0x2743",
        "LoD/1.11b": "0x2743",
        "LoD/1.12a": "0x2764",
        "LoD/1.13c": "0x2764",
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
      "signature": "void CleanupConsoleOutput(void)",
      "calling_convention": "__stdcall",
      "comment": "Performs console output cleanup and shutdown operations based on display flags.\n\nAlgorithm:\n\n1. Check if console display is enabled (g_dwConsoleDisplayFlag == 1)\n2. OR if display flag is disabled but debug flag is set (g_dwConsoleDisplayFlag == 0 AND g_dwConsoleDebugFlag == 1)\n3. If either condition true, execute cleanup sequence:\n   - Send pre-cleanup signal via FUN_1001f820(0xFC)\n   - Call registered cleanup callback if available (g_pfnCleanupCallback)\n   - Send final cleanup signal via FUN_1001f820(0xFF)\n4. Return to caller\n\nParameters:\nNone\n\nReturns:\nvoid - No return value\n\nSpecial Cases:\nIf neither console display nor debug mode are active, function exits immediately without cleanup\n\nMagic Numbers Reference:\n0xFC (252) - Pre-cleanup signal code passed to FUN_1001f820\n0xFF (255) - Final cleanup signal code passed to FUN_1001f820",
      "name_source": "LoD/1.08",
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
    "d2mcpclient.dll_STR_ff7880d11813": {
      "addresses": {
        "LoD/1.07": "0x6FA53AC0",
        "LoD/1.08": "0x6FA53AC0",
        "LoD/1.09": "0x6F9F3AE0",
        "LoD/1.09b": "0x6F9F3AE0",
        "LoD/1.09d": "0x6F9F3AE0",
        "LoD/1.10": "0x6F9F39A0",
        "LoD/1.11": "0x6FA225CC",
        "LoD/1.11b": "0x6FA225CC",
        "LoD/1.12a": "0x6FA225EC",
        "LoD/1.13c": "0x6FA225EC",
        "LoD/1.13d": "0x6FA2290C"
      },
      "rvas": {
        "LoD/1.07": "0x3AC0",
        "LoD/1.08": "0x3AC0",
        "LoD/1.09": "0x3AE0",
        "LoD/1.09b": "0x3AE0",
        "LoD/1.09d": "0x3AE0",
        "LoD/1.10": "0x39A0",
        "LoD/1.11": "0x25CC",
        "LoD/1.11b": "0x25CC",
        "LoD/1.12a": "0x25EC",
        "LoD/1.13c": "0x25EC",
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
      "signature": "void DisplayRuntimeError(uint dwErrorCode)",
      "calling_convention": "__cdecl",
      "comment": "Displays runtime error messages using either console or GUI output\n\nAlgorithm:\n1. Search error table at DAT_6ff36ae0 for matching error code\n2. Calculate table index and verify error code match\n3. Check global exit flags to determine output method\n4. If exit flags set (g_dwExitFlag1==1 OR g_dwExitFlag2==1 while g_dwExitFlag1==0):\n   - Write error message directly to stdout using WriteFile\n5. If GUI mode and error code is not 0xFC (assert error):\n   - Get current module filename with GetModuleFileNameA\n   - If filename retrieval fails, use \"<program name unknown>\"\n   - Truncate filename to 60 chars if too long, append \"...\"\n   - Build complete error message with \"Runtime Error!\n\nProgram: \" prefix\n   - Append module name, newline, and error-specific message\n   - Display message box using Microsoft Visual C++ Runtime Library title\n\nParameters:\ndwErrorCode - Error code to look up in runtime error table\n\nReturns:\nvoid - Function does not return value\n\nSpecial Cases:\n- Error code 0xFC bypasses GUI display (assertion error special case)  \n- Module name truncation occurs at 60+ characters\n- Console mode bypasses all GUI formatting\n- Invalid error codes result in no action\n\nStructure Layout:\nErrorTableEntry (8 bytes):\nOffset Size Field         Type     Description\n0x00   4    dwErrorCode   uint     Runtime error identifier\n0x04   4    lpszMessage   char *   Pointer to error message string\n\nMagic Numbers Reference:\n0xFC     - Special assertion error code that bypasses GUI display\n0x104    - Buffer size (260 bytes) for module filename  \n0x3C     - Maximum filename length (60 chars) before truncation\n0x12010  - MessageBox flags: MB_ICONHAND | MB_SYSTEMMODAL\n0x6ff36ae0 - Base address of runtime error lookup table\n0x6ff36b70 - End address of runtime error lookup table\n\nGlobal Variables:\ng_dwExitFlag1 (0x6ff39eac) - Primary exit flag for console output mode\ng_dwExitFlag2 (0x6ff39eb0) - Secondary exit flag for alternate console mode",
      "name_source": "LoD/1.08",
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
    "d2mcpclient.dll_MNE_38a52ad8d912": {
      "addresses": {
        "LoD/1.07": "0x6FA53C13",
        "LoD/1.08": "0x6FA53C13",
        "LoD/1.09": "0x6F9F3C33",
        "LoD/1.09b": "0x6F9F3C33",
        "LoD/1.09d": "0x6F9F3C33",
        "LoD/1.10": "0x6F9F3AF3"
      },
      "rvas": {
        "LoD/1.07": "0x3C13",
        "LoD/1.08": "0x3C13",
        "LoD/1.09": "0x3C33",
        "LoD/1.09b": "0x3C33",
        "LoD/1.09d": "0x3C33",
        "LoD/1.10": "0x3AF3"
      },
      "sizes": {
        "LoD/1.07": 215,
        "LoD/1.08": 215,
        "LoD/1.09": 215,
        "LoD/1.09b": 215,
        "LoD/1.09d": 215,
        "LoD/1.10": 215
      },
      "signature": "void DeallocateMemory(void * pMemory)",
      "calling_convention": "__cdecl",
      "comment": "Strategy-based memory deallocation with custom memory management and exception handling.\n\nAlgorithm:\n\n1. Validate memory pointer parameter - return early if NULL\n2. Set up structured exception handling frame with global exception data\n3. Check allocation strategy from g_dwAllocationStrategy global variable\n4. Strategy 3: Acquire critical section 9, locate memory block, remove from custom pool\n5. Strategy 2: Acquire critical section 9, find block metadata, deallocate from custom allocator  \n6. Fallback: Use standard HeapFree with global heap handle for all other strategies\n7. Release critical sections and restore exception context before return\n8. Handle allocation failures by falling back to standard heap operations\n\nParameters:\n\npMemory (void *): Pointer to memory block to deallocate. NULL check performed early.\n\nReturns:\n\nvoid: Function does not return a value. Memory is deallocated through side effects.\n\nSpecial Cases:\n\n- NULL pointer: Function returns immediately without error\n- Strategy 3 (0x03): Custom pool allocation with block tracking and removal\n- Strategy 2 (0x02): Metadata-based allocation with size and location tracking  \n- All other strategies: Standard Win32 HeapFree fallback using g_hHeapHandle\n- Exception handling: SEH frame protects against access violations during deallocation\n\nMagic Numbers Reference:\n\n0x03: Custom pool allocation strategy requiring block location and removal\n0x02: Metadata-tracked allocation strategy with size/location info\n0x09: Critical section index for memory allocation synchronization\n0xFFFFFFFF: Exception handler state reset value (-1)\n0x00: Exception handler active state value\n0x01: Exception handler secondary state value\n\nError Handling:\n\n- Access violations caught by SEH frame during block location/removal\n- Critical sections always released via exception unwinding or normal exit\n- Failed custom deallocation falls back to standard HeapFree operation\n- Memory corruption protection through structured exception handling\n\nState Machine:\n\nState 1: Initial validation - NULL check and exception frame setup\nState 2: Strategy analysis - Read g_dwAllocationStrategy and branch accordingly  \nState 3a: Strategy 3 path - Critical section, block location, custom removal\nState 3b: Strategy 2 path - Critical section, metadata lookup, allocator cleanup\nState 4: Fallback path - Standard HeapFree with global heap handle\nState 5: Cleanup - Critical section release and exception context restoration",
      "name_source": "LoD/1.08",
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
    "d2mcpclient.dll__malloc": {
      "addresses": {
        "LoD/1.07": "0x6FA53CFC",
        "LoD/1.08": "0x6FA53CFC",
        "LoD/1.09": "0x6F9F3D1C",
        "LoD/1.09b": "0x6F9F3D1C",
        "LoD/1.09d": "0x6F9F3D1C",
        "LoD/1.10": "0x6F9F3BDC",
        "LoD/1.11": "0x6FA228C7",
        "LoD/1.11b": "0x6FA228C7",
        "LoD/1.12a": "0x6FA228E8",
        "LoD/1.13c": "0x6FA228E8",
        "LoD/1.13d": "0x6FA22C07"
      },
      "rvas": {
        "LoD/1.07": "0x3CFC",
        "LoD/1.08": "0x3CFC",
        "LoD/1.09": "0x3D1C",
        "LoD/1.09b": "0x3D1C",
        "LoD/1.09d": "0x3D1C",
        "LoD/1.10": "0x3BDC",
        "LoD/1.11": "0x28C7",
        "LoD/1.11b": "0x28C7",
        "LoD/1.12a": "0x28E8",
        "LoD/1.13c": "0x28E8",
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
    "d2mcpclient.dll___nh_malloc": {
      "addresses": {
        "LoD/1.07": "0x6FA53D0E",
        "LoD/1.08": "0x6FA53D0E",
        "LoD/1.09": "0x6F9F3D2E",
        "LoD/1.09b": "0x6F9F3D2E",
        "LoD/1.09d": "0x6F9F3D2E",
        "LoD/1.10": "0x6F9F3BEE",
        "LoD/1.11": "0x6FA2289B",
        "LoD/1.11b": "0x6FA2289B",
        "LoD/1.12a": "0x6FA228BC",
        "LoD/1.13c": "0x6FA228BC",
        "LoD/1.13d": "0x6FA22BDB"
      },
      "rvas": {
        "LoD/1.07": "0x3D0E",
        "LoD/1.08": "0x3D0E",
        "LoD/1.09": "0x3D2E",
        "LoD/1.09b": "0x3D2E",
        "LoD/1.09d": "0x3D2E",
        "LoD/1.10": "0x3BEE",
        "LoD/1.11": "0x289B",
        "LoD/1.11b": "0x289B",
        "LoD/1.12a": "0x28BC",
        "LoD/1.13c": "0x28BC",
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
    "d2mcpclient.dll_MNE_2427cd9c654a": {
      "addresses": {
        "LoD/1.07": "0x6FA53D3A",
        "LoD/1.08": "0x6FA53D3A",
        "LoD/1.09": "0x6F9F3D5A",
        "LoD/1.09b": "0x6F9F3D5A",
        "LoD/1.09d": "0x6F9F3D5A",
        "LoD/1.10": "0x6F9F3C1A"
      },
      "rvas": {
        "LoD/1.07": "0x3D3A",
        "LoD/1.08": "0x3D3A",
        "LoD/1.09": "0x3D5A",
        "LoD/1.09b": "0x3D5A",
        "LoD/1.09d": "0x3D5A",
        "LoD/1.10": "0x3C1A"
      },
      "sizes": {
        "LoD/1.07": 231,
        "LoD/1.08": 231,
        "LoD/1.09": 231,
        "LoD/1.09b": 231,
        "LoD/1.09d": 231,
        "LoD/1.10": 231
      },
      "signature": "void * AllocateMemoryByStrategy(ulong dwSize)",
      "calling_convention": "__cdecl",
      "comment": "Allocate memory using strategy-based allocation system with fallback to heap\n\nAlgorithm:\n1. Initialize structured exception handling (SEH) with error state 0xFFFFFFFF\n2. Check global allocation strategy value (g_dwAllocationStrategy)\n3. Strategy 3 (Pool allocation):\n   - Verify requested size <= pool limit (g_dwPoolSizeLimit)\n   - Acquire critical section lock (index 9)\n   - Call pool allocator (FUN_6ff2eb6f) with raw size\n   - Release critical section lock\n   - Return allocated pointer if successful, otherwise fall to heap\n4. Strategy 2 (Block allocation):\n   - Calculate aligned size: (size + 15) & 0xFFFFFFF0 (16-byte alignment)\n   - Use minimum 16 bytes if size is 0\n   - Verify aligned size <= block threshold (g_dwBlockSizeThreshold)\n   - Acquire critical section lock (index 9)\n   - Call block allocator (FUN_6ff2f612) with size >> 4 (divided by 16)\n   - Release critical section lock\n   - Return allocated pointer if successful, otherwise fall to heap\n5. Fallback allocation:\n   - Use minimum 1 byte if size is 0\n   - Calculate aligned size: (size + 15) & 0xFFFFFFF0\n   - Call HeapAlloc with global heap handle (g_hHeapHandle)\n   - Return allocated pointer (or NULL on failure)\n6. Restore exception handling and return\n\nParameters:\ndwSize (ulong): Requested allocation size in bytes\n\nReturns:\nvoid *: Pointer to allocated memory block, or NULL if allocation fails\n\nSpecial Cases:\nZero size allocation converts to minimum allocation (1 byte for heap, 16 for blocks)\nAll allocations are 16-byte aligned for optimal performance\nCritical sections provide thread safety for pool and block strategies\n\nMagic Numbers Reference:\n0xFFFFFFFF - SEH error state marker\n0x10 (16) - Minimum block size and alignment boundary\n0xF (15) - Alignment mask for 16-byte boundary calculation\n0xFFFFFFF0 - Alignment mask (inverted 15) for clearing low 4 bits\n9 - Critical section index for allocation subsystem\n\nError Handling:\nSEH protects against access violations during allocation\nFailed pool/block allocations automatically fall back to heap allocation\nNULL return indicates complete allocation failure (out of memory)\n\nState Machine:\nState 1: Check strategy 3 \u2192 Pool allocation attempt \u2192 Success/Fall to heap\nState 2: Check strategy 2 \u2192 Block allocation attempt \u2192 Success/Fall to heap  \nState 3: Fallback allocation \u2192 HeapAlloc \u2192 Return result\nState 4: Cleanup SEH and return allocated pointer",
      "name_source": "LoD/1.08",
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
    "d2mcpclient.dll_MNE_371cf2604575": {
      "addresses": {
        "LoD/1.07": "0x6FA53E36",
        "LoD/1.08": "0x6FA53E36",
        "LoD/1.09": "0x6F9F3E56",
        "LoD/1.09b": "0x6F9F3E56",
        "LoD/1.09d": "0x6F9F3E56",
        "LoD/1.10": "0x6F9F3D16"
      },
      "rvas": {
        "LoD/1.07": "0x3E36",
        "LoD/1.08": "0x3E36",
        "LoD/1.09": "0x3E56",
        "LoD/1.09b": "0x3E56",
        "LoD/1.09d": "0x3E56",
        "LoD/1.10": "0x3D16"
      },
      "sizes": {
        "LoD/1.07": 289,
        "LoD/1.08": 289,
        "LoD/1.09": 289,
        "LoD/1.09b": 289,
        "LoD/1.09d": 289,
        "LoD/1.10": 289
      },
      "signature": "void * AllocateMemoryWithRetry(uint dwWidth, uint dwHeight)",
      "calling_convention": "__cdecl",
      "comment": "Allocates memory using a multi-tiered allocation strategy with automatic retry handling.\n\nAlgorithm:\n1. Multiply dwWidth * dwHeight to calculate total size requirement\n2. Apply size validation - reject requests larger than 0xFFFFFFE0 bytes  \n3. Apply 16-byte alignment padding for small allocations (add 0xF, mask 0xFFFFFFF0)\n4. Set up structured exception handling (SEH) frame with handler at 0x6ff2cf5c\n5. Enter retry loop with multiple allocation strategies:\n   a. If g_dwAllocationStrategy == 3 (pool mode):\n      - Check size against g_dwPoolSizeLimit threshold\n      - Acquire critical section 9 for thread safety\n      - Call FUN_6ff2eb6f(size) for pool allocation\n      - Release critical section and zero allocated block\n   b. If g_dwAllocationStrategy == 2 (block mode):\n      - Check size against g_dwBlockSizeThreshold  \n      - Acquire critical section 9 for thread safety\n      - Call FUN_6ff2f612(size >> 4) for 16-byte block allocation\n      - Release critical section and zero allocated block\n   c. Fallback to HeapAlloc with HEAP_ZERO_MEMORY (0x8) flag\n6. If allocation fails and g_pfnRetryHandler exists:\n   - Call FUN_6ff2f9e7(size) retry handler\n   - If retry succeeds, restart allocation loop\n   - If retry fails, return NULL\n7. Zero allocated memory using _memset before returning\n8. Restore SEH frame and return pointer or NULL\n\nParameters:\n- dwWidth (uint): Width dimension for allocation size calculation\n- dwHeight (uint): Height dimension for allocation size calculation\n\nReturns:\n- Success: Non-NULL pointer to zeroed memory block of size (dwWidth * dwHeight)\n- Failure: NULL if allocation fails or size exceeds limits\n\nSpecial Cases:\n- Size 0 is normalized to size 1 to prevent zero-byte allocations\n- Sizes > 0xFFFFFFE0 immediately return NULL (integer overflow protection)\n- Small allocations get 16-byte alignment padding for performance\n- Uses structured exception handling for robust error recovery\n\nMagic Numbers Reference:\n- 0xFFFFFFE0 (4294967264): Maximum allocation size limit\n- 0xF (15): Alignment padding mask\n- 0xFFFFFFF0 (4294967280): 16-byte alignment mask  \n- 0x8 (8): HEAP_ZERO_MEMORY flag for HeapAlloc\n- 9: Critical section index for allocation synchronization\n\nError Handling:\n- Integer overflow: Sizes > 0xFFFFFFE0 rejected immediately\n- Pool allocation failure: Falls through to block allocation\n- Block allocation failure: Falls through to heap allocation  \n- Heap allocation failure: Calls retry handler if available\n- Retry handler failure: Returns NULL to caller\n- SEH exceptions: Handled by registered exception handler",
      "name_source": "LoD/1.08",
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
    "d2mcpclient.dll_MNE_70593f43ea0b": {
      "addresses": {
        "LoD/1.07": "0x6FA53F80",
        "LoD/1.08": "0x6FA53F80",
        "LoD/1.09": "0x6F9F3FA0",
        "LoD/1.09b": "0x6F9F3FA0",
        "LoD/1.09d": "0x6F9F3FA0",
        "LoD/1.10": "0x6F9F3E60",
        "LoD/1.11": "0x6FA24070",
        "LoD/1.11b": "0x6FA24070",
        "LoD/1.12a": "0x6FA240A0",
        "LoD/1.13c": "0x6FA240A0",
        "LoD/1.13d": "0x6FA243B0"
      },
      "rvas": {
        "LoD/1.07": "0x3F80",
        "LoD/1.08": "0x3F80",
        "LoD/1.09": "0x3FA0",
        "LoD/1.09b": "0x3FA0",
        "LoD/1.09d": "0x3FA0",
        "LoD/1.10": "0x3E60",
        "LoD/1.11": "0x4070",
        "LoD/1.11b": "0x4070",
        "LoD/1.12a": "0x40A0",
        "LoD/1.13c": "0x40A0",
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
      "signature": "char * CopyStringOptimized(char * szDestination, char * szSource)",
      "calling_convention": "__cdecl",
      "comment": "Optimized string copy function that efficiently copies null-terminated strings\nusing word-aligned memory operations and bitwise null detection for maximum\nperformance on x86 architecture.\n\nAlgorithm:\n1. Check source pointer alignment against 4-byte boundary (szSource & 3)\n2. Copy bytes individually until source reaches word alignment\n3. Check each copied byte for null terminator, exit early if found\n4. Begin optimized word-level copying once aligned\n5. Load 32-bit words from source and apply null detection algorithm\n6. Use magic constant 0x7efefeff to detect null bytes within words\n7. When null detected, determine exact byte position using bit masks\n8. Copy final bytes and null terminator based on detected position\n9. Return original destination pointer\n\nParameters:\nszDestination (char*): Destination buffer where string will be copied\nszSource (char*): Source null-terminated string to copy\n\nReturns:\nchar*: Returns szDestination (original destination buffer address)\n\nSpecial Cases:\nEmpty string (first byte is null) handled correctly by early exit\nSource and destination buffers must not overlap (undefined behavior)\nDestination buffer must be large enough to hold entire source string\n\nMagic Numbers:\n0x7efefeff: Magic constant for fast null byte detection in 32-bit words\n0x81010100: Bit mask for isolating overflow bits from null detection\n0xffffffff: XOR mask component of null detection algorithm  \n0x3: Bit mask for checking 4-byte memory alignment",
      "name_source": "LoD/1.08",
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
    "d2mcpclient.dll_MNE_845fc5044ff1": {
      "addresses": {
        "LoD/1.07": "0x6FA53F90",
        "LoD/1.08": "0x6FA53F90",
        "LoD/1.09": "0x6F9F3FB0",
        "LoD/1.09b": "0x6F9F3FB0",
        "LoD/1.09d": "0x6F9F3FB0",
        "LoD/1.10": "0x6F9F3E70"
      },
      "rvas": {
        "LoD/1.07": "0x3F90",
        "LoD/1.08": "0x3F90",
        "LoD/1.09": "0x3FB0",
        "LoD/1.09b": "0x3FB0",
        "LoD/1.09d": "0x3FB0",
        "LoD/1.10": "0x3E70"
      },
      "sizes": {
        "LoD/1.07": 224,
        "LoD/1.08": 224,
        "LoD/1.09": 224,
        "LoD/1.09b": 224,
        "LoD/1.09d": 224,
        "LoD/1.10": 224
      },
      "signature": "char * OptimizedStringCopy(char * lpszDestination, char * lpszSource)",
      "calling_convention": "__cdecl",
      "comment": "Performs optimized string copying using word-aligned memory access and null-byte detection.\nThis function implements a high-performance strcpy equivalent using x86 alignment optimization.\nUses magic constants to detect null terminators within 32-bit words for maximum throughput.\nHandles both aligned and unaligned source/destination buffers gracefully.\n\nAlgorithm:\n1. Check destination pointer alignment against 4-byte word boundary\n2. Copy unaligned bytes one-by-one until destination reaches word alignment  \n3. Enter optimized loop processing 4-byte words from aligned destination\n4. Apply magic constant 0x7EFEFEFF to detect null bytes within words\n5. Use mask 0x81010100 to isolate carry bits indicating null presence\n6. When null detected in word, determine exact byte position and handle\n7. Switch to source processing with similar alignment optimization\n8. Copy source bytes individually until source is word-aligned\n9. Process aligned source words until null terminator found\n10. Terminate destination string with null and return original pointer\n\nParameters:\nlpszDestination - Pointer to destination buffer with sufficient space allocated\nlpcszSource - Pointer to source null-terminated string to be copied\n\nReturns:\nReturns lpszDestination pointer for function chaining operations\n\nMagic Numbers Reference:\n0x7EFEFEFF (2130640639) - Magic additive constant for null detection algorithm\n0x81010100 (2164391168) - Bit mask to isolate null detection carry flags  \n0x3 (3) - Alignment mask for checking 4-byte word boundaries\n0xFF0000 (16711680) - Third byte mask for null position detection\n0xFF000000 (4278190080) - Fourth byte mask for null position detection\n\nSpecial Cases:\nEmpty source string copies only null terminator to destination\nOverlapping memory regions produce undefined behavior per C standard\nDestination buffer must accommodate source length plus null terminator\nAlgorithm assumes little-endian x86 architecture for bit manipulation",
      "name_source": "LoD/1.08",
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
    "d2mcpclient.dll__strlen": {
      "addresses": {
        "LoD/1.07": "0x6FA54070",
        "LoD/1.08": "0x6FA54070",
        "LoD/1.09": "0x6F9F4090",
        "LoD/1.09b": "0x6F9F4090",
        "LoD/1.09d": "0x6F9F4090",
        "LoD/1.10": "0x6F9F3F50",
        "LoD/1.11": "0x6FA24170",
        "LoD/1.11b": "0x6FA24170",
        "LoD/1.12a": "0x6FA241A0",
        "LoD/1.13c": "0x6FA241A0",
        "LoD/1.13d": "0x6FA244B0"
      },
      "rvas": {
        "LoD/1.07": "0x4070",
        "LoD/1.08": "0x4070",
        "LoD/1.09": "0x4090",
        "LoD/1.09b": "0x4090",
        "LoD/1.09d": "0x4090",
        "LoD/1.10": "0x3F50",
        "LoD/1.11": "0x4170",
        "LoD/1.11b": "0x4170",
        "LoD/1.12a": "0x41A0",
        "LoD/1.13c": "0x41A0",
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
    "d2mcpclient.dll_MNE_b7003782678f": {
      "addresses": {
        "LoD/1.07": "0x6FA540EB",
        "LoD/1.08": "0x6FA540EB",
        "LoD/1.09": "0x6F9F410B",
        "LoD/1.09b": "0x6F9F410B",
        "LoD/1.09d": "0x6F9F410B",
        "LoD/1.10": "0x6F9F3FCB"
      },
      "rvas": {
        "LoD/1.07": "0x40EB",
        "LoD/1.08": "0x40EB",
        "LoD/1.09": "0x410B",
        "LoD/1.09b": "0x410B",
        "LoD/1.09d": "0x410B",
        "LoD/1.10": "0x3FCB"
      },
      "sizes": {
        "LoD/1.07": 429,
        "LoD/1.08": 429,
        "LoD/1.09": 429,
        "LoD/1.09b": 429,
        "LoD/1.09d": 429,
        "LoD/1.10": 429
      },
      "signature": "uint InitializeCodePageLocale(uint dwCodePage)",
      "calling_convention": "__cdecl",
      "comment": "Initialize character type classification table for the specified code page.\n\nAlgorithm:\n1. Acquire critical section lock (index 0x19) for thread-safe table updates\n2. Retrieve normalized code page from parameter using FUN_6ff30e24()  \n3. Check if requested code page already matches current global code page (g_dwCurrentCodePage)\n4. If code page is zero, call cleanup function and return 0\n5. Search predefined code page table (g_adwCodePageTable) for matching entry\n6. If found in predefined table:\n   a. Clear global character type table (g_abCharacterTypeTable) to zero\n   b. Load character type ranges from predefined table entry\n   c. For each of 4 type categories, process character ranges\n   d. Set character type bits by ORing predefined values with table entries\n   e. Update global code page state and configuration values\n7. If not in predefined table:\n   a. Call GetCPInfo() to retrieve Windows code page information\n   b. Clear character type table and reset DBCS configuration\n   c. If single-byte code page (MaxCharSize < 2), set single-byte flag\n   d. If multi-byte code page, process lead byte ranges from CPINFO\n   e. Set lead byte bit (0x04) for all characters in lead byte ranges\n   f. Set trail byte bit (0x08) for all characters 1-254\n8. Call finalization functions FUN_6ff30eca() and optionally FUN_6ff30ea1()\n9. Release critical section lock and return success\n\nParameters:\ndwCodePage (uint): Windows code page identifier (e.g., 1252 for Latin-1, 932 for Shift-JIS)\n\nReturns:\nuint: 0 on successful initialization, 0xFFFFFFFF on failure\n\nSpecial Cases:\nIf code page is already current, return 0 immediately without reprocessing\nIf GetCPInfo fails and global flag g_fCodePageInitialized is clear, return 0xFFFFFFFF\nZero code page triggers cleanup sequence via FUN_6ff30ea1()\n\nMagic Numbers Reference:\n0x19 - Critical section index for character type table protection\n0x04 - Lead byte character type bit flag  \n0x08 - Trail byte character type bit flag\n0x30 - Size of each predefined code page table entry\n0x40 - Loop count for clearing 256-byte character table (64 * 4 bytes)\n0xFF - Maximum character value for trail byte processing",
      "name_source": "LoD/1.08",
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
    "d2mcpclient.dll_MNE_8f2a733057dd": {
      "addresses": {
        "LoD/1.07": "0x6FA54298",
        "LoD/1.08": "0x6FA54298",
        "LoD/1.09": "0x6F9F42B8",
        "LoD/1.09b": "0x6F9F42B8",
        "LoD/1.09d": "0x6F9F42B8",
        "LoD/1.10": "0x6F9F4178"
      },
      "rvas": {
        "LoD/1.07": "0x4298",
        "LoD/1.08": "0x4298",
        "LoD/1.09": "0x42B8",
        "LoD/1.09b": "0x42B8",
        "LoD/1.09d": "0x42B8",
        "LoD/1.10": "0x4178"
      },
      "sizes": {
        "LoD/1.07": 74,
        "LoD/1.08": 74,
        "LoD/1.09": 74,
        "LoD/1.09b": 74,
        "LoD/1.09d": 74,
        "LoD/1.10": 74
      },
      "signature": "uint ResolveCodePageIdentifier(int nCodePageSelector)",
      "calling_convention": "__cdecl",
      "comment": "Resolves code page identifiers to actual Windows code page numbers.\n\nAlgorithm:\n1. Clear initialization flag g_dwCodePageInitialized to 0\n2. Check if nCodePageSelector equals -2 (CP_OEMCP constant)\n   - Set g_dwCodePageInitialized = 1 to mark operation performed\n   - Call GetOEMCP() API to retrieve OEM code page\n   - Return OEM code page number\n3. Check if nCodePageSelector equals -3 (CP_ACP constant)  \n   - Set g_dwCodePageInitialized = 1 to mark operation performed\n   - Call GetACP() API to retrieve ANSI code page\n   - Return ANSI code page number\n4. Check if nCodePageSelector equals -4 (CP_THREAD_ACP constant)\n   - Retrieve stored thread locale code page from g_dwThreadLocaleCodePage\n   - Set g_dwCodePageInitialized = 1 to mark operation performed\n   - Return thread locale code page value\n5. For any other value (explicit code page number)\n   - Keep g_dwCodePageInitialized = 0 (no API call needed)\n   - Return nCodePageSelector unchanged\n\nParameters:\nnCodePageSelector (int): Code page selector constant or explicit code page number\n  -2 (CP_OEMCP): Request OEM code page via GetOEMCP()\n  -3 (CP_ACP): Request ANSI code page via GetACP()  \n  -4 (CP_THREAD_ACP): Request thread locale code page from global storage\n  Other: Explicit Windows code page number (1252, 65001, etc.)\n\nReturns:\nuint: Resolved Windows code page number\n  Success: Valid code page number (437, 1252, 65001, etc.)\n  Error: Original nCodePageSelector value if no resolution needed\n\nSpecial Cases:\n- Indirect jumps at 0x100215b0 and 0x100215c5 call GetOEMCP/GetACP via function pointers\n- Thread locale code page (-4) uses pre-stored value, not live API call\n- Global flag g_dwCodePageInitialized tracks whether API resolution was performed\n- Function handles both symbolic constants and explicit numeric code page values\n\nMagic Numbers Reference:\n-2 (0xFFFFFFFE): CP_OEMCP - OEM code page constant\n-3 (0xFFFFFFFD): CP_ACP - ANSI code page constant  \n-4 (0xFFFFFFFC): CP_THREAD_ACP - Thread locale code page constant\n0x1003ca88: Address of g_dwCodePageInitialized flag\n0x1003c8e4: Address of g_dwThreadLocaleCodePage storage\n0x100230b0: Function pointer to GetOEMCP API\n0x100230ac: Function pointer to GetACP API",
      "name_source": "LoD/1.08",
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
    "d2mcpclient.dll_MNE_f31c6439952c": {
      "addresses": {
        "LoD/1.07": "0x6FA542E2",
        "LoD/1.08": "0x6FA542E2",
        "LoD/1.09": "0x6F9F4302",
        "LoD/1.09b": "0x6F9F4302",
        "LoD/1.09d": "0x6F9F4302",
        "LoD/1.10": "0x6F9F41C2"
      },
      "rvas": {
        "LoD/1.07": "0x42E2",
        "LoD/1.08": "0x42E2",
        "LoD/1.09": "0x4302",
        "LoD/1.09b": "0x4302",
        "LoD/1.09d": "0x4302",
        "LoD/1.10": "0x41C2"
      },
      "sizes": {
        "LoD/1.07": 51,
        "LoD/1.08": 51,
        "LoD/1.09": 51,
        "LoD/1.09b": 51,
        "LoD/1.09d": 51,
        "LoD/1.10": 51
      },
      "signature": "uint MapCodePageIdentifier(uint dwInputCodePage)",
      "calling_convention": "__cdecl",
      "comment": "Maps input code page identifiers to corresponding output code page identifiers for locale initialization.\n\nAlgorithm:\n1. Check if input code page matches 0x3a4 (932 - Japanese Shift_JIS)\n2. If match, return 0x411 (1041 - Japanese Japan)\n3. Check if input code page matches 0x3a8 (936 - Chinese Simplified GBK) \n4. If match, return 0x804 (2052 - Chinese People's Republic)\n5. Check if input code page matches 0x3b5 (949 - Korean)\n6. If match, return 0x412 (1042 - Korean)\n7. Check if input code page matches 0x3b6 (950 - Chinese Traditional Big5)\n8. If match, return 0x404 (1028 - Chinese Taiwan)\n9. If no matches found, return 0 (invalid/unsupported code page)\n\nParameters:\n  dwInputCodePage (uint): Input code page identifier to map\n\nReturns:\n  uint: Corresponding locale identifier (LCID) if supported, 0 if unsupported\n\nMagic Numbers Reference:\n  0x3a4 (932): Japanese Shift_JIS code page\n  0x3a8 (936): Chinese Simplified GBK code page\n  0x3b5 (949): Korean code page  \n  0x3b6 (950): Chinese Traditional Big5 code page\n  0x411 (1041): Japanese Japan LCID\n  0x804 (2052): Chinese People's Republic LCID\n  0x412 (1042): Korean LCID\n  0x404 (1028): Chinese Taiwan LCID",
      "name_source": "LoD/1.08",
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
    "d2mcpclient.dll_MNE_05d3556ba26e": {
      "addresses": {
        "LoD/1.07": "0x6FA54315",
        "LoD/1.08": "0x6FA54315",
        "LoD/1.09": "0x6F9F4335",
        "LoD/1.09b": "0x6F9F4335",
        "LoD/1.09d": "0x6F9F4335",
        "LoD/1.10": "0x6F9F41F5"
      },
      "rvas": {
        "LoD/1.07": "0x4315",
        "LoD/1.08": "0x4315",
        "LoD/1.09": "0x4335",
        "LoD/1.09b": "0x4335",
        "LoD/1.09d": "0x4335",
        "LoD/1.10": "0x41F5"
      },
      "sizes": {
        "LoD/1.07": 41,
        "LoD/1.08": 41,
        "LoD/1.09": 41,
        "LoD/1.09b": 41,
        "LoD/1.09d": 41,
        "LoD/1.10": 41
      },
      "signature": "void InitializeLocaleDataBuffers(void)",
      "calling_convention": "__stdcall",
      "comment": "Initializes locale-related data buffers by zeroing memory regions and global variables.\n\nAlgorithm:\n1. Initialize pointer to start of buffer at 0x1003cbc0\n2. Set loop counter to 0x40 (64 iterations)\n3. For each iteration, store zero at current pointer location and increment pointer\n4. After loop, store additional zero byte at final pointer location\n5. Zero individual global variables at specific addresses\n\nParameters:\nNone\n\nReturns:\nvoid\n\nMagic Numbers Reference:\n0x40 (64 decimal) - Number of DWORDs to zero in main buffer\n0x1003cbc0 - Start address of main buffer to be zeroed\n0x1003caa4 - Global variable address\n0x1003cabc - Global variable address  \n0x1003ccc4 - Global variable address\n0x1003cab0 - Global variable address\n0x1003cab4 - Global variable address\n0x1003cab8 - Global variable address\n\nSpecial Cases:\nEnsures complete buffer initialization by storing extra zero byte after REP STOSD\nClears 256 bytes total (64 DWORDs * 4 bytes + 1 additional byte)",
      "name_source": "LoD/1.08",
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
    "d2mcpclient.dll_MNE_63906d1f35f7": {
      "addresses": {
        "LoD/1.07": "0x6FA5433E",
        "LoD/1.08": "0x6FA5433E",
        "LoD/1.09": "0x6F9F435E",
        "LoD/1.09b": "0x6F9F435E",
        "LoD/1.09d": "0x6F9F435E",
        "LoD/1.10": "0x6F9F421E"
      },
      "rvas": {
        "LoD/1.07": "0x433E",
        "LoD/1.08": "0x433E",
        "LoD/1.09": "0x435E",
        "LoD/1.09b": "0x435E",
        "LoD/1.09d": "0x435E",
        "LoD/1.10": "0x421E"
      },
      "sizes": {
        "LoD/1.07": 389,
        "LoD/1.08": 389,
        "LoD/1.09": 389,
        "LoD/1.09b": 389,
        "LoD/1.09d": 389,
        "LoD/1.10": 389
      },
      "signature": "void InitializeCharacterTables(void)",
      "calling_convention": "__stdcall",
      "comment": "Initializes character lookup tables and locale-specific character mappings for the current code page.\n\nAlgorithm:\n1. Retrieve code page information using GetCPInfo() with the global code page identifier\n2. If code page info valid, initialize base character table with identity mapping (0-255)\n3. Set character at index 0 to space character for proper handling\n4. Process multi-byte character lead byte ranges to mark them as spaces in character table\n5. Call FUN_10021c9e to generate character type flags for the character set\n6. Generate uppercase mappings using LocaleMapStringWithConversion with flag 0x100\n7. Generate lowercase mappings using LocaleMapStringWithConversion with flag 0x200\n8. Iterate through all 256 characters and populate global character tables:\n   - If character type flag & 0x1 (uppercase): set flag 0x10, use lowercase mapping\n   - If character type flag & 0x2 (lowercase): set flag 0x20, use uppercase mapping\n   - Otherwise: clear character mapping entry\n9. If code page info invalid, fall back to ASCII-only mappings:\n   - For A-Z (0x41-0x5A): set flag 0x10, add 0x20 for lowercase\n   - For a-z (0x61-0x7A): set flag 0x20, subtract 0x20 for uppercase\n   - For all other characters: clear mapping entry\n\nParameters:\nNone\n\nReturns:\nvoid - Function operates on global character tables DAT_1003cac0 and DAT_1003cbc0\n\nSpecial Cases:\n- Character 0 is always mapped to space (0x20) for proper null character handling\n- Lead bytes in multi-byte character sets are marked as spaces to prevent misinterpretation\n- Falls back to basic ASCII case mapping if code page information unavailable\n\nMagic Numbers:\n0x100 - LCMAP_UPPERCASE flag for LocaleMapStringWithConversion\n0x200 - LCMAP_LOWERCASE flag for LocaleMapStringWithConversion  \n0x10 - Character flag indicating uppercase letter\n0x20 - Character flag indicating lowercase letter\n0x1 - Character type flag for uppercase character\n0x2 - Character type flag for lowercase character\n0x41-0x5A - ASCII range for uppercase letters A-Z\n0x61-0x7A - ASCII range for lowercase letters a-z\n\nError Handling:\n- GetCPInfo failure triggers fallback to ASCII-only character mappings\n- Lead byte processing handles ranges safely with bounds checking\n- Character table initialization ensures all 256 entries are properly set\n\nStructure Layout:\n_cpinfo structure (18 bytes):\nOffset  Size  Field Name    Type    Description\n0x0     4     MaxCharSize   UINT    Maximum character size in bytes\n0x4     12    DefaultChar   BYTE[2] Default replacement character \n0x6     12    LeadByte      BYTE[12] Lead byte ranges for MBCS",
      "name_source": "LoD/1.08",
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
    "d2mcpclient.dll_MNE_750c71b47c1a": {
      "addresses": {
        "LoD/1.07": "0x6FA544C3",
        "LoD/1.08": "0x6FA544C3",
        "LoD/1.09": "0x6F9F44E3",
        "LoD/1.09b": "0x6F9F44E3",
        "LoD/1.09d": "0x6F9F44E3",
        "LoD/1.10": "0x6F9F43A3"
      },
      "rvas": {
        "LoD/1.07": "0x44C3",
        "LoD/1.08": "0x44C3",
        "LoD/1.09": "0x44E3",
        "LoD/1.09b": "0x44E3",
        "LoD/1.09d": "0x44E3",
        "LoD/1.10": "0x43A3"
      },
      "sizes": {
        "LoD/1.07": 28,
        "LoD/1.08": 28,
        "LoD/1.09": 28,
        "LoD/1.09b": 28,
        "LoD/1.09d": 28,
        "LoD/1.10": 28
      },
      "signature": "void InitializeCodePageOnce(void)",
      "calling_convention": "__stdcall",
      "comment": "Ensures code page locale initialization occurs only once during program execution.\n\nAlgorithm:\n1. Check initialization flag g_fCodePageInitialized for zero (uninitialized state)\n2. If uninitialized, call InitializeCodePageLocale(-3) to set up system locale\n3. Set initialization flag g_fCodePageInitialized to true (1) to prevent re-initialization\n4. Return immediately if already initialized (early exit optimization)\n\nParameters:\nNone\n\nReturns:\nvoid - No return value, initialization is fire-and-forget\n\nSpecial Cases:\n- Thread-safe one-time initialization using simple boolean flag\n- Early return optimization prevents redundant initialization calls\n- Flag remains set for program lifetime once initialization completes\n\nMagic Numbers Reference:\n0xfffffffd (-3) - Special code page identifier passed to InitializeCodePageLocale\n                  Likely represents CP_THREAD_ACP (thread's current ANSI code page)\n\nError Handling:\n- No explicit error handling; relies on InitializeCodePageLocale for error management\n- Boolean flag ensures initialization attempts happen only once regardless of success/failure",
      "name_source": "LoD/1.08",
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
    "d2mcpclient.dll_MNE_bff09423b51f": {
      "addresses": {
        "LoD/1.07": "0x6FA563A0",
        "LoD/1.08": "0x6FA563A0",
        "LoD/1.09": "0x6F9F63C0",
        "LoD/1.09b": "0x6F9F63C0",
        "LoD/1.09d": "0x6F9F63C0",
        "LoD/1.10": "0x6F9F6280"
      },
      "rvas": {
        "LoD/1.07": "0x63A0",
        "LoD/1.08": "0x63A0",
        "LoD/1.09": "0x63C0",
        "LoD/1.09b": "0x63C0",
        "LoD/1.09d": "0x63C0",
        "LoD/1.10": "0x6280"
      },
      "sizes": {
        "LoD/1.07": 664,
        "LoD/1.08": 664,
        "LoD/1.09": 664,
        "LoD/1.09b": 664,
        "LoD/1.09d": 664,
        "LoD/1.10": 664
      },
      "signature": "void * OptimizedMemoryMove(void * pDestination, void * pSource, uint dwByteCount)",
      "calling_convention": "__cdecl",
      "comment": "Optimized memory move implementation with overlap detection and alignment optimization.\n\nAlgorithm:\n1. Check for overlapping memory regions (source and destination ranges overlap)\n2. If overlapping regions detected, copy backwards from end to start to avoid corruption\n3. If no overlap, copy forwards from start to end for better cache performance\n4. For both directions, optimize copying using 4-byte aligned transfers when possible\n5. Handle misaligned data by copying individual bytes first to reach alignment\n6. Perform bulk 4-byte transfers in optimized loop (unroll threshold of 8 iterations)\n7. Copy remaining bytes (0-3) using individual byte transfers\n\nParameters:\npDestination - Destination memory buffer to copy data to\npSource - Source memory buffer to copy data from  \ndwByteCount - Number of bytes to copy between buffers\n\nReturns:\nvoid * - Returns original destination pointer (pDestination) for function chaining\n\nSpecial Cases:\nZero byte count - Returns immediately without any memory operations\nMisaligned pointers - Falls back to byte-by-byte copying with alignment handling\nLarge transfers - Uses optimized 4-byte transfers with loop unrolling for performance\n\nMagic Numbers Reference:\n0x4 (4) - Alignment boundary and 4-byte transfer size\n0x3 (3) - Alignment mask to check 4-byte boundary alignment  \n0x7 (7) - Loop unrolling threshold for optimized bulk transfer\n\nError Handling:\nNo explicit error checking - assumes valid memory regions and non-null pointers\nOverlap detection prevents memory corruption during overlapping copies\nAlignment optimization ensures optimal performance on x86 architecture",
      "name_source": "LoD/1.08",
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
    "d2mcpclient.dll_MNE_e4c337356f23": {
      "addresses": {
        "LoD/1.07": "0x6FA54815",
        "LoD/1.08": "0x6FA54815",
        "LoD/1.09": "0x6F9F4835",
        "LoD/1.09b": "0x6F9F4835",
        "LoD/1.09d": "0x6F9F4835",
        "LoD/1.10": "0x6F9F46F5"
      },
      "rvas": {
        "LoD/1.07": "0x4815",
        "LoD/1.08": "0x4815",
        "LoD/1.09": "0x4835",
        "LoD/1.09b": "0x4835",
        "LoD/1.09d": "0x4835",
        "LoD/1.10": "0x46F5"
      },
      "sizes": {
        "LoD/1.07": 23,
        "LoD/1.08": 23,
        "LoD/1.09": 23,
        "LoD/1.09b": 23,
        "LoD/1.09d": 23,
        "LoD/1.10": 23
      },
      "signature": "void * ParseNumberWithDefaultFlags(void * this, char * _Str, char * * _EndPtr, int _Radix)",
      "calling_convention": "__thiscall",
      "comment": "Wrapper for ParseNumberWithLocking with default flags (0)\nDelegates to actual implementation with zero flag parameter\n\nAlgorithm:\n1. Push zero constant (default flags)\n2. Push three parameters from stack\n3. Call ParseNumberWithLocking with all four parameters\n4. Return result from implementation\n\nParameters:\nthis - this pointer for method context\npszInput - pointer to input string\npnOutput - pointer to output integer result (error position if parsing fails)\nnRadix - number base (8=octal, 10=decimal, 16=hexadecimal)\n\nReturns:\nVoid pointer with result from ParseNumberWithLocking, or NULL on error\n\nSee Also:\nParseNumberWithLocking - Actual implementation with full parameter control",
      "name_source": "LoD/1.08",
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
    "d2mcpclient.dll_MNE_cf4bba8373cc": {
      "addresses": {
        "LoD/1.07": "0x6FA5482C",
        "LoD/1.08": "0x6FA5482C",
        "LoD/1.09": "0x6F9F484C",
        "LoD/1.09b": "0x6F9F484C",
        "LoD/1.09d": "0x6F9F484C",
        "LoD/1.10": "0x6F9F470C"
      },
      "rvas": {
        "LoD/1.07": "0x482C",
        "LoD/1.08": "0x482C",
        "LoD/1.09": "0x484C",
        "LoD/1.09b": "0x484C",
        "LoD/1.09d": "0x484C",
        "LoD/1.10": "0x470C"
      },
      "sizes": {
        "LoD/1.07": 517,
        "LoD/1.08": 517,
        "LoD/1.09": 517,
        "LoD/1.09b": 517,
        "LoD/1.09d": 517,
        "LoD/1.10": 517
      },
      "signature": "void * StringToUnsignedLongWithBase(void * this, byte * pbString, byte * * ppbEndPtr, int nBase, uint dwFlags)",
      "calling_convention": "__thiscall",
      "comment": "Convert string to unsigned long integer with specified base.\n\nAlgorithm:\n1. Skip leading whitespace characters using character attribute table\n2. Process optional sign character (+ or -)\n3. Validate base parameter (must be 0-36, excluding 1)\n4. Auto-detect base if base parameter is 0:\n   - If string starts with '0x' or '0X': hexadecimal (base 16)\n   - If string starts with '0': octal (base 8) \n   - Otherwise: decimal (base 10)\n5. Skip '0x' or '0X' prefix for hexadecimal numbers\n6. Calculate maximum value threshold for overflow detection\n7. Process each character in conversion loop:\n   - Check if character is valid digit for specified base\n   - For digits 0-9: convert using character code - 0x30\n   - For letters A-F/a-f: use FUN_6ff2bc30 and subtract 0x37\n   - Validate digit value is less than base\n   - Check for overflow before multiplication\n   - Accumulate result: result = result * base + digit\n8. Handle overflow conditions and set errno to ERANGE (0x22)\n9. Apply negative sign if flag bit 2 is set\n10. Update end pointer to point to first non-converted character\n\nParameters:\npContext (void*): Context data pointer for character processing mode\npbString (byte*): Input string to convert\nppbEndPtr (byte**): Output pointer to first unconverted character (may be NULL)\nnBase (int): Numeric base for conversion (0 for auto-detect, 2-36)\ndwFlags (uint): Control flags for conversion behavior\n\nReturns:\nvoid*: Converted unsigned long value, or 0 on invalid input\n- Returns 0x00000000 for invalid base or no valid digits\n- Returns 0xFFFFFFFF for unsigned overflow with UINT_MAX flag\n- Returns 0x7FFFFFFF for signed positive overflow\n- Returns 0x80000000 for signed negative overflow\n\nSpecial Cases:\nInvalid base values (base < 0, base == 1, base > 36) return 0\nEmpty strings or strings with no valid digits return 0\nOverflow conditions set errno via FUN_6ff2cab3() to ERANGE (0x22)\n\nFlag Bits:\n0x01: UINT_MAX flag - return 0xFFFFFFFF on overflow\n0x02: Negative sign detected\n0x04: Overflow detected during conversion\n0x08: At least one digit successfully processed\n\nMagic Numbers Reference:\n0x2D: ASCII '-' (minus sign)\n0x2B: ASCII '+' (plus sign)\n0x30: ASCII '0' (digit zero)\n0x78: ASCII 'x' (lowercase hex prefix)\n0x58: ASCII 'X' (uppercase hex prefix)\n0x37: Offset for converting A-F to 10-15\n0x08: Character attribute bit for whitespace\n0x04: Character attribute bit for digit\n0x103: Character attribute bits for hex digit\n0x22: ERANGE errno value\n0x7FFFFFFF: Maximum positive signed 32-bit value\n0x80000000: Maximum negative signed 32-bit value\n0xFFFFFFFF: Maximum unsigned 32-bit value\n\nError Handling:\nBase validation failure: Returns 0, sets endptr to original string\nOverflow detection: Sets errno to ERANGE, returns appropriate limit value\nInvalid characters: Stops conversion, sets endptr to invalid character",
      "name_source": "LoD/1.08",
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
    "d2mcpclient.dll__strchr": {
      "addresses": {
        "LoD/1.07": "0x6FA54A50"
      },
      "rvas": {
        "LoD/1.07": "0x4A50"
      },
      "sizes": {
        "LoD/1.07": 193
      },
      "name": "_strchr",
      "signature": "char * _strchr(char * _Str, int _Val)",
      "calling_convention": "__cdecl",
      "comment": "Library Function - Single Match\n _strchr\n\nLibraries: Visual Studio 1998 Debug, Visual Studio 1998 Release",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:e8d820fe0ad4443eff596f9c063b1159",
      "basic_block_counts": {
        "LoD/1.07": 26
      },
      "loop_counts": {
        "LoD/1.07": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "e8d820fe0ad4443eff596f9c063b1159"
      }
    },
    "d2mcpclient.dll__strstr": {
      "addresses": {
        "LoD/1.07": "0x6FA54B10",
        "LoD/1.08": "0x6FA54B10",
        "LoD/1.09": "0x6F9F4B30",
        "LoD/1.09b": "0x6F9F4B30",
        "LoD/1.09d": "0x6F9F4B30",
        "LoD/1.10": "0x6F9F49F0"
      },
      "rvas": {
        "LoD/1.07": "0x4B10",
        "LoD/1.08": "0x4B10",
        "LoD/1.09": "0x4B30",
        "LoD/1.09b": "0x4B30",
        "LoD/1.09d": "0x4B30",
        "LoD/1.10": "0x49F0"
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
    "d2mcpclient.dll__strncmp": {
      "addresses": {
        "LoD/1.07": "0x6FA54B90",
        "LoD/1.08": "0x6FA54B90",
        "LoD/1.09": "0x6F9F4BB0",
        "LoD/1.09b": "0x6F9F4BB0",
        "LoD/1.09d": "0x6F9F4BB0",
        "LoD/1.10": "0x6F9F4A70",
        "LoD/1.11": "0x6FA24DD0",
        "LoD/1.11b": "0x6FA24DD0",
        "LoD/1.12a": "0x6FA24E00",
        "LoD/1.13c": "0x6FA24E00",
        "LoD/1.13d": "0x6FA25110"
      },
      "rvas": {
        "LoD/1.07": "0x4B90",
        "LoD/1.08": "0x4B90",
        "LoD/1.09": "0x4BB0",
        "LoD/1.09b": "0x4BB0",
        "LoD/1.09d": "0x4BB0",
        "LoD/1.10": "0x4A70",
        "LoD/1.11": "0x4DD0",
        "LoD/1.11b": "0x4DD0",
        "LoD/1.12a": "0x4E00",
        "LoD/1.13c": "0x4E00",
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
    "d2mcpclient.dll_MNE_2a518bd4b0b9": {
      "addresses": {
        "LoD/1.07": "0x6FA54BD0",
        "LoD/1.08": "0x6FA54BD0",
        "LoD/1.09": "0x6F9F4BF0",
        "LoD/1.09b": "0x6F9F4BF0",
        "LoD/1.09d": "0x6F9F4BF0",
        "LoD/1.10": "0x6F9F4AB0"
      },
      "rvas": {
        "LoD/1.07": "0x4BD0",
        "LoD/1.08": "0x4BD0",
        "LoD/1.09": "0x4BF0",
        "LoD/1.09b": "0x4BF0",
        "LoD/1.09d": "0x4BF0",
        "LoD/1.10": "0x4AB0"
      },
      "sizes": {
        "LoD/1.07": 47,
        "LoD/1.08": 47,
        "LoD/1.09": 47,
        "LoD/1.09b": 47,
        "LoD/1.09d": 47,
        "LoD/1.10": 47
      },
      "signature": "void AllocateStackSpace(void)",
      "calling_convention": "__stdcall",
      "comment": "Dynamically allocates stack space with page probing to ensure proper memory commitment.\n\nAlgorithm:\n1. Initialize stack pointer to current position plus 8 bytes (beyond return address and saved ECX)\n2. Check if requested allocation size exceeds one page (0x1000 bytes)\n3. If multi-page allocation needed, enter probing loop:\n   - Subtract one page (0x1000 bytes) from stack pointer\n   - Subtract one page from remaining allocation size\n   - Touch memory at stack pointer to trigger page commitment\n   - Repeat until remaining size is less than one page\n4. Subtract final remaining bytes from stack pointer\n5. Touch memory at final stack position to commit last page\n6. Update ESP register to new stack pointer position\n7. Restore original ECX and return address from saved stack frame\n8. Return to caller with stack space allocated and committed\n\nParameters:\ndwStackSize (uint) - Number of bytes to allocate on stack\n\nReturns:\nvoid - No return value, modifies stack pointer directly\n\nSpecial Cases:\n- Single page allocations (\u2264 0xFFF bytes) skip the probing loop\n- Memory touches use TEST instruction to trigger page faults for uncommitted pages\n- Stack grows downward, so allocation decreases stack pointer\n- Function preserves ECX register across call\n\nMagic Numbers Reference:\n0x1000 (4096) - Windows page size for stack probing\n0xFFF (4095) - Maximum single-page allocation without probing\n\nError Handling:\n- No explicit error handling - relies on Windows page fault mechanism\n- Invalid memory access triggers system page fault handler\n- Stack overflow protection handled by system guard pages",
      "name_source": "LoD/1.08",
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
    "d2mcpclient.dll_MNE_a57b3ae583e4": {
      "addresses": {
        "LoD/1.07": "0x6FA54BFF",
        "LoD/1.08": "0x6FA54BFF",
        "LoD/1.09": "0x6F9F4C1F",
        "LoD/1.09b": "0x6F9F4C1F",
        "LoD/1.09d": "0x6F9F4C1F",
        "LoD/1.10": "0x6F9F4ADF",
        "LoD/1.11": "0x6FA234C4",
        "LoD/1.11b": "0x6FA234C4",
        "LoD/1.12a": "0x6FA234FC",
        "LoD/1.13c": "0x6FA234FC",
        "LoD/1.13d": "0x6FA23804"
      },
      "rvas": {
        "LoD/1.07": "0x4BFF",
        "LoD/1.08": "0x4BFF",
        "LoD/1.09": "0x4C1F",
        "LoD/1.09b": "0x4C1F",
        "LoD/1.09d": "0x4C1F",
        "LoD/1.10": "0x4ADF",
        "LoD/1.11": "0x34C4",
        "LoD/1.11b": "0x34C4",
        "LoD/1.12a": "0x34FC",
        "LoD/1.13c": "0x34FC",
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
      "signature": "int InitializeMemoryPool(uint dwPoolSizeLimit)",
      "calling_convention": "__cdecl",
      "comment": "Initialize memory pool allocation system with specified size limit.\n\nAlgorithm:\n1. Allocate heap memory for MemoryAllocation table (320 bytes)\n2. Verify allocation succeeded, return failure if NULL\n3. Initialize allocation tracking globals to zero state\n4. Set allocation table base pointer in global variables\n5. Store pool size limit parameter in global state\n6. Set default allocation granularity to 16 bytes\n\nParameters:\ndwPoolSizeLimit (uint) - Maximum size in bytes for the memory pool\n\nReturns:\n1 - Memory pool successfully initialized\n0 - Allocation failed, pool not initialized\n\nMagic Numbers Reference:\n0x140 (320 bytes) - Size of MemoryAllocation table for tracking allocations\n0x10 (16 bytes) - Default allocation granularity/alignment value\n\nError Handling:\nAllocation failure: Returns 0 immediately if HeapAlloc fails\nNo exception handling: Function assumes valid heap handle exists\n\nStructure Layout:\nMemoryAllocation table - 20-byte structure for tracking individual allocations\nTable accommodates 16 allocation entries (320/20 = 16)",
      "name_source": "LoD/1.08",
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
    "d2mcpclient.dll_MNE_2a0dd1f395da": {
      "addresses": {
        "LoD/1.07": "0x6FA54C47",
        "LoD/1.08": "0x6FA54C47",
        "LoD/1.09": "0x6F9F4C67",
        "LoD/1.09b": "0x6F9F4C67",
        "LoD/1.09d": "0x6F9F4C67",
        "LoD/1.10": "0x6F9F4B27",
        "LoD/1.11": "0x6FA2350C",
        "LoD/1.11b": "0x6FA2350C",
        "LoD/1.12a": "0x6FA23544",
        "LoD/1.13c": "0x6FA23544",
        "LoD/1.13d": "0x6FA2384C"
      },
      "rvas": {
        "LoD/1.07": "0x4C47",
        "LoD/1.08": "0x4C47",
        "LoD/1.09": "0x4C67",
        "LoD/1.09b": "0x4C67",
        "LoD/1.09d": "0x4C67",
        "LoD/1.10": "0x4B27",
        "LoD/1.11": "0x350C",
        "LoD/1.11b": "0x350C",
        "LoD/1.12a": "0x3544",
        "LoD/1.13c": "0x3544",
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
      "signature": "MemoryDescriptor * FindMemoryDescriptorByAddress(uint dwTargetAddress)",
      "calling_convention": "__cdecl",
      "comment": "Searches for a MemoryDescriptor entry containing a target address within a 1MB range.\n\nAlgorithm:\n1. Initialize iterator to start of MemoryDescriptor array (PTR_1003ce08)\n2. Calculate array end boundary using count (INT_1003ce04) * 20-byte element size\n3. Loop through array until end boundary reached:\n   a. Calculate address difference from target to descriptor base address (offset 0xc)\n   b. Check if difference is within 0x100000 (1MB) range using unsigned comparison\n   c. If match found, return pointer to current MemoryDescriptor\n   d. Otherwise advance iterator by 20 bytes (0x14) to next descriptor\n4. Return 0 if no matching descriptor found\n\nParameters:\n- nTargetAddress (int): Target address to locate within memory descriptors\n\nReturns:\n- MemoryDescriptor *: Pointer to descriptor containing target address\n- 0: No descriptor found containing target address within 1MB range\n\nSpecial Cases:\n- Empty array (count = 0): Returns 0 immediately\n- Target address beyond all descriptors: Returns 0 after full iteration\n\nMagic Numbers Reference:\n- 0x14 (20): MemoryDescriptor structure size in bytes\n- 0xc (12): Offset to base address field within MemoryDescriptor\n- 0x100000 (1048576): Maximum address range tolerance (1MB)\n\nStructure Layout:\nOffset | Size | Field Name       | Type | Description\n-------|------|------------------|------|------------------\n+0x00  | ?    | [Unknown fields] | ?    | Structure prefix\n+0x0c  | 4    | dwBaseAddress    | uint | Base memory address\n+0x10  | ?    | [Unknown fields] | ?    | Additional data\nTotal: 20 bytes (0x14)",
      "name_source": "LoD/1.08",
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
    "d2mcpclient.dll_MNE_ef5171f8f748": {
      "addresses": {
        "LoD/1.07": "0x6FA54C72",
        "LoD/1.08": "0x6FA54C72",
        "LoD/1.09": "0x6F9F4C92",
        "LoD/1.09b": "0x6F9F4C92",
        "LoD/1.09d": "0x6F9F4C92",
        "LoD/1.10": "0x6F9F4B52"
      },
      "rvas": {
        "LoD/1.07": "0x4C72",
        "LoD/1.08": "0x4C72",
        "LoD/1.09": "0x4C92",
        "LoD/1.09b": "0x4C92",
        "LoD/1.09d": "0x4C92",
        "LoD/1.10": "0x4B52"
      },
      "sizes": {
        "LoD/1.07": 809,
        "LoD/1.08": 809,
        "LoD/1.09": 809,
        "LoD/1.09b": 809,
        "LoD/1.09d": 809,
        "LoD/1.10": 809
      },
      "signature": "void DeallocateMemoryBlock(MemoryPool * pMemoryPool, int nBlockAddress)",
      "calling_convention": "__cdecl",
      "comment": "Deallocates memory block and updates free list structures and allocation bitmaps.\n\nAlgorithm:\n1. Extract bitmap base address from pMemoryPool[4] and calculate pool index from block address\n2. Get free list header pointer using pool index * 0x204 + 0x144 offset calculation\n3. Read block header from (nBlockAddress - 4) to get current block size information\n4. Validate block is not already free by checking low bit of adjusted size (must be 0)\n5. If current block can be coalesced with next block:\n   a. Calculate size index from block size (>> 4) - 1, clamped to 0x3F maximum\n   b. Check if next block's prev/next pointers are equal (indicates it's in free list)\n   c. Update allocation bitmap by clearing bit and decrementing reference count\n   d. Remove next block from its free list by updating linked list pointers\n6. If current block can be coalesced with previous block:\n   a. Calculate size indices for both current and previous blocks\n   b. If size indices differ, remove previous block from its free list\n   c. Update allocation bitmap for previous block size\n   d. Merge blocks by updating size and pointers\n7. Insert merged block into appropriate free list:\n   a. Link block into free list header for calculated size index\n   b. Update allocation bitmap by setting bit and incrementing reference count\n8. Update block headers with final merged size and create footer with size\n9. Decrement free list header reference count\n10. If reference count reaches zero, deallocate entire pool:\n    a. Call VirtualFree to release 32KB memory region\n    b. Update global allocation tracking structures\n    c. Call HeapFree to release bitmap data structure\n    d. Compact allocation table by removing deallocated entry\n    e. Update global pointers and counters\n\nParameters:\npMemoryPool    - Pointer to MemoryPool structure containing bitmap and offset data\nnBlockAddress  - Memory address of block to deallocate (actual allocated address, not header)\n\nReturns:\nvoid\n\nSpecial Cases:\n- Block already marked as free (low bit set) causes early return with no action\n- Size indices are clamped to maximum value 0x3F for bitmap array bounds\n- Bitmap spans two 32-bit words: bits 0-31 and 32-63, requiring different calculations\n- Pool deallocation only occurs when reference count reaches exactly zero\n\nMagic Numbers Reference:\n0x3F (63)     - Maximum size index for allocation bitmap (64 total size classes)\n0x204 (516)   - Size of each pool's metadata structure in bytes\n0x144 (324)   - Offset to free list headers within pool structure  \n0x44 (68)     - Offset to first bitmap word (bits 0-31) from bitmap base\n0xc4 (196)    - Offset to second bitmap word (bits 32-63) from bitmap base\n0x8000        - Pool size: 32KB per memory pool allocation\n0x4000        - VirtualFree flag: MEM_DECOMMIT for releasing committed memory\n0x8000        - VirtualFree flag: MEM_RELEASE for releasing reserved memory\n0x80000000    - Bit mask base for calculating allocation bitmap bits\n\nStructure Layout:\nMemoryPool (20 bytes):\nOffset  Size  Field Name       Type    Description\n0x00    4     dwPoolFlags      uint    Pool status flags and allocation state\n0x04    4     dwSecondaryFlags uint    Secondary bitmap flags  \n0x08    4     dwPoolIndex      uint    Index of this pool in global table\n0x0C    4     dwBaseOffset     uint    Base address offset for this pool\n0x10    4     pBitmapData      void*   Pointer to allocation bitmap data structure\n\nFreeBlock (12 bytes):\nOffset  Size  Field Name    Type    Description\n0x00    4     dwBlockSize   uint    Size of this free block in bytes (low bit = free flag)\n0x04    4     pNext         void*   Pointer to next free block in same size class\n0x08    4     pPrev         void*   Pointer to previous free block in same size class",
      "name_source": "LoD/1.08",
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
    "d2mcpclient.dll_MNE_ff64648b3e6e": {
      "addresses": {
        "LoD/1.07": "0x6FA54F9B",
        "LoD/1.08": "0x6FA54F9B",
        "LoD/1.09": "0x6F9F4FBB",
        "LoD/1.09b": "0x6F9F4FBB",
        "LoD/1.09d": "0x6F9F4FBB",
        "LoD/1.10": "0x6F9F4E7B"
      },
      "rvas": {
        "LoD/1.07": "0x4F9B",
        "LoD/1.08": "0x4F9B",
        "LoD/1.09": "0x4FBB",
        "LoD/1.09b": "0x4FBB",
        "LoD/1.09d": "0x4FBB",
        "LoD/1.10": "0x4E7B"
      },
      "sizes": {
        "LoD/1.07": 777,
        "LoD/1.08": 777,
        "LoD/1.09": 777,
        "LoD/1.09b": 777,
        "LoD/1.09d": 777,
        "LoD/1.10": 777
      },
      "signature": "void * AllocateMemoryDescriptorBlock(uint dwRequestedSize)",
      "calling_convention": "__cdecl",
      "comment": "Allocates memory block from descriptor-based allocator with size-class free lists\n\nAlgorithm:\n1. Align requested size to 16-byte boundary and calculate size class index\n2. Generate bitmasks for free block tracking based on size class (splits at 32-bit boundary)\n3. Search descriptor array for available descriptor with matching free blocks\n4. If no descriptor found, search from beginning for any available descriptor\n5. If still no descriptor, search for descriptor with zero reserved field\n6. If no descriptor available, call allocation expansion function (FUN_1001db6e)\n7. If expansion fails, initialize new descriptor with FUN_1001dc1f\n8. Locate appropriate free list and find block of suitable size\n9. Calculate bit position for free block tracking within size class\n10. Remove block from free list by unlinking (doubly-linked list operations)\n11. If block larger than needed, split block and reinsert remainder into appropriate size class\n12. Update bit tracking arrays and reference counts for block allocation\n13. Set block headers with size information for boundary tag system\n14. Update global state if this was the last block in descriptor\n15. Return pointer to allocated memory (block pointer + 4 for header skip)\n\nParameters:\n- nRequestedSize (uint): Size in bytes to allocate, will be aligned to 16-byte boundary\n\nReturns:\n- void*: Pointer to allocated memory block, or NULL if allocation fails\n\nSpecial Cases:\n- Sizes are rounded up to next 16-byte boundary (add 0x17, mask with 0xfffffff0)\n- Free blocks tracked using dual bitmask system (low 32 bits, high 32 bits)\n- Size classes use bit positions 0-63 for different allocation sizes\n- Block splitting occurs when allocated block significantly larger than request\n- Boundary tag system maintains size at block start and end for coalescing\n\nMagic Numbers Reference:\n- 0x17 (23): Alignment padding for 16-byte boundaries\n- 0xfffffff0: Mask for 16-byte alignment\n- 0x20 (32): Bit boundary for high/low bitmask split\n- 0x3f (63): Maximum size class index\n- 0x81 (129): Stride for free list array access (129 dwords per size class)\n- 0x51 (81): Base offset for free list pointers in allocator data\n- 0x31 (49): Offset to high bitmask in allocator data\n- 0x11 (17): Offset to low bitmask in allocator data\n- 0x80000000: High bit mask for bit manipulation operations\n\nStructure Layout:\nOffset | Size | Field Name    | Type              | Description\n-------|------|---------------|-------------------|---------------------------\n0x00   | 4    | pHeapMemory   | void*             | Pointer to heap memory base\n0x04   | 4    | pVirtualMemory| void*             | Pointer to virtual memory\n0x08   | 4    | dwReserved1   | uint              | Reserved field, 0=available\n0x0C   | 4    | dwFlags       | uint              | Descriptor flags/status\n0x10   | 4    | pAllocatorData| AllocatorData*    | Pointer to allocator metadata\n\nError Handling:\n- Returns NULL if expansion function (FUN_1001db6e) fails to provide new descriptor\n- Returns NULL if descriptor initialization (FUN_1001dc1f) returns -1\n- Gracefully handles empty free lists by searching alternate size classes\n- Validates descriptor boundaries before proceeding with allocation",
      "name_source": "LoD/1.08",
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
    "d2mcpclient.dll_MNE_b59a8a7d2c8f": {
      "addresses": {
        "LoD/1.07": "0x6FA552A4",
        "LoD/1.08": "0x6FA552A4",
        "LoD/1.09": "0x6F9F52C4",
        "LoD/1.09b": "0x6F9F52C4",
        "LoD/1.09d": "0x6F9F52C4",
        "LoD/1.10": "0x6F9F5184"
      },
      "rvas": {
        "LoD/1.07": "0x52A4",
        "LoD/1.08": "0x52A4",
        "LoD/1.09": "0x52C4",
        "LoD/1.09b": "0x52C4",
        "LoD/1.09d": "0x52C4",
        "LoD/1.10": "0x5184"
      },
      "sizes": {
        "LoD/1.07": 177,
        "LoD/1.08": 177,
        "LoD/1.09": 177,
        "LoD/1.09b": 177,
        "LoD/1.09d": 177,
        "LoD/1.10": 177
      },
      "signature": "undefined4 * AllocateMemoryDescriptor(void)",
      "calling_convention": "__stdcall",
      "comment": "Allocates a new memory descriptor with associated heap and virtual memory buffers.\n\nAlgorithm:\n1. Check if descriptor array is full (g_nDescriptorCount == g_dwBufferElementSize)\n2. If full, reallocate descriptor array with space for 16 more entries using HeapReAlloc\n3. Update g_dwBufferElementSize by adding 0x10 and store new array pointer in g_pDescriptorArray\n4. Calculate pointer to next available descriptor (g_pDescriptorArray + g_nDescriptorCount)\n5. Allocate 0x41c4 bytes of heap memory using HeapAlloc with HEAP_ZERO_MEMORY flag (0x8)\n6. Store heap allocation pointer in descriptor dwReserved3 field\n7. Allocate 1MB (0x100000) of virtual memory using VirtualAlloc with MEM_RESERVE flag (0x2000)\n8. Store virtual allocation pointer in descriptor dwReserved2 field\n9. Initialize descriptor fields: dwReserved1 = 0xffffffff, clear pVirtualMemory and pHeapMemory\n10. Increment global descriptor count (g_nDescriptorCount)\n11. Set first DWORD of heap memory to 0xffffffff as initialization marker\n12. Return pointer to pVirtualMemory field of the new descriptor\n\nParameters:\nNone\n\nReturns:\nvoid * - Pointer to pVirtualMemory field of allocated descriptor on success\nNULL - If descriptor array reallocation fails, heap allocation fails, or virtual memory allocation fails\n\nSpecial Cases:\nIf heap allocation succeeds but virtual memory allocation fails, the heap memory is freed to prevent leaks before returning NULL\n\nMagic Numbers Reference:\n0x10 (16) - Descriptor array growth increment\n0x41c4 (16836) - Size of heap allocation per descriptor\n0x100000 (1048576) - Virtual memory allocation size (1MB)\n0x2000 (8192) - MEM_RESERVE flag for VirtualAlloc\n0x8 (8) - HEAP_ZERO_MEMORY flag for HeapAlloc\n0xffffffff (-1) - Initialization value for dwReserved1 and heap memory marker\n\nStructure Layout:\nMemoryDescriptor (20 bytes total):\nOffset | Size | Field Name      | Type    | Description\n0x00   | 4    | pVirtualMemory  | void *  | Pointer to virtual memory allocation\n0x04   | 4    | pHeapMemory     | void *  | Pointer to heap memory allocation\n0x08   | 4    | dwReserved1     | uint    | Status/flags field, initialized to 0xffffffff\n0x0C   | 4    | dwReserved2     | uint    | Stores virtual memory allocation pointer\n0x10   | 4    | dwReserved3     | uint    | Stores heap memory allocation pointer\n\nError Handling:\nArray reallocation failure returns NULL immediately without cleanup\nHeap allocation failure returns NULL immediately\nVirtual allocation failure after successful heap allocation frees heap memory before returning NULL",
      "name_source": "LoD/1.08",
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
    "d2mcpclient.dll_MNE_0002c858ef39": {
      "addresses": {
        "LoD/1.07": "0x6FA55355",
        "LoD/1.08": "0x6FA55355",
        "LoD/1.09": "0x6F9F5375",
        "LoD/1.09b": "0x6F9F5375",
        "LoD/1.09d": "0x6F9F5375",
        "LoD/1.10": "0x6F9F5235"
      },
      "rvas": {
        "LoD/1.07": "0x5355",
        "LoD/1.08": "0x5355",
        "LoD/1.09": "0x5375",
        "LoD/1.09b": "0x5375",
        "LoD/1.09d": "0x5375",
        "LoD/1.10": "0x5235"
      },
      "sizes": {
        "LoD/1.07": 251,
        "LoD/1.08": 251,
        "LoD/1.09": 251,
        "LoD/1.09b": 251,
        "LoD/1.09d": 251,
        "LoD/1.10": 251
      },
      "signature": "int AllocateMemorySlot(MemoryDescriptor * pMemoryDescriptor)",
      "calling_convention": "__cdecl",
      "comment": "Allocates a memory slot in the memory descriptor system and initializes linked list structures.\n\nAlgorithm:\n1. Extract base offset from memory descriptor (offset 0x10)\n2. Find next available slot by counting leading set bits in allocation mask (offset 0x8)\n3. Calculate descriptor offset: slot_index * 0x204 + 0x144 + base_offset\n4. Initialize 64 linked list node pairs (0x3f iterations) with self-referencing pointers\n5. Calculate memory base address: slot_index * 0x8000 + base_address (offset 0xc)\n6. Allocate 32KB (0x8000 bytes) of virtual memory with VirtualAlloc\n7. If allocation fails, return -1\n8. Initialize memory block as doubly-linked list with 1024-byte (0x400) stride\n9. Set up forward and backward pointers for each node in the allocated block\n10. Link descriptor to allocated memory at specific offsets (0x1fc, 0x200)\n11. Clear slot status flag at base_offset + 0x44 + slot_index * 4\n12. Set slot allocation flag at base_offset + 0xc4 + slot_index * 4\n13. Increment allocation counter at base_offset + 0x43\n14. If counter wraps to 0, set overflow flag (bit 0) in descriptor flags (offset 0x4)\n15. Clear allocated bit in allocation mask using bit manipulation\n\nParameters:\npMemoryDescriptor - Pointer to MemoryDescriptor structure containing allocation state\n\nReturns:\nSlot index (0-31) on successful allocation\n-1 on VirtualAlloc failure\n\nSpecial Cases:\nMagic Numbers Reference:\n0x204 (516) - Descriptor block size per slot\n0x144 (324) - Base descriptor offset \n0x8000 (32768) - Memory block size (32KB)\n0x1000 (4096) - VirtualAlloc MEM_COMMIT flag\n0x3f (63) - Loop counter for 64 node pairs\n0x400 (1024) - Node stride in memory block\n0xff0 (4080) - Node size/offset marker\n0x1c00 (7168) - Memory block boundary check\n\nStructure Layout:\nOffset | Size | Field Name    | Type | Description\n0x4    | 4    | dwFlags       | uint | Status flags (bit 0 = overflow)\n0x8    | 4    | dwAllocMask   | uint | Allocation bitmask (bit per slot)  \n0xc    | 4    | pBaseMemory   | int* | Base address for memory blocks\n0x10   | 4    | nBaseOffset   | int  | Base offset for descriptor blocks\n\nError Handling:\nVirtualAlloc failure returns -1 without modifying descriptor state\nSlot index calculation assumes valid input parameters",
      "name_source": "LoD/1.08",
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
    "d2mcpclient.dll_MNE_b10e654b1e08": {
      "addresses": {
        "LoD/1.07": "0x6FA55450",
        "LoD/1.08": "0x6FA55450",
        "LoD/1.09": "0x6F9F5470",
        "LoD/1.09b": "0x6F9F5470",
        "LoD/1.09d": "0x6F9F5470",
        "LoD/1.10": "0x6F9F5330"
      },
      "rvas": {
        "LoD/1.07": "0x5450",
        "LoD/1.08": "0x5450",
        "LoD/1.09": "0x5470",
        "LoD/1.09b": "0x5470",
        "LoD/1.09d": "0x5470",
        "LoD/1.10": "0x5330"
      },
      "sizes": {
        "LoD/1.07": 324,
        "LoD/1.08": 324,
        "LoD/1.09": 324,
        "LoD/1.09b": 324,
        "LoD/1.09d": 324,
        "LoD/1.10": 324
      },
      "signature": "ErrorTableEntry * InitializeMemoryAllocator(void)",
      "calling_convention": "__stdcall",
      "comment": "Initializes a memory allocator with virtual memory management and free list structures.\n\nAlgorithm:\n1. Check global allocator mode (g_nAllocatorMode) to determine allocation strategy\n2. If mode is -1, use static global error table offset (g_aErrorTable + 0x12)\n3. Otherwise, allocate 0x2020 bytes from heap for descriptor structure\n4. Reserve 4MB (0x400000) of virtual address space with MEM_RESERVE flag\n5. Commit first 64KB (0x10000) with PAGE_READWRITE protection\n6. Initialize allocator descriptor linking to global error table chain\n7. Setup memory structure pointers: base, end, free list start\n8. Initialize 1024 (0x400) free list entries with size masks and patterns\n9. Clear committed memory region to zero\n10. Setup memory blocks with headers and free list linkage\n11. Return pointer to allocator descriptor on success, NULL on failure\n\nParameters:\nNone\n\nReturns:\nErrorTableEntry * - Pointer to allocator descriptor on success, NULL on failure\n  - Success: Valid pointer to initialized memory allocator structure\n  - Error: NULL if heap allocation fails or virtual memory allocation fails\n\nSpecial Cases:\n- Static mode (g_nAllocatorMode == -1): Uses pre-allocated global structure\n- Dynamic mode (g_nAllocatorMode != -1): Allocates new descriptor from heap\n- Memory allocation failures trigger cleanup of partial allocations\n- Error table is repurposed as allocator descriptor structure\n\nMagic Numbers Reference:\n0x2020 (8224 decimal) - Heap allocation size for allocator descriptor\n0x400000 (4194304 decimal) - Virtual memory reservation size (4MB)\n0x10000 (65536 decimal) - Initial committed memory size (64KB)  \n0x2000 (8192 decimal) - MEM_RESERVE flag for VirtualAlloc\n0x1000 (4096 decimal) - MEM_COMMIT flag for VirtualAlloc\n0x8000 (32768 decimal) - MEM_RELEASE flag for VirtualFree\n0x400 (1024 decimal) - Number of free list entries to initialize\n0xf1 (241 decimal) - Free block size pattern mask\n0xff (255 decimal) - Block header marker byte\n0xf0 (240 decimal) - Block size field value\n0x1000 (4096 decimal) - Block stride size\n\nError Handling:\n- HeapAlloc failure: Returns NULL immediately\n- VirtualAlloc reserve failure: Cleans up heap allocation if dynamic mode\n- VirtualAlloc commit failure: Releases reserved memory and cleans up heap\n- All cleanup paths properly restore system state before returning NULL\n\nStructure Layout:\nErrorTableEntry repurposed as AllocatorDescriptor:\nOffset  Size  Field Name          Type              Description\n0x00    4     dwErrorCode         uint              Base pointer or link field  \n0x04    4     lpszMessage         char *            Next pointer or link field\n0x08    4     [field2].dwCode     uint              Free list start pointer\n0x0C    4     [field2].lpMsg      char *            Memory descriptor pointer  \n0x10    4     [field3].dwCode     uint              Virtual memory base\n0x14    4     [field3].lpMsg      char *            Virtual memory end\n0x18    ...   Free List Entries   ErrorTableEntry[] Array of 1024 free block entries",
      "name_source": "LoD/1.08",
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
    "d2mcpclient.dll_MNE_54ffff5ceafb": {
      "addresses": {
        "LoD/1.07": "0x6FA55594",
        "LoD/1.08": "0x6FA55594",
        "LoD/1.09": "0x6F9F55B4",
        "LoD/1.09b": "0x6F9F55B4",
        "LoD/1.09d": "0x6F9F55B4",
        "LoD/1.10": "0x6F9F5474"
      },
      "rvas": {
        "LoD/1.07": "0x5594",
        "LoD/1.08": "0x5594",
        "LoD/1.09": "0x55B4",
        "LoD/1.09b": "0x55B4",
        "LoD/1.09d": "0x55B4",
        "LoD/1.10": "0x5474"
      },
      "sizes": {
        "LoD/1.07": 86,
        "LoD/1.08": 86,
        "LoD/1.09": 86,
        "LoD/1.09b": 86,
        "LoD/1.09d": 86,
        "LoD/1.10": 86
      },
      "signature": "void FreeErrorTableEntry(void * * pErrorEntry)",
      "calling_convention": "__cdecl",
      "comment": "Free an error table entry and unlink it from the doubly-linked error table list.\n\nAlgorithm:\n1. Free virtual memory region associated with error entry (VirtualFree at offset 0x10 with MEM_RELEASE flag 0x8000)\n2. Check if entry is the current head of global error table list (PTR_g_aErrorTable_18__dwErrorCode_6ff38b90)\n3. If head entry, update global head pointer to next entry (pNext at offset 0x4)\n4. Check if entry is the sentinel node (g_aErrorTable + 0x12 = offset 0x6ff36b70)\n5. If sentinel node, set DAT_6ff36b80 to 0xffffffff and return\n6. If regular node, unlink from doubly-linked list by updating next/prev pointers\n7. Free the error table entry structure memory using HeapFree with global heap handle\n\nParameters:\npErrorEntry: Pointer to ErrorTableEntry structure to deallocate\n\nReturns:\nvoid: No return value\n\nSpecial Cases:\nSentinel node (at 0x6ff36b70): Sets global flag DAT_6ff36b80 to 0xffffffff instead of freeing\nHead node: Updates global head pointer before unlinking from list\n\nMagic Numbers Reference:\n0x8000: MEM_RELEASE flag for VirtualFree (decimal 32768)\n0x10: Offset to virtual memory handle in ErrorTableEntry structure (decimal 16)\n0x4: Offset to pNext pointer in ErrorTableEntry structure (decimal 4)  \n0x0: Offset to pPrev pointer in ErrorTableEntry structure (decimal 0)\n0x6ff36b70: Address of sentinel error table node\n0x6ff38b90: Global pointer to error table head entry\n0x6ff36b80: Global flag modified when sentinel node is freed\n0xffffffff: Value set in global flag when sentinel freed (decimal 4294967295)\n\nError Handling:\nNo explicit error checking performed on VirtualFree or HeapFree calls\nAssumes valid ErrorTableEntry pointer passed as parameter\nRelies on linked list structure integrity for safe unlinking operations\n\nStructure Layout:\nOffset | Size | Field Name | Type | Description\n0x00   | 4    | pNext      | void* | Pointer to next error table entry\n0x04   | 4    | pPrev      | void* | Pointer to previous error table entry  \n0x08   | 4    | dwReserved1| uint  | Reserved field (purpose unknown)\n0x0C   | 4    | dwReserved2| uint  | Reserved field (purpose unknown)\n0x10   | 4    | pVirtualMem| void* | Virtual memory handle for VirtualFree",
      "name_source": "LoD/1.08",
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
    "d2mcpclient.dll_MNE_4356a93c484f": {
      "addresses": {
        "LoD/1.07": "0x6FA555EA",
        "LoD/1.08": "0x6FA555EA",
        "LoD/1.09": "0x6F9F560A",
        "LoD/1.09b": "0x6F9F560A",
        "LoD/1.09d": "0x6F9F560A",
        "LoD/1.10": "0x6F9F54CA"
      },
      "rvas": {
        "LoD/1.07": "0x55EA",
        "LoD/1.08": "0x55EA",
        "LoD/1.09": "0x560A",
        "LoD/1.09b": "0x560A",
        "LoD/1.09d": "0x560A",
        "LoD/1.10": "0x54CA"
      },
      "sizes": {
        "LoD/1.07": 194,
        "LoD/1.08": 194,
        "LoD/1.09": 194,
        "LoD/1.09b": 194,
        "LoD/1.09d": 194,
        "LoD/1.10": 194
      },
      "signature": "void FreeMemoryPoolPages(int nPageCount)",
      "calling_convention": "__cdecl",
      "comment": "Frees virtual memory pages from managed memory pools\n\nAlgorithm:\n1. Initialize pool traversal from global pool head pointer g_aErrorTable[0x12].lpszMessage\n2. Skip pools with invalid virtual memory base (ppuVar4[4] == 0xffffffff)\n3. Initialize page offset to 0x3ff000 (4MB - 4KB) and scan backwards through bitmap\n4. For each bitmap entry marked as allocated (0xf0), attempt VirtualFree\n5. Call VirtualFree with MEM_DECOMMIT (0x4000) to release 4KB page\n6. Mark bitmap slot as freed (0xffffffff) and decrement global page counter\n7. Update minimum free slot pointer if current slot is lower\n8. Decrement target page count and exit early if quota reached\n9. Continue scanning until beginning of pool (offset 0) reached\n10. Check if all bitmap entries are free (0x400 consecutive 0xffffffff entries)\n11. If pool is completely empty, call cleanup function FUN_6ff2f45e\n12. Advance to next pool in linked list and repeat until quota met\n\nParameters:\nnPageCount (int): Maximum number of 4KB pages to free from all pools\n\nReturns:\nvoid: No return value, modifies global pool state and memory allocation\n\nSpecial Cases:\n- Early exit when requested page count reached\n- Skip pools with no virtual memory allocated\n- Only update minimum free slot if current is lower than existing\n- Pool cleanup only triggered when all 1024 bitmap entries are free\n- Global page counter DAT_6ff3a058 decremented for each freed page\n\nMagic Numbers:\n0x3ff000 - Starting offset (4MB - 4KB) for backward bitmap scan\n0x1000 - Page size (4KB) for VirtualFree operations  \n0x4000 - MEM_DECOMMIT flag for VirtualFree\n0xf0 - Bitmap entry indicating allocated page\n0xffffffff - Bitmap entry indicating freed page\n0x400 - Total bitmap entries per pool (1024 slots)\n0x804 - Offset to bitmap data array (2052 bytes)\n\nStructure Layout (MemoryPoolDescriptor):\nOffset | Size | Field Name    | Type  | Description\n-------|------|---------------|-------|----------------------------------\n   0   |  4   | pHead         | void* | Head of pool list  \n   4   |  4   | pNext         | void* | Next pool in linked list\n   8   |  4   | dwReserved1   | uint  | Reserved field\n  12   |  4   | pMinFreeSlot  | void* | Pointer to lowest free slot\n  16   |  4   | pVirtualBase  | void* | Virtual memory base address\n  20   |  4   | dwReserved2   | uint  | Reserved field  \n  24   |  4   | dwPoolStatus  | uint  | Pool status flags\n  28   |  4   | dwReserved3   | uint  | Reserved field\n  32   | 8192 | aBitmapData   |uint[] | Page allocation bitmap (1024 entries)\n\nFlag Bits:\n0xf0 - Page allocated and committed\n0xffffffff - Page freed and available",
      "name_source": "LoD/1.08",
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
    "d2mcpclient.dll_MNE_d9739637e22d": {
      "addresses": {
        "LoD/1.07": "0x6FA556AC",
        "LoD/1.08": "0x6FA556AC",
        "LoD/1.09": "0x6F9F56CC",
        "LoD/1.09b": "0x6F9F56CC",
        "LoD/1.09d": "0x6F9F56CC",
        "LoD/1.10": "0x6F9F558C"
      },
      "rvas": {
        "LoD/1.07": "0x56AC",
        "LoD/1.08": "0x56AC",
        "LoD/1.09": "0x56CC",
        "LoD/1.09b": "0x56CC",
        "LoD/1.09d": "0x56CC",
        "LoD/1.10": "0x558C"
      },
      "sizes": {
        "LoD/1.07": 87,
        "LoD/1.08": 87,
        "LoD/1.09": 87,
        "LoD/1.09b": 87,
        "LoD/1.09d": 87,
        "LoD/1.10": 87
      },
      "signature": "int ValidateAllocationBlockAddress(byte * pAddress, ErrorTableEntry * * ppTableEntry, uint * puBaseAddress)",
      "calling_convention": "__cdecl",
      "comment": "Validate memory address within allocation block and calculate adjusted address\n\nAlgorithm:\n1. Initialize table pointer to g_aErrorTable[18] (offset 0x12 * 8 bytes)\n2. Loop through linked error table entries checking address bounds\n3. Compare address against entry's lower bound (offset 0x10) and upper bound (offset 0x14)\n4. If address outside bounds, follow next pointer (offset 0x0) to continue search\n5. Exit loop if reach sentinel value 0x6ff36b70 indicating end of table\n6. Validate 16-byte alignment by checking (address & 0xf) == 0\n7. Validate minimum offset by checking (address & 0xfff) >= 0x100\n8. Store found table entry pointer in output parameter\n9. Calculate 4KB-aligned base address using (address & 0xfffff000)\n10. Store base address in output parameter  \n11. Calculate final address: ((address - base - 0x100) >> 4) + 8 + base\n\nParameters:\npAddress (void*): Memory address to validate and process\nppTableEntry (ErrorTableEntry**): Output pointer for found error table entry\npuBaseAddress (uint*): Output pointer for calculated 4KB base address\n\nReturns:\n0: Validation failed - address not found in table, misaligned, or offset too small\nNon-zero: Calculated adjusted address based on base address and offset\n\nSpecial Cases:\n- Returns 0 if address not found in any table entry bounds\n- Returns 0 if address not 16-byte aligned (address & 0xf != 0)  \n- Returns 0 if offset within 4KB page less than 0x100 bytes\n- Handles linked list traversal with sentinel check at 0x6ff36b70\n\nMagic Numbers Reference:\n0x12 (18): Starting offset in error table array\n0xf (15): Alignment mask for 16-byte boundary check\n0xfff (4095): Page offset mask for 4KB boundary\n0x100 (256): Minimum required offset within page\n0xfffff000: 4KB page base address mask\n0x4 (4): Right shift amount for 16-byte block calculation\n0x8 (8): Base offset added to final calculation\n0x6ff36b70: Sentinel value marking end of error table list\n\nStructure Layout:\nErrorTableEntry (8 bytes):\nOffset | Size | Field Name    | Type                  | Description\n0x00   | 4    | dwErrorCode   | ErrorTableEntry*      | Next entry pointer or error code\n0x04   | 4    | lpszMessage   | char*                 | Error message string pointer\n\nAddress Bounds Check:\nOffset 0x10: Lower bound address for allocation block\nOffset 0x14: Upper bound address for allocation block",
      "name_source": "LoD/1.08",
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
    "d2mcpclient.dll_MNE_ab1eb8b21e2b": {
      "addresses": {
        "LoD/1.07": "0x6FA55703",
        "LoD/1.08": "0x6FA55703",
        "LoD/1.09": "0x6F9F5723",
        "LoD/1.09b": "0x6F9F5723",
        "LoD/1.09d": "0x6F9F5723",
        "LoD/1.10": "0x6F9F55E3"
      },
      "rvas": {
        "LoD/1.07": "0x5703",
        "LoD/1.08": "0x5703",
        "LoD/1.09": "0x5723",
        "LoD/1.09b": "0x5723",
        "LoD/1.09d": "0x5723",
        "LoD/1.10": "0x55E3"
      },
      "sizes": {
        "LoD/1.07": 69,
        "LoD/1.08": 69,
        "LoD/1.09": 69,
        "LoD/1.09b": 69,
        "LoD/1.09d": 69,
        "LoD/1.10": 69
      },
      "signature": "void UpdateMemoryPoolTracking(MemoryPool * pMemoryPool, uint dwAddress, byte * pbFlag)",
      "calling_convention": "__cdecl",
      "comment": "Updates memory pool tracking information and triggers cleanup when threshold reached.\n\nAlgorithm:\n1. Calculate pointer to tracking entry in memory pool descriptor array\n2. Add flag byte value to tracking entry allocation count  \n3. Clear the input flag byte to zero\n4. Set tracking entry status field to 0xf1 (active tracking)\n5. Check if allocation count reached threshold (0xf0 = 240 allocations)\n6. If threshold reached, increment global allocated pages counter\n7. If global counter reaches 0x20 (32 pages), trigger memory cleanup\n\nParameters:\npMemoryPool - Pointer to MemoryPool structure containing tracking arrays\ndwAddress - Virtual address used to calculate tracking entry index\npbFlag - Pointer to byte flag containing allocation count to add\n\nReturns:\nNone (void function)\n\nSpecial Cases:\nThreshold of 0xf0 (240) allocations triggers page counting mechanism\nGlobal threshold of 0x20 (32) pages triggers FreeMemoryPoolPages cleanup\nStatus value 0xf1 indicates active tracking state\n\nMagic Numbers Reference:\n0x10 - Base offset in memory pool structure for address calculations\n0x18 - Array offset in memory pool structure for tracking entries  \n0xc - Right shift count for address-to-index conversion (4096-byte pages)\n0x8 - Size of each tracking entry (8 bytes: count + status)\n0xf0 - Allocation count threshold (240 decimal)\n0xf1 - Active tracking status marker\n0x20 - Global page limit (32 decimal) before cleanup\n0x10 - Parameter passed to FreeMemoryPoolPages for cleanup\n\nStructure Layout:\nMemoryPool tracking entry (8 bytes):\nOffset | Size | Field Name | Type | Description\n+0x0   | 4    | nCount     | uint | Allocation count for this pool segment\n+0x4   | 4    | dwStatus   | uint | Status flags (0xf1 = active tracking)",
      "name_source": "LoD/1.08",
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
    "d2mcpclient.dll_MNE_de76025ed283": {
      "addresses": {
        "LoD/1.07": "0x6FA55748",
        "LoD/1.08": "0x6FA55748",
        "LoD/1.09": "0x6F9F5768",
        "LoD/1.09b": "0x6F9F5768",
        "LoD/1.09d": "0x6F9F5768",
        "LoD/1.10": "0x6F9F5628"
      },
      "rvas": {
        "LoD/1.07": "0x5748",
        "LoD/1.08": "0x5748",
        "LoD/1.09": "0x5768",
        "LoD/1.09b": "0x5768",
        "LoD/1.09d": "0x5768",
        "LoD/1.10": "0x5628"
      },
      "sizes": {
        "LoD/1.07": 520,
        "LoD/1.08": 520,
        "LoD/1.09": 520,
        "LoD/1.09b": 520,
        "LoD/1.09d": 520,
        "LoD/1.10": 520
      },
      "signature": "int * AllocateMemoryFromPool(uint dwBytesToAllocate)",
      "calling_convention": "__cdecl",
      "comment": "Allocates memory from a managed pool using a linked list of memory allocators with fallback to VirtualAlloc.\n\nAlgorithm:\n\n1. Traverse linked list of memory allocators starting from g_pErrorTableHead\n2. For each active allocator (piVar8[4] != -1):\n   - Search active memory blocks (offset 0x8 to 0x2018) for suitable free space\n   - Check if requested size fits within block's available range  \n   - Call FUN_6ff2f81a to attempt allocation from block\n   - If successful, update block metadata and return pointer\n   - If failed, update block end marker and continue search\n3. Search lower priority blocks (offset 0x18 to end) using same allocation logic\n4. If no space found in current allocator, advance to next allocator in list\n5. If all existing allocators exhausted, find empty allocator slot in g_aErrorTable\n6. For empty allocator: count consecutive free pages (up to 0x10 maximum)\n7. Call VirtualAlloc to allocate physical memory for counted pages (page_count << 0xc bytes)\n8. Call _memset to zero-initialize allocated memory \n9. Initialize each page with 0xF0 byte free space and link metadata\n10. Set up allocator tracking structures and update global head pointer\n11. Extract requested allocation from first initialized page\n12. Return pointer to allocated memory + 0x100 offset, or NULL on failure\n\nParameters:\n\ndwBytesToAllocate (uint) - Number of bytes to allocate from memory pool\n\nReturns:\n\nSUCCESS: Pointer to allocated memory block (base + 0x100 offset)\nFAILURE: NULL (0x0) if allocation fails or VirtualAlloc fails\n\nSpecial Cases:\n\n- If allocator reaches end of list (circular check), searches for empty slots\n- VirtualAlloc failure returns NULL immediately  \n- Memory is zero-initialized after VirtualAlloc\n- Each page provides 0xF0 (240) bytes of usable space\n- Allocator metadata uses 0x10 bytes overhead per page\n- Maximum consecutive pages per allocation: 0x10 (16 pages = 64KB)\n\nMagic Numbers Reference:\n\n0x100 (256) - Return pointer offset from memory block base\n0xF0 (240) - Usable bytes per memory page after metadata overhead  \n0xF1 (241) - Initial end marker for free space tracking\n0x1000 (4096) - Virtual memory page size for VirtualAlloc\n0x400 (1024) - Memory block stride in int* units (0x400 * 4 = 4096 bytes)\n0x806 (2054) - End boundary for active block search range  \n0x403 (1027) - Maximum entries in error table array\n0x18 (24) - Allocator metadata overhead size\n0x2018 (8216) - Upper boundary offset for active block range\n0x10 (16) - Maximum consecutive pages for single allocation\n0x3d (61) - Byte offset marker for page initialization flag (0xff)\n\nError Handling:\n\n- VirtualAlloc failure: Returns NULL without cleanup\n- FUN_6ff2f81a allocation failure: Updates block metadata and continues search  \n- Empty allocator list: Calls InitializeMemoryAllocator() for bootstrap\n- Invalid allocator state: Skips to next allocator in linked list\n- Circular list detection: Breaks loop and searches for empty slots\n\nStructure Layout:\n\nErrorTableEntry (8 bytes per entry):\nOffset | Size | Field Name  | Type   | Description\n-------|------|-------------|--------|------------------------------------------\n0x00   | 4    | dwErrorCode | uint   | Error code or next pointer for linking\n0x04   | 4    | lpszMessage | char * | Message pointer or memory tracking data\n\nMemory Allocator Node Layout (accessed as int* array):\nOffset | Size | Field Name    | Type  | Description  \n-------|------|---------------|-------|------------------------------------------\n0x00   | 4    | pNext         | int * | Next allocator in linked list\n0x04   | 4    | pReserved     | int * | Reserved/unused field\n0x08   | 4    | pMemoryStart  | int * | Pointer to first memory block entry\n0x0C   | 4    | pMemoryEnd    | int * | Pointer to end of memory block array  \n0x10   | 4    | pVirtualBase  | int * | Base address from VirtualAlloc\n0x14   | 4    | dwReserved    | int   | Reserved/unused field",
      "name_source": "LoD/1.08",
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
    "d2mcpclient.dll_MNE_4f3543287939": {
      "addresses": {
        "LoD/1.07": "0x6FA55950",
        "LoD/1.08": "0x6FA55950",
        "LoD/1.09": "0x6F9F5970",
        "LoD/1.09b": "0x6F9F5970",
        "LoD/1.09d": "0x6F9F5970",
        "LoD/1.10": "0x6F9F5830"
      },
      "rvas": {
        "LoD/1.07": "0x5950",
        "LoD/1.08": "0x5950",
        "LoD/1.09": "0x5970",
        "LoD/1.09b": "0x5970",
        "LoD/1.09d": "0x5970",
        "LoD/1.10": "0x5830"
      },
      "sizes": {
        "LoD/1.07": 292,
        "LoD/1.08": 292,
        "LoD/1.09": 292,
        "LoD/1.09b": 292,
        "LoD/1.09d": 292,
        "LoD/1.10": 292
      },
      "signature": "int AllocateBufferSpace(BufferManager * pBufferMgr, uint dwAvailableBytes, uint dwRequestedBytes)",
      "calling_convention": "__cdecl",
      "comment": "Allocates buffer space in managed buffer with chunk-based allocation\n\nAlgorithm:\n1. Extract buffer boundary (pBufferMgr + 0xF8) and current position \n2. Check if remaining space (pBufferMgr->dwRemaining) is sufficient for request\n3. If sufficient space available at current position, allocate directly\n4. Otherwise, scan buffer starting from current position for available chunks\n5. For each chunk, if first byte is 0, count consecutive zeros to find free space\n6. If first byte is non-zero, advance by that value (skip allocated chunk)\n7. When suitable free space found, mark first byte with marker value\n8. Update buffer manager pointers: pCurrent advances by dwRequestedBytes\n9. Calculate return value: (allocated_pointer * 16 - pBufferMgr * 15)\n\nParameters:\npBufferMgr: Pointer to BufferManager structure with allocation state\ndwAvailableBytes: Total bytes available for allocation operations\ndwRequestedBytes: Number of bytes to allocate from buffer\n\nReturns:\nint: Calculated handle/offset for allocated space, 0 on failure\n\nSpecial Cases:\n- Returns 0 if insufficient space available\n- Returns 0 if buffer boundary would be exceeded\n- Handles buffer wraparound by resetting to base pointer (offset 8)\n- Marker value placed at allocation start for tracking\n\nStructure Layout:\nOffset | Size | Field Name  | Type     | Description\n-------|------|-------------|----------|----------------------------------\n0x00   | 4    | pCurrent    | void*    | Current allocation position\n0x04   | 4    | dwRemaining | uint     | Bytes remaining at current pos\n0x08   | 4    | pBase       | void*    | Base buffer pointer for reset\n...    | 236  | padding     | byte[236]| Reserved space\n0xF8   | 4    | pEnd        | void*    | End boundary pointer",
      "name_source": "LoD/1.08",
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
    "d2mcpclient.dll_STR_f59c01a33eca": {
      "addresses": {
        "LoD/1.07": "0x6FA55A74",
        "LoD/1.08": "0x6FA55A74",
        "LoD/1.09": "0x6F9F5A94",
        "LoD/1.09b": "0x6F9F5A94",
        "LoD/1.09d": "0x6F9F5A94",
        "LoD/1.10": "0x6F9F5954"
      },
      "rvas": {
        "LoD/1.07": "0x5A74",
        "LoD/1.08": "0x5A74",
        "LoD/1.09": "0x5A94",
        "LoD/1.09b": "0x5A94",
        "LoD/1.09d": "0x5A94",
        "LoD/1.10": "0x5954"
      },
      "sizes": {
        "LoD/1.07": 137,
        "LoD/1.08": 137,
        "LoD/1.09": 137,
        "LoD/1.09b": 137,
        "LoD/1.09d": 137,
        "LoD/1.10": 137
      },
      "signature": "int ShowMessageBoxWithActiveWindow(char * lpszText, char * lpszCaption, int nType)",
      "calling_convention": "__cdecl",
      "comment": "Displays a message box using dynamic loading of user32.dll functions with active window detection.\n\nAlgorithm:\n\n1. Check if MessageBoxA function pointer is already loaded (DAT_1003ca8c)\n2. If not loaded, dynamically load user32.dll using LoadLibraryA\n3. Get function pointers for MessageBoxA, GetActiveWindow, and GetLastActivePopup\n4. Store function pointers in global variables (DAT_1003ca8c, DAT_1003ca90, DAT_1003ca94)\n5. If GetActiveWindow is available, call it to get active window handle\n6. If active window exists and GetLastActivePopup is available, get last active popup\n7. Call MessageBoxA with detected window handle and provided text, caption, and type\n8. Return the result from MessageBoxA\n\nParameters:\n\nlpszText - Pointer to null-terminated string containing message text to display\nlpszCaption - Pointer to null-terminated string containing dialog caption/title\nnType - Message box type flags controlling buttons and icon (MB_OK, MB_ICONERROR, etc.)\n\nReturns:\n\nInteger result from MessageBoxA indicating which button was pressed:\n- IDOK (1) if OK button clicked\n- IDCANCEL (2) if Cancel button clicked  \n- IDABORT (3) if Abort button clicked\n- IDRETRY (4) if Retry button clicked\n- IDIGNORE (5) if Ignore button clicked\n- IDYES (6) if Yes button clicked\n- IDNO (7) if No button clicked\n- 0 if function initialization failed\n\nSpecial Cases:\n\nIf user32.dll cannot be loaded or required functions cannot be found, returns 0.\nUses lazy loading pattern - initializes function pointers only on first call.\nWindow handle detection provides proper message box parenting for modal behavior.\n\nGlobal Variables:\n\nDAT_1003ca8c - Function pointer to MessageBoxA (FARPROC)\nDAT_1003ca90 - Function pointer to GetActiveWindow (FARPROC) \nDAT_1003ca94 - Function pointer to GetLastActivePopup (FARPROC)",
      "name_source": "LoD/1.08",
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
    "d2mcpclient.dll__strncpy": {
      "addresses": {
        "LoD/1.07": "0x6FA55B00",
        "LoD/1.08": "0x6FA55B00",
        "LoD/1.09": "0x6F9F5B20",
        "LoD/1.09b": "0x6F9F5B20",
        "LoD/1.09d": "0x6F9F5B20",
        "LoD/1.10": "0x6F9F59E0",
        "LoD/1.11": "0x6FA24640",
        "LoD/1.11b": "0x6FA24640",
        "LoD/1.12a": "0x6FA24670",
        "LoD/1.13c": "0x6FA24670",
        "LoD/1.13d": "0x6FA24980"
      },
      "rvas": {
        "LoD/1.07": "0x5B00",
        "LoD/1.08": "0x5B00",
        "LoD/1.09": "0x5B20",
        "LoD/1.09b": "0x5B20",
        "LoD/1.09d": "0x5B20",
        "LoD/1.10": "0x59E0",
        "LoD/1.11": "0x4640",
        "LoD/1.11b": "0x4640",
        "LoD/1.12a": "0x4670",
        "LoD/1.13c": "0x4670",
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
    "d2mcpclient.dll___global_unwind2": {
      "addresses": {
        "LoD/1.07": "0x6FA55C00",
        "LoD/1.08": "0x6FA55C00",
        "LoD/1.09": "0x6F9F5C20",
        "LoD/1.09b": "0x6F9F5C20",
        "LoD/1.09d": "0x6F9F5C20",
        "LoD/1.10": "0x6F9F5AE0",
        "LoD/1.11": "0x6FA228DC",
        "LoD/1.11b": "0x6FA228DC",
        "LoD/1.12a": "0x6FA228FC",
        "LoD/1.13c": "0x6FA228FC",
        "LoD/1.13d": "0x6FA22C1C"
      },
      "rvas": {
        "LoD/1.07": "0x5C00",
        "LoD/1.08": "0x5C00",
        "LoD/1.09": "0x5C20",
        "LoD/1.09b": "0x5C20",
        "LoD/1.09d": "0x5C20",
        "LoD/1.10": "0x5AE0",
        "LoD/1.11": "0x28DC",
        "LoD/1.11b": "0x28DC",
        "LoD/1.12a": "0x28FC",
        "LoD/1.13c": "0x28FC",
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
      "signature": "undefined __global_unwind2(PVOID param_1)",
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
    "d2mcpclient.dll___local_unwind2": {
      "addresses": {
        "LoD/1.07": "0x6FA55C42",
        "LoD/1.08": "0x6FA55C42",
        "LoD/1.09": "0x6F9F5C62",
        "LoD/1.09b": "0x6F9F5C62",
        "LoD/1.09d": "0x6F9F5C62",
        "LoD/1.10": "0x6F9F5B22",
        "LoD/1.11": "0x6FA2291E",
        "LoD/1.11b": "0x6FA2291E",
        "LoD/1.12a": "0x6FA2293E",
        "LoD/1.13c": "0x6FA2293E",
        "LoD/1.13d": "0x6FA22C5E"
      },
      "rvas": {
        "LoD/1.07": "0x5C42",
        "LoD/1.08": "0x5C42",
        "LoD/1.09": "0x5C62",
        "LoD/1.09b": "0x5C62",
        "LoD/1.09d": "0x5C62",
        "LoD/1.10": "0x5B22",
        "LoD/1.11": "0x291E",
        "LoD/1.11b": "0x291E",
        "LoD/1.12a": "0x293E",
        "LoD/1.13c": "0x293E",
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
      "signature": "undefined __local_unwind2(int param_1, int param_2)",
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
    "d2mcpclient.dll_MNE_ed17ad9d511f": {
      "addresses": {
        "LoD/1.07": "0x6FA55CD6",
        "LoD/1.08": "0x6FA55CD6",
        "LoD/1.09": "0x6F9F5CF6",
        "LoD/1.09b": "0x6F9F5CF6",
        "LoD/1.09d": "0x6F9F5CF6",
        "LoD/1.10": "0x6F9F5BB6",
        "LoD/1.11": "0x6FA229B2",
        "LoD/1.11b": "0x6FA229B2",
        "LoD/1.12a": "0x6FA229D2",
        "LoD/1.13c": "0x6FA229D2",
        "LoD/1.13d": "0x6FA22CF2"
      },
      "rvas": {
        "LoD/1.07": "0x5CD6",
        "LoD/1.08": "0x5CD6",
        "LoD/1.09": "0x5CF6",
        "LoD/1.09b": "0x5CF6",
        "LoD/1.09d": "0x5CF6",
        "LoD/1.10": "0x5BB6",
        "LoD/1.11": "0x29B2",
        "LoD/1.11b": "0x29B2",
        "LoD/1.12a": "0x29D2",
        "LoD/1.13c": "0x29D2",
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
      "signature": "void StoreSehContext(void)",
      "calling_convention": "__stdcall",
      "comment": "Stores exception handling context for SEH frame setup.\n\nAlgorithm:\n1. Load static exception frame structure pointer into EBX\n2. Write return address from stack [EBP+8] to frame offset +8\n3. Write exception context (EAX) to frame offset +4\n4. Write current frame pointer (EBP) to frame offset +C (12)\n5. Return with stack cleanup (RET 0x4)\n\nParameters:\n- dwExceptionContext (EAX): Exception context value to store\n\nReturns:\n- void\n\nRelated Functions:\n- Called by __local_unwind2 exception unwinding handler",
      "name_source": "LoD/1.08",
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
    "d2mcpclient.dll_MNE_89d1b6190541": {
      "addresses": {
        "LoD/1.07": "0x6FA55DB5",
        "LoD/1.08": "0x6FA55DB5",
        "LoD/1.09": "0x6F9F5DD5",
        "LoD/1.09b": "0x6F9F5DD5",
        "LoD/1.09d": "0x6F9F5DD5",
        "LoD/1.10": "0x6F9F5C95",
        "LoD/1.11": "0x6FA2188A",
        "LoD/1.11b": "0x6FA2188A",
        "LoD/1.12a": "0x6FA2188A",
        "LoD/1.13c": "0x6FA2188A",
        "LoD/1.13d": "0x6FA21BC6"
      },
      "rvas": {
        "LoD/1.07": "0x5DB5",
        "LoD/1.08": "0x5DB5",
        "LoD/1.09": "0x5DD5",
        "LoD/1.09b": "0x5DD5",
        "LoD/1.09d": "0x5DD5",
        "LoD/1.10": "0x5C95",
        "LoD/1.11": "0x188A",
        "LoD/1.11b": "0x188A",
        "LoD/1.12a": "0x188A",
        "LoD/1.13c": "0x188A",
        "LoD/1.13d": "0x1BC6"
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
      "signature": "void __seh_longjmp_unwind@4(SehFrame * pSehFrame)",
      "calling_convention": "__stdcall",
      "comment": "Performs structured exception handling longjmp stack unwinding operations.\n\nAlgorithm:\n1. Extract the target SEH frame pointer from pSehFrame->pNext (offset 0x18)\n2. Extract the target instruction offset from pSehFrame->dwTargetOffset (offset 0x1c) \n3. Call LocalUnwindTwo to perform actual stack unwinding with extracted parameters\n4. Return after unwinding completes\n\nParameters:\npSehFrame (SehFrame *): Pointer to SEH frame containing unwinding parameters\n  - Offset 0x18: pNext - Target SEH frame for unwinding\n  - Offset 0x1c: dwTargetOffset - Target instruction offset for longjmp\n\nReturns:\nvoid - Function performs unwinding and returns to caller\n\nSpecial Cases:\nThis function is a thin wrapper around LocalUnwindTwo for longjmp operations.\nCalled during structured exception handling when executing longjmp.",
      "name_source": "LoD/1.08",
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
    "d2mcpclient.dll_MNE_ee4facdaccbd": {
      "addresses": {
        "LoD/1.07": "0x6FA55DD0",
        "LoD/1.08": "0x6FA55DD0",
        "LoD/1.09": "0x6F9F5DF0",
        "LoD/1.09b": "0x6F9F5DF0",
        "LoD/1.09d": "0x6F9F5DF0",
        "LoD/1.10": "0x6F9F5CB0",
        "LoD/1.11": "0x6FA23FE7",
        "LoD/1.11b": "0x6FA23FE7",
        "LoD/1.12a": "0x6FA2401F",
        "LoD/1.13c": "0x6FA2401F",
        "LoD/1.13d": "0x6FA24327"
      },
      "rvas": {
        "LoD/1.07": "0x5DD0",
        "LoD/1.08": "0x5DD0",
        "LoD/1.09": "0x5DF0",
        "LoD/1.09b": "0x5DF0",
        "LoD/1.09d": "0x5DF0",
        "LoD/1.10": "0x5CB0",
        "LoD/1.11": "0x3FE7",
        "LoD/1.11b": "0x3FE7",
        "LoD/1.12a": "0x401F",
        "LoD/1.13c": "0x401F",
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
      "signature": "int InvokeCallbackHandler(int nParameter)",
      "calling_convention": "__cdecl",
      "comment": "Setting prototype: int InvokeCallbackHandler(int nParameter)",
      "name_source": "LoD/1.08",
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
    "d2mcpclient.dll__memset": {
      "addresses": {
        "LoD/1.07": "0x6FA55DF0",
        "LoD/1.08": "0x6FA55DF0",
        "LoD/1.09": "0x6F9F5E10",
        "LoD/1.09b": "0x6F9F5E10",
        "LoD/1.09d": "0x6F9F5E10",
        "LoD/1.10": "0x6F9F5CD0",
        "LoD/1.11": "0x6FA24010",
        "LoD/1.11b": "0x6FA24010",
        "LoD/1.12a": "0x6FA24040",
        "LoD/1.13c": "0x6FA24040",
        "LoD/1.13d": "0x6FA24350"
      },
      "rvas": {
        "LoD/1.07": "0x5DF0",
        "LoD/1.08": "0x5DF0",
        "LoD/1.09": "0x5E10",
        "LoD/1.09b": "0x5E10",
        "LoD/1.09d": "0x5E10",
        "LoD/1.10": "0x5CD0",
        "LoD/1.11": "0x4010",
        "LoD/1.11b": "0x4010",
        "LoD/1.12a": "0x4040",
        "LoD/1.13c": "0x4040",
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
    "d2mcpclient.dll_MNE_c1d05e132bc8": {
      "addresses": {
        "LoD/1.07": "0x6FA55E48",
        "LoD/1.08": "0x6FA55E48",
        "LoD/1.09": "0x6F9F5E68",
        "LoD/1.09b": "0x6F9F5E68",
        "LoD/1.09d": "0x6F9F5E68",
        "LoD/1.10": "0x6F9F5D28"
      },
      "rvas": {
        "LoD/1.07": "0x5E48",
        "LoD/1.08": "0x5E48",
        "LoD/1.09": "0x5E68",
        "LoD/1.09b": "0x5E68",
        "LoD/1.09d": "0x5E68",
        "LoD/1.10": "0x5D28"
      },
      "sizes": {
        "LoD/1.07": 511,
        "LoD/1.08": 511,
        "LoD/1.09": 511,
        "LoD/1.09b": 511,
        "LoD/1.09d": 511,
        "LoD/1.10": 511
      },
      "signature": "int LocaleMapStringWithConversion(uint dwLcid, uint dwMapFlags, char * lpszSrcStr, int nSrcLen, char * lpszDestStr, int nDestLen, uint dwCodePage, int nFlags)",
      "calling_convention": "__cdecl",
      "comment": "Performs locale-aware string mapping with automatic character encoding conversion.\n\nAlgorithm:\n1. Set up structured exception handling (SEH) frame\n2. Initialize Unicode support detection if not already done\n   a. Test LCMapStringW with empty string to detect Unicode support\n   b. If Unicode fails, test LCMapStringA for ANSI support\n   c. Set global flag (1=Unicode, 2=ANSI) based on results\n3. Validate source string length using FUN_1001fb97 if positive length\n4. Branch based on detected encoding support:\n   - If ANSI mode (flag=2): Call LCMapStringA directly and return result\n   - If Unicode mode (flag=1): Perform conversion sequence\n5. Unicode conversion sequence:\n   a. Use default code page if dwCodePage is 0\n   b. Calculate required wide character buffer size with MultiByteToWideChar\n   c. Allocate stack space for wide character conversion buffer\n   d. Convert source string from multibyte to wide character\n   e. Get required output buffer size with LCMapStringW\n   f. If LCMAP_SORTKEY flag (0x400) is set:\n      - Return required size if output buffer is NULL\n      - Validate output buffer size and perform mapping directly\n   g. If normal mapping:\n      - Allocate second stack buffer for wide character output\n      - Perform LCMapStringW mapping to wide character buffer\n      - Convert result back to multibyte using WideCharToMultiByte\n6. Clean up SEH frame and return result\n\nParameters:\ndwLcid (uint): Locale identifier for mapping operation\ndwMapFlags (uint): Mapping flags controlling case conversion and sorting\nlpszSrcStr (char *): Source string in multibyte encoding\nnSrcLen (int): Length of source string (-1 for null-terminated)\nlpszDestStr (char *): Output buffer for mapped string\nnDestLen (int): Size of output buffer in characters\ndwCodePage (uint): Code page for character conversion (0 = default)\nnFlags (int): Additional conversion flags for MultiByteToWideChar\n\nReturns:\nNumber of characters written to output buffer on success\n0 on failure (insufficient buffer, conversion error, or unsupported operation)\n\nSpecial Cases:\nIf lpszDestStr is NULL, returns required buffer size\nLCMAP_SORTKEY flag (0x400) returns sort key instead of mapped string\nAutomatic fallback from Unicode to ANSI if Unicode APIs unavailable\n\nMagic Numbers Reference:\n0x100 - LCMAP_LOWERCASE flag for case conversion test\n0x400 - LCMAP_SORTKEY flag for sort key generation\n0x220 - WC_NO_BEST_FIT_CHARS | WC_COMPOSITECHECK flags\n0x1003ca54 - Global Unicode support flag (1=Unicode, 2=ANSI)\n0x1003c8e4 - Default code page storage\n\nError Handling:\nReturns 0 for all error conditions including:\n- Unsupported locale or mapping flags\n- Insufficient output buffer space\n- Character conversion failures\n- Stack allocation failures",
      "name_source": "LoD/1.08",
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
    "d2mcpclient.dll_MNE_c365f0335b7b": {
      "addresses": {
        "LoD/1.07": "0x6FA5606C",
        "LoD/1.08": "0x6FA5606C",
        "LoD/1.09": "0x6F9F608C",
        "LoD/1.09b": "0x6F9F608C",
        "LoD/1.09d": "0x6F9F608C",
        "LoD/1.10": "0x6F9F5F4C"
      },
      "rvas": {
        "LoD/1.07": "0x606C",
        "LoD/1.08": "0x606C",
        "LoD/1.09": "0x608C",
        "LoD/1.09b": "0x608C",
        "LoD/1.09d": "0x608C",
        "LoD/1.10": "0x5F4C"
      },
      "sizes": {
        "LoD/1.07": 43,
        "LoD/1.08": 43,
        "LoD/1.09": 43,
        "LoD/1.09b": 43,
        "LoD/1.09d": 43,
        "LoD/1.10": 43
      },
      "signature": "int CalculateStringLengthWithLimit(char * lpszString, int nMaxLength)",
      "calling_convention": "__cdecl",
      "comment": "Calculate the length of a null-terminated string with maximum limit.\n\nAlgorithm:\n1. Initialize current pointer to start of string and remaining counter to max length\n2. If max length is zero, skip to step 5\n3. Loop while remaining length > 0:\n   a. Decrement remaining length counter\n   b. Check if current character is null terminator, if so break loop\n   c. Advance current pointer to next character\n4. Continue loop until null terminator found or max length reached\n5. Check if null terminator was found:\n   a. If found: return actual string length (current pointer - original pointer)\n   b. If not found: return max length parameter (string exceeds limit)\n\nParameters:\nlpszString (char *): Pointer to null-terminated string buffer to measure\nnMaxLength (int): Maximum number of characters to examine before stopping\n\nReturns:\nint: Actual string length if null terminator found within limit\n     Maximum length parameter if string exceeds specified limit\n     Zero if maximum length parameter is zero\n\nSpecial Cases:\n- Returns 0 if nMaxLength is 0 (no characters to examine)\n- Returns nMaxLength if no null terminator found within limit\n- Handles empty string (immediate null terminator) correctly by returning 0",
      "name_source": "LoD/1.08",
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
    "d2mcpclient.dll_MNE_a7046d73bbd2": {
      "addresses": {
        "LoD/1.07": "0x6FA56097",
        "LoD/1.08": "0x6FA56097",
        "LoD/1.09": "0x6F9F60B7",
        "LoD/1.09b": "0x6F9F60B7",
        "LoD/1.09d": "0x6F9F60B7",
        "LoD/1.10": "0x6F9F5F77"
      },
      "rvas": {
        "LoD/1.07": "0x6097",
        "LoD/1.08": "0x6097",
        "LoD/1.09": "0x60B7",
        "LoD/1.09b": "0x60B7",
        "LoD/1.09d": "0x60B7",
        "LoD/1.10": "0x5F77"
      },
      "sizes": {
        "LoD/1.07": 318,
        "LoD/1.08": 318,
        "LoD/1.09": 318,
        "LoD/1.09b": 318,
        "LoD/1.09d": 318,
        "LoD/1.10": 318
      },
      "signature": "BOOL GetCharacterTypeInfo(DWORD dwInfoType, LPCSTR lpszString, int nStringLength, LPWORD lpwCharType, UINT uiCodePage, LCID dwLocaleId, int nConversionFlags)",
      "calling_convention": "__cdecl",
      "comment": "Retrieves character type information for a string using either Unicode or ANSI APIs based on system capability detection.\n\nAlgorithm:\n1. Set up structured exception handling frame with stack-based exception list\n2. Initialize global character type detection state (DAT_1003ca98) on first call\n3. Test Unicode capability by calling GetStringTypeW with empty string\n4. Fall back to ANSI mode if Unicode fails by calling GetStringTypeA  \n5. Store detected capability (1=Unicode, 2=ANSI) in global state for subsequent calls\n6. Branch execution based on detected character handling mode:\n   - Unicode mode (1): Convert ANSI input to Unicode then call GetStringTypeW\n   - ANSI mode (2): Call GetStringTypeA directly with input parameters\n7. Apply default locale if codepage/locale parameters are zero\n8. Restore exception handling state and return API result\n\nParameters:\ndwInfoType - Character type flags (CT_CTYPE1, CT_CTYPE2, CT_CTYPE3)\nlpszString - Input string to analyze for character types\ncchString - Length of input string in characters, or -1 for null-terminated\nlpwCharType - Output buffer receiving character type information per character\nuiCodePage - Code page for Unicode conversion, 0 uses thread default\ndwLocaleId - Locale identifier for character analysis, 0 uses system default\ndwFlags - Conversion flags affecting MultiByteToWideChar behavior\n\nReturns:\nTRUE on successful character type analysis\nFALSE on failure (invalid parameters, conversion errors, or unsupported locale)\n\nSpecial Cases:\nMagic number 0xffffffff indicates exception handling state marker\nGlobal DAT_1003ca98 stores capability: 0=uninitialized, 1=Unicode, 2=ANSI only\nDynamic stack allocation used for Unicode conversion buffer sizing\nException handler DAT_10028758 protects against conversion failures\n\nError Handling:\nUnicode detection failure falls back to ANSI mode automatically\nZero codepage/locale parameters use system defaults (g_dwThreadLocaleCodePage, g_dwLocaleFlags)\nMultiByteToWideChar failure returns FALSE without character analysis\nStack allocation failure detected via null pointer check",
      "name_source": "LoD/1.08",
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
    "d2mcpclient.dll_MNE_b1691d6b7b8b": {
      "addresses": {
        "LoD/1.07": "0x6FA561E0",
        "LoD/1.08": "0x6FA561E0",
        "LoD/1.09": "0x6F9F6200",
        "LoD/1.09b": "0x6F9F6200",
        "LoD/1.09d": "0x6F9F6200",
        "LoD/1.10": "0x6F9F60C0",
        "LoD/1.11": "0x6FA22817",
        "LoD/1.11b": "0x6FA22817",
        "LoD/1.12a": "0x6FA22838",
        "LoD/1.13c": "0x6FA22838",
        "LoD/1.13d": "0x6FA22B57"
      },
      "rvas": {
        "LoD/1.07": "0x61E0",
        "LoD/1.08": "0x61E0",
        "LoD/1.09": "0x6200",
        "LoD/1.09b": "0x6200",
        "LoD/1.09d": "0x6200",
        "LoD/1.10": "0x60C0",
        "LoD/1.11": "0x2817",
        "LoD/1.11b": "0x2817",
        "LoD/1.12a": "0x2838",
        "LoD/1.13c": "0x2838",
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
      "signature": "DWORD * GetThreadContextFieldAt8(void)",
      "calling_convention": "__stdcall",
      "comment": "Get pointer to DWORD field at offset +8 bytes within thread context data.\n\nAlgorithm:\n1. Retrieve thread context pointer via GetOrCreateThreadContext()\n2. Calculate offset +8 bytes (2 DWORDs) from context base\n3. Return pointer to field at calculated offset\n\nParameters:\nNone\n\nReturns:\nuint * - Pointer to DWORD field at offset +8 within ThreadContext structure\n         Returns valid pointer if thread context exists\n         May return invalid pointer if context allocation failed\n\nSpecial Cases:\n- Relies on GetOrCreateThreadContext() for context availability\n- Offset +8 assumes fixed ThreadContext structure layout\n- Caller must validate returned pointer before dereferencing\n\nMagic Numbers Reference:\n0x8 (8 decimal) - Byte offset to target field within ThreadContext structure",
      "name_source": "LoD/1.08",
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
    "d2mcpclient.dll_MNE_e038b71e9908": {
      "addresses": {
        "LoD/1.07": "0x6FA561E9",
        "LoD/1.08": "0x6FA561E9",
        "LoD/1.09": "0x6F9F6209",
        "LoD/1.09b": "0x6F9F6209",
        "LoD/1.09d": "0x6F9F6209",
        "LoD/1.10": "0x6F9F60C9"
      },
      "rvas": {
        "LoD/1.07": "0x61E9",
        "LoD/1.08": "0x61E9",
        "LoD/1.09": "0x6209",
        "LoD/1.09b": "0x6209",
        "LoD/1.09d": "0x6209",
        "LoD/1.10": "0x60C9"
      },
      "sizes": {
        "LoD/1.07": 111,
        "LoD/1.08": 111,
        "LoD/1.09": 111,
        "LoD/1.09b": 111,
        "LoD/1.09d": 111,
        "LoD/1.10": 111
      },
      "signature": "uint ConvertCharacterToUpperCase(uint dwCharacterCode)",
      "calling_convention": "__cdecl",
      "comment": "Converts lowercase ASCII character to uppercase with locale-aware support.\n\nAlgorithm:\n1. Check global locale availability flag (g_dwLocaleAvailableFlag)\n2. If locale disabled, perform simple ASCII range check and conversion:\n   - Validate character is in range 'a' (0x61) to 'z' (0x7A)\n   - Convert by subtracting 0x20 to get uppercase equivalent\n3. If locale enabled, use thread-safe locale conversion:\n   - Increment critical section counter using InterlockedIncrement\n   - Check if critical section limit exceeded (g_dwCriticalSectionLimit != 0)\n   - If limit exceeded, decrement counter and enter critical section\n   - Call FUN_6ff2bc9f for locale-aware character conversion\n   - Release critical section or decrement counter based on limit state\n4. Return converted character code\n\nParameters:\ndwCharacterCode (uint): Character code to convert to uppercase\n\nReturns:\nuint: Uppercase character code if conversion successful, original code otherwise\n\nSpecial Cases:\n- Non-alphabetic characters: Returned unchanged\n- Out of ASCII range 'a'-'z': Returned unchanged when locale disabled\n- Critical section limit exceeded: Uses synchronization primitives\n\nMagic Numbers Reference:\n0x61 (97): ASCII 'a' - lowercase range start\n0x7A (122): ASCII 'z' - lowercase range end  \n0x20 (32): ASCII case difference (uppercase = lowercase - 0x20)\n0x13 (19): Critical section resource identifier\n\nError Handling:\n- Invalid character codes: Returned unchanged\n- Critical section contention: Handled via InterlockedIncrement/Decrement\n- Locale conversion failure: Falls back to original character code",
      "name_source": "LoD/1.08",
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
    "d2mcpclient.dll_MNE_5918dc16e1bf": {
      "addresses": {
        "LoD/1.07": "0x6FA56258",
        "LoD/1.08": "0x6FA56258",
        "LoD/1.09": "0x6F9F6278",
        "LoD/1.09b": "0x6F9F6278",
        "LoD/1.09d": "0x6F9F6278",
        "LoD/1.10": "0x6F9F6138"
      },
      "rvas": {
        "LoD/1.07": "0x6258",
        "LoD/1.08": "0x6258",
        "LoD/1.09": "0x6278",
        "LoD/1.09b": "0x6278",
        "LoD/1.09d": "0x6278",
        "LoD/1.10": "0x6138"
      },
      "sizes": {
        "LoD/1.07": 204,
        "LoD/1.08": 204,
        "LoD/1.09": 204,
        "LoD/1.09b": 204,
        "LoD/1.09d": 204,
        "LoD/1.10": 204
      },
      "signature": "dword ConvertCharacterToUpperCaseWithLocale(void * this, uint param_1)",
      "calling_convention": "__thiscall",
      "comment": "Converts a character to uppercase with locale-aware processing support\n\nAlgorithm:\n1. Initialize result with input character code\n2. Check if locale processing is available via g_dwLocaleAvailableFlag\n3. If locale unavailable, perform simple ASCII conversion (a-z to A-Z range 0x61-0x7A to 0x41-0x5A)\n4. If locale available, validate character is within single-byte range (< 0x100)\n5. Check character attribute flags using g_pCharacterAttributeTable or FUN_6ff2c474\n6. Return original character if no case conversion attribute (flag 0x02) found\n7. Determine byte length based on character attribute table high-byte entry (0x80 flag)\n8. Set up character buffer for conversion: single-byte (1) or double-byte (2) mode\n9. Call FUN_6ff2da18 (Windows LCMapStringA/W equivalent) for locale-specific conversion\n10. Extract converted result from buffer: single-byte (0xFF mask) or double-byte (0xFFFF mask)\n\nParameters:\npLocaleContext: Locale context pointer for character processing operations\ndwCharacterCode: Input character code to convert to uppercase\n\nReturns:\nConverted uppercase character code, or original character if no conversion applicable\n\nSpecial Cases:\nSimple ASCII conversion when locale unavailable: subtracts 0x20 from lowercase letters\nMulti-byte character handling via byte reordering and CONCAT operations\nFlag 0x02 in attribute table indicates case-convertible character\nFlag 0x80 in high-byte table indicates double-byte character sequence\n\nMagic Numbers Reference:\n0x60: ASCII '`' character, lower bound check for lowercase range\n0x7B: ASCII '{' character, upper bound check for lowercase range  \n0x20: ASCII offset between lowercase and uppercase letters\n0x100: Single-byte character range limit\n0x02: Character attribute flag for case conversion capability\n0x80: High-byte attribute flag indicating double-byte character\n0x200: LCMapString conversion flag (LCMAP_UPPERCASE)\n0xFF: Single-byte character mask\n0xFFFF: Double-byte character mask",
      "name_source": "LoD/1.08",
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
    "d2mcpclient.dll_MNE_d858691b25ff": {
      "addresses": {
        "LoD/1.07": "0x6FA56324",
        "LoD/1.08": "0x6FA56324",
        "LoD/1.09": "0x6F9F6344",
        "LoD/1.09b": "0x6F9F6344",
        "LoD/1.09d": "0x6F9F6344",
        "LoD/1.10": "0x6F9F6204"
      },
      "rvas": {
        "LoD/1.07": "0x6324",
        "LoD/1.08": "0x6324",
        "LoD/1.09": "0x6344",
        "LoD/1.09b": "0x6344",
        "LoD/1.09d": "0x6344",
        "LoD/1.10": "0x6204"
      },
      "sizes": {
        "LoD/1.07": 117,
        "LoD/1.08": 117,
        "LoD/1.09": 117,
        "LoD/1.09b": 117,
        "LoD/1.09d": 117,
        "LoD/1.10": 117
      },
      "signature": "uint GetCharacterProperties(void * this, int nCharCode, uint dwTypeMask)",
      "calling_convention": "__thiscall",
      "comment": "Setting prototype: uint GetCharacterProperties(void * pLocaleData, int nCharCode, uint dwPropertyMask)",
      "name_source": "LoD/1.08",
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
    "d2mcpclient.dll_MNE_30f0fd08cad9": {
      "addresses": {
        "LoD/1.07": "0x6FA56770",
        "LoD/1.08": "0x6FA56770",
        "LoD/1.09": "0x6F9F6790",
        "LoD/1.09b": "0x6F9F6790",
        "LoD/1.09d": "0x6F9F6790",
        "LoD/1.10": "0x6F9F6650"
      },
      "rvas": {
        "LoD/1.07": "0x6770",
        "LoD/1.08": "0x6770",
        "LoD/1.09": "0x6790",
        "LoD/1.09b": "0x6790",
        "LoD/1.09d": "0x6790",
        "LoD/1.10": "0x6650"
      },
      "sizes": {
        "LoD/1.07": 62,
        "LoD/1.08": 62,
        "LoD/1.09": 62,
        "LoD/1.09b": 62,
        "LoD/1.09d": 62,
        "LoD/1.10": 62
      },
      "signature": "int CountCharsUntilFilterMatch(byte * pbInput, byte * pbFilterChars)",
      "calling_convention": "__cdecl",
      "comment": "Counts characters in input string until encountering a character present in the filter string.\n\nAlgorithm:\n1. Initialize 256-bit character bitmap (32 bytes) to zero on stack\n2. Build bitmap from filter string: for each character, set corresponding bit using BTS instruction\n3. Initialize character counter to -1\n4. Loop through input string:\n   a. Increment counter\n   b. Read current character from input\n   c. If character is null terminator, return counter (end of string reached)\n   d. Test if character bit is set in bitmap using BT instruction\n   e. If bit is clear (character not in filter), continue loop\n   f. If bit is set (character matches filter), return counter\n\nParameters:\npbInput (byte *): Input string to scan for characters\npbFilterChars (byte *): String containing characters to filter against\n\nReturns:\nint: Number of characters processed before encountering a filtered character\n     Returns total string length if no filtered characters found\n\nSpecial Cases:\nEmpty input string: Returns 0\nEmpty filter string: Returns length of entire input string (no characters filtered)\nNull terminator handling: Proper termination on null bytes\n\nMagic Numbers Reference:\n0x01: Bit mask for setting individual bits in bitmap (1 << (char & 7))\n0x20: Stack space allocated for 32-byte character bitmap (256 bits)\n0x07: Bit position mask (char & 7) for bit operations within byte\n0x03: Right shift count (char >> 3) to convert character to byte index\n\nAlgorithm Implementation:\nBitmap indexing: abCharBitmap[char >> 3] accesses byte containing char's bit\nBit positioning: (char & 7) gets bit position (0-7) within that byte\nBit setting: Uses BTS (bit test and set) for atomic bit setting\nBit testing: Uses BT (bit test) for efficient character lookup",
      "name_source": "LoD/1.08",
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
    "d2mcpclient.dll_MNE_0eb6c316488d": {
      "addresses": {
        "LoD/1.07": "0x6FA567B0",
        "LoD/1.08": "0x6FA567B0",
        "LoD/1.09": "0x6F9F67D0",
        "LoD/1.09b": "0x6F9F67D0",
        "LoD/1.09d": "0x6F9F67D0",
        "LoD/1.10": "0x6F9F6690"
      },
      "rvas": {
        "LoD/1.07": "0x67B0",
        "LoD/1.08": "0x67B0",
        "LoD/1.09": "0x67D0",
        "LoD/1.09b": "0x67D0",
        "LoD/1.09d": "0x67D0",
        "LoD/1.10": "0x6690"
      },
      "sizes": {
        "LoD/1.07": 58,
        "LoD/1.08": 58,
        "LoD/1.09": 58,
        "LoD/1.09b": 58,
        "LoD/1.09d": 58,
        "LoD/1.10": 58
      },
      "signature": "byte * FindFirstCharInSet(byte * pbString, byte * pbCharSet)",
      "calling_convention": "__cdecl",
      "comment": "Find the first character in a string that exists within a character set using bit vector lookup.\n\nAlgorithm:\n\n1. Initialize 32-byte (256-bit) lookup table on stack (abStack_28[32])\n2. Clear all 256 bits to zero by pushing 8 zero dwords on stack\n3. Build character set bit vector from pbCharSet:\n   - Read each character from character set string\n   - Calculate bit position: byte_index = char >> 3, bit_offset = char & 7\n   - Set corresponding bit: abStack_28[byte_index] |= (1 << bit_offset)\n4. Search pbString for first character in the character set:\n   - Read each character from input string\n   - Test bit in lookup table: (abStack_28[char >> 3] >> (char & 7)) & 1\n   - If bit is set, character exists in set - return pointer to character\n   - If bit is clear, continue to next character\n5. Return null pointer if no matching character found\n\nParameters:\n\npbCharSet (byte *): Null-terminated string defining the character set to search for\npbString (byte *): Null-terminated input string to search within\n\nReturns:\n\nSuccess: Pointer to first character in pbString that exists in pbCharSet\nFailure: null pointer (cast to byte *) if no character from set found in string\n\nSpecial Cases:\n\nEmpty character set (pbCharSet[0] == 0): Returns null immediately since no characters to match\nEmpty input string (pbString[0] == 0): Returns null immediately since no characters to search\nCharacter 0x00 in character set: Will terminate character set scan early, excluding null from set\n\nMagic Numbers Reference:\n\n0x20 (32 decimal): Stack allocation for 256-bit lookup table (32 bytes \u00d7 8 bits = 256 bits)\n>> 3 operation: Division by 8 to convert character value to byte index in lookup table\n& 7 operation: Modulo 8 to get bit position within the byte (0-7)\n0x01: Bit mask for setting individual bits in lookup table",
      "name_source": "LoD/1.08",
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
    "d2mcpclient.dll_MNE_8c1ef08c1332": {
      "addresses": {
        "LoD/1.07": "0x6FA567F0",
        "LoD/1.08": "0x6FA567F0",
        "LoD/1.09": "0x6F9F6810",
        "LoD/1.09b": "0x6F9F6810",
        "LoD/1.09d": "0x6F9F6810",
        "LoD/1.10": "0x6F9F66D0"
      },
      "rvas": {
        "LoD/1.07": "0x67F0",
        "LoD/1.08": "0x67F0",
        "LoD/1.09": "0x6810",
        "LoD/1.09b": "0x6810",
        "LoD/1.09d": "0x6810",
        "LoD/1.10": "0x66D0"
      },
      "sizes": {
        "LoD/1.07": 208,
        "LoD/1.08": 208,
        "LoD/1.09": 208,
        "LoD/1.09b": 208,
        "LoD/1.09d": 208,
        "LoD/1.10": 208
      },
      "signature": "uint CompareStringsIgnoreCase(void * this, byte * param_1, byte * param_2)",
      "calling_convention": "__thiscall",
      "comment": "Performs case-insensitive string comparison with optional locale support\n\nAlgorithm:\n1. Load saved critical section counter value for potential restoration\n2. Check if locale data is available (DAT_6ff39f20 == 0 for simple mode)\n3. Simple mode (no locale): Compare characters directly with ASCII case conversion\n   - Read characters from both strings until difference found or null terminator\n   - Convert to lowercase using ASCII transformation: char + 0xbf + conditional 0x20 + 0x41\n   - Return comparison result: -1 if string1 < string2, 0 if equal, 1 if string1 > string2\n4. Locale mode: Thread-safe comparison with locale-specific character conversion\n   - Increment critical section counter with atomic operation\n   - Check critical section depth limit (DAT_6ff3b544)\n   - If depth exceeded, restore counter and call error handler FUN_6ff2c3fe(0x13)\n   - Compare characters using locale conversion function FUN_6ff2bdda\n   - Decrement critical section counter or call cleanup FUN_6ff2c45f(0x13)\n5. Return normalized comparison result as unsigned integer\n\nParameters:\nthis (pLocaleContext): Locale context object for character conversion operations\nlpszString1: First null-terminated string to compare\nlpszString2: Second null-terminated string to compare\n\nReturns:\n0x00000000: Strings are equal (case-insensitive)\n0x00000001: First string is lexically greater than second string\n0xFFFFFFFF: First string is lexically less than second string\n\nSpecial Cases:\n- Empty strings (immediate null terminator) return 0x00000000\n- Null pointer parameters cause undefined behavior\n- Critical section overflow triggers error handler and may modify comparison behavior\n\nMagic Numbers:\n0xbf: ASCII case conversion offset (-65 decimal)\n0x1a: Check for alphabetic character range (26 decimal) \n0x20: Space character offset for lowercase conversion (32 decimal)\n0x41: ASCII 'A' character base (65 decimal)\n0x13: Error code passed to critical section handlers\n0xff: Initial comparison state marker (255 decimal)\n\nError Handling:\n- Critical section depth limit exceeded: Call FUN_6ff2c3fe(0x13) and restore counter\n- Normal exit from critical section: Call FUN_6ff2c45f(0x13) for cleanup\n- Locale conversion errors are handled by FUN_6ff2bdda callee\n\nGlobal Dependencies:\n_DAT_6ff3b548: Critical section entry counter (thread synchronization)\nDAT_6ff39f20: Locale availability flag (0 = simple mode, non-zero = locale mode)\nDAT_6ff3b544: Critical section depth limit threshold",
      "name_source": "LoD/1.08",
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
    "d2mcpclient.dll_MNE_662566ebcde3": {
      "addresses": {
        "LoD/1.07": "0x6FA568C0",
        "LoD/1.08": "0x6FA568C0",
        "LoD/1.09": "0x6F9F68E0",
        "LoD/1.09b": "0x6F9F68E0",
        "LoD/1.09d": "0x6F9F68E0",
        "LoD/1.10": "0x6F9F67A0"
      },
      "rvas": {
        "LoD/1.07": "0x68C0",
        "LoD/1.08": "0x68C0",
        "LoD/1.09": "0x68E0",
        "LoD/1.09b": "0x68E0",
        "LoD/1.09d": "0x68E0",
        "LoD/1.10": "0x67A0"
      },
      "sizes": {
        "LoD/1.07": 257,
        "LoD/1.08": 257,
        "LoD/1.09": 257,
        "LoD/1.09b": 257,
        "LoD/1.09d": 257,
        "LoD/1.10": 257
      },
      "signature": "int CompareStringsWithLocale(byte * pbString1, char * szString2, uint dwMaxLength)",
      "calling_convention": "__cdecl",
      "comment": "Compares two strings with optional locale-aware processing and case handling.\n\nAlgorithm:\n1. Validate that dwMaxLength is non-zero, return 0 if zero\n2. Check global locale availability flag (g_dwLocaleAvailableFlag)\n3a. If locale unavailable (flag == 0):\n    - Perform simple byte-by-byte comparison\n    - Apply ASCII case conversion (0x41-0x5A -> 0x61-0x7A) for uppercase letters\n    - Compare converted characters until null terminator or length exceeded\n    - Return comparison result: -1 (less), 0 (equal), 1 (greater)\n3b. If locale available (flag != 0):\n    - Enter critical section with thread-safe counter increment\n    - Check critical section limit and call error handler if exceeded\n    - Perform locale-aware character comparison using FUN_6ff2bdda helper\n    - Process characters through locale transformation before comparison\n    - Exit critical section when complete or call cleanup handler\n4. Return comparison result as signed integer\n\nParameters:\npbString1 (byte*): First string to compare, treated as byte array for case conversion\nszString2 (char*): Second string to compare, null-terminated character string\ndwMaxLength (uint): Maximum number of characters to compare, prevents buffer overrun\n\nReturns:\n0: Strings are equal within specified length\n-1 (0xFFFFFFFF): First string is lexicographically less than second\n1: First string is lexicographically greater than second\n\nSpecial Cases:\nCritical section handling prevents race conditions in multi-threaded locale operations\nCase conversion limited to ASCII range (0x41-0x5A) for performance\nLocale-aware path delegates character mapping to FUN_6ff2bdda helper function\n\nMagic Numbers Reference:\n0x40 (64): ASCII boundary before uppercase letters\n0x5B (91): ASCII boundary after uppercase letters  \n0x20 (32): ASCII case conversion offset (upper to lower)\n0x13 (19): Error code for critical section limit exceeded",
      "name_source": "LoD/1.08",
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
    "d2mcpclient.dll_MNE_cc0e19248bdb": {
      "addresses": {
        "LoD/1.07": "0x6FA56AB5",
        "LoD/1.08": "0x6FA56AB5",
        "LoD/1.09": "0x6F9F6AD5",
        "LoD/1.09b": "0x6F9F6AD5",
        "LoD/1.09d": "0x6F9F6AD5",
        "LoD/1.10": "0x6F9F6995"
      },
      "rvas": {
        "LoD/1.07": "0x6AB5",
        "LoD/1.08": "0x6AB5",
        "LoD/1.09": "0x6AD5",
        "LoD/1.09b": "0x6AD5",
        "LoD/1.09d": "0x6AD5",
        "LoD/1.10": "0x6995"
      },
      "sizes": {
        "LoD/1.07": 203,
        "LoD/1.08": 203,
        "LoD/1.09": 203,
        "LoD/1.09b": 203,
        "LoD/1.09d": 203,
        "LoD/1.10": 203
      },
      "signature": "uint ConvertCharacterToLowerCase(void * this, uint param_1)",
      "calling_convention": "__thiscall",
      "comment": "Setting prototype: uint ConvertCharacterToLowerCase(void* pLocaleContext, uint dwCharacterCode)",
      "name_source": "LoD/1.08",
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
    "d2mcpclient.dll_RtlUnwind": {
      "addresses": {
        "LoD/1.07": "0x6FA56BB4",
        "LoD/1.08": "0x6FA56BB4",
        "LoD/1.09": "0x6F9F6BD4",
        "LoD/1.09b": "0x6F9F6BD4",
        "LoD/1.09d": "0x6F9F6BD4",
        "LoD/1.10": "0x6F9F6A94",
        "LoD/1.11": "0x6FA25D5E",
        "LoD/1.11b": "0x6FA25D5E",
        "LoD/1.12a": "0x6FA25DCE",
        "LoD/1.13c": "0x6FA25DCE",
        "LoD/1.13d": "0x6FA25D5E"
      },
      "rvas": {
        "LoD/1.07": "0x6BB4",
        "LoD/1.08": "0x6BB4",
        "LoD/1.09": "0x6BD4",
        "LoD/1.09b": "0x6BD4",
        "LoD/1.09d": "0x6BD4",
        "LoD/1.10": "0x6A94",
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
    "d2mcpclient.dll_ValidateEntityOperationAlwaysT": {
      "addresses": {
        "LoD/1.08": "0x6FA51010",
        "LoD/1.09": "0x6F9F1010",
        "LoD/1.09b": "0x6F9F1010",
        "LoD/1.09d": "0x6F9F1010",
        "LoD/1.10": "0x6F9F1010",
        "LoD/1.11": "0x6FA27580",
        "LoD/1.11b": "0x6FA26040",
        "LoD/1.12a": "0x6FA269F0",
        "LoD/1.13c": "0x6FA260A0",
        "LoD/1.13d": "0x6FA27690"
      },
      "rvas": {
        "LoD/1.08": "0x1010",
        "LoD/1.09": "0x1010",
        "LoD/1.09b": "0x1010",
        "LoD/1.09d": "0x1010",
        "LoD/1.10": "0x1010",
        "LoD/1.11": "0x7580",
        "LoD/1.11b": "0x6040",
        "LoD/1.12a": "0x69F0",
        "LoD/1.13c": "0x60A0",
        "LoD/1.13d": "0x7690"
      },
      "sizes": {
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
      "name": "ValidateEntityOperationAlwaysTrue",
      "signature": "int ValidateEntityOperationAlwaysTrue(void)",
      "calling_convention": "__stdcall",
      "comment": "Validation stub that always returns TRUE (success).\n\nClassification: Leaf function / Validation stub\n\nAlgorithm:\n1. Move constant 1 (TRUE) into EAX\n2. Return immediately\n\nParameters:\n- None (void)\n\nReturns:\n- int: Always returns 1 (TRUE) indicating validation passed\n\nUsage Context:\n- Referenced from g_aValidateEntityOperations function pointer table at 0x6fba69c0\n- Part of entity validation dispatch system\n- Used as placeholder validation for operations that require no actual validation\n- Paired with FUN_6fae9c80 (missile firing operation) in the operation table\n\nCross-References:\n- DATA xref from 0x6fba69e8 (g_aValidateEntityOperations + 0x28)\n\nNote: This is a stub function - validation always succeeds, allowing the\nassociated operation to proceed unconditionally.",
      "name_source": "LoD/1.08",
      "method": "MNE",
      "index": "MNE:7b4de9f0cf357b113d12e0c7e214792b",
      "basic_block_counts": {
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
        "LoD/1.08": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.09": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.09b": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.09d": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.10": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.11": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.11b": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.12a": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.13c": "7b4de9f0cf357b113d12e0c7e214792b",
        "LoD/1.13d": "7b4de9f0cf357b113d12e0c7e214792b"
      }
    },
    "d2mcpclient.dll_MNE_499cef981783": {
      "addresses": {
        "LoD/1.08": "0x6FA51020",
        "LoD/1.09": "0x6F9F1020",
        "LoD/1.09b": "0x6F9F1020",
        "LoD/1.09d": "0x6F9F1020",
        "LoD/1.10": "0x6F9F1020"
      },
      "rvas": {
        "LoD/1.08": "0x1020",
        "LoD/1.09": "0x1020",
        "LoD/1.09b": "0x1020",
        "LoD/1.09d": "0x1020",
        "LoD/1.10": "0x1020"
      },
      "sizes": {
        "LoD/1.08": 28,
        "LoD/1.09": 28,
        "LoD/1.09b": 28,
        "LoD/1.09d": 28,
        "LoD/1.10": 28
      },
      "name_source": "LoD/1.08",
      "method": "MNE",
      "index": "MNE:499cef981783ef8f6d9af893c3d08f84",
      "callees": {
        "LoD/1.08": [
          "Ordinal_10047"
        ],
        "LoD/1.09": [
          "Ordinal_10047"
        ],
        "LoD/1.09b": [
          "Ordinal_10047"
        ],
        "LoD/1.09d": [
          "Ordinal_10047"
        ],
        "LoD/1.10": [
          "Ordinal_10047"
        ]
      },
      "basic_block_counts": {
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1
      },
      "loop_counts": {
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.08": "499cef981783ef8f6d9af893c3d08f84",
        "LoD/1.09": "499cef981783ef8f6d9af893c3d08f84",
        "LoD/1.09b": "499cef981783ef8f6d9af893c3d08f84",
        "LoD/1.09d": "499cef981783ef8f6d9af893c3d08f84",
        "LoD/1.10": "499cef981783ef8f6d9af893c3d08f84"
      }
    },
    "d2mcpclient.dll_API_4fcbd90bf10b": {
      "addresses": {
        "LoD/1.08": "0x6FA51040",
        "LoD/1.09": "0x6F9F1040",
        "LoD/1.09b": "0x6F9F1040",
        "LoD/1.09d": "0x6F9F1040",
        "LoD/1.10": "0x6F9F13D0"
      },
      "rvas": {
        "LoD/1.08": "0x1040",
        "LoD/1.09": "0x1040",
        "LoD/1.09b": "0x1040",
        "LoD/1.09d": "0x1040",
        "LoD/1.10": "0x13D0"
      },
      "sizes": {
        "LoD/1.08": 22,
        "LoD/1.09": 22,
        "LoD/1.09b": 22,
        "LoD/1.09d": 22,
        "LoD/1.10": 22
      },
      "name_source": "LoD/1.08",
      "method": "API",
      "index": "API:4fcbd90bf10bd2ab26bfa04f1a8f03a4",
      "callees": {
        "LoD/1.08": [
          "Ordinal_10047",
          "SetErrorHandlingDisabled"
        ],
        "LoD/1.09": [
          "Ordinal_10047",
          "SetErrorHandlingDisabled"
        ],
        "LoD/1.09b": [
          "Ordinal_10047",
          "SetErrorHandlingDisabled"
        ],
        "LoD/1.09d": [
          "Ordinal_10047",
          "SetErrorHandlingDisabled"
        ],
        "LoD/1.10": [
          "Ordinal_10047",
          "SetErrorHandlingDisabled"
        ]
      },
      "basic_block_counts": {
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1
      },
      "loop_counts": {
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.08": "f32811193b2d3afd67fe60449b44f48d",
        "LoD/1.09": "f32811193b2d3afd67fe60449b44f48d",
        "LoD/1.09b": "f32811193b2d3afd67fe60449b44f48d",
        "LoD/1.09d": "f32811193b2d3afd67fe60449b44f48d",
        "LoD/1.10": "f32811193b2d3afd67fe60449b44f48d"
      }
    },
    "d2mcpclient.dll_API_4fcbd90bf10b_1060": {
      "addresses": {
        "LoD/1.08": "0x6FA51060",
        "LoD/1.09": "0x6F9F1060",
        "LoD/1.09b": "0x6F9F1060",
        "LoD/1.09d": "0x6F9F1060",
        "LoD/1.10": "0x6F9F1040"
      },
      "rvas": {
        "LoD/1.08": "0x1060",
        "LoD/1.09": "0x1060",
        "LoD/1.09b": "0x1060",
        "LoD/1.09d": "0x1060",
        "LoD/1.10": "0x1040"
      },
      "sizes": {
        "LoD/1.08": 22,
        "LoD/1.09": 22,
        "LoD/1.09b": 22,
        "LoD/1.09d": 22,
        "LoD/1.10": 22
      },
      "name_source": "LoD/1.08",
      "method": "API",
      "index": "API:4fcbd90bf10bd2ab26bfa04f1a8f03a4",
      "callees": {
        "LoD/1.08": [
          "Ordinal_10047",
          "SetErrorHandlingDisabled"
        ],
        "LoD/1.09": [
          "Ordinal_10047",
          "SetErrorHandlingDisabled"
        ],
        "LoD/1.09b": [
          "Ordinal_10047",
          "SetErrorHandlingDisabled"
        ],
        "LoD/1.09d": [
          "Ordinal_10047",
          "SetErrorHandlingDisabled"
        ],
        "LoD/1.10": [
          "Ordinal_10047",
          "SetErrorHandlingDisabled"
        ]
      },
      "basic_block_counts": {
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1
      },
      "loop_counts": {
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.08": "f32811193b2d3afd67fe60449b44f48d",
        "LoD/1.09": "f32811193b2d3afd67fe60449b44f48d",
        "LoD/1.09b": "f32811193b2d3afd67fe60449b44f48d",
        "LoD/1.09d": "f32811193b2d3afd67fe60449b44f48d",
        "LoD/1.10": "f32811193b2d3afd67fe60449b44f48d"
      }
    },
    "d2mcpclient.dll_MNE_52c1fd74bf52": {
      "addresses": {
        "LoD/1.08": "0x6FA51080",
        "LoD/1.09": "0x6F9F1080",
        "LoD/1.09b": "0x6F9F1080",
        "LoD/1.09d": "0x6F9F1080",
        "LoD/1.10": "0x6F9F1080"
      },
      "rvas": {
        "LoD/1.08": "0x1080",
        "LoD/1.09": "0x1080",
        "LoD/1.09b": "0x1080",
        "LoD/1.09d": "0x1080",
        "LoD/1.10": "0x1080"
      },
      "sizes": {
        "LoD/1.08": 53,
        "LoD/1.09": 53,
        "LoD/1.09b": 53,
        "LoD/1.09d": 53,
        "LoD/1.10": 53
      },
      "name_source": "LoD/1.08",
      "method": "MNE",
      "index": "MNE:52c1fd74bf5286f0a00443d23b376ba5",
      "callees": {
        "LoD/1.08": [
          "Ordinal_10047"
        ],
        "LoD/1.09": [
          "Ordinal_10047"
        ],
        "LoD/1.09b": [
          "Ordinal_10047"
        ],
        "LoD/1.09d": [
          "Ordinal_10047"
        ],
        "LoD/1.10": [
          "Ordinal_10047"
        ]
      },
      "basic_block_counts": {
        "LoD/1.08": 3,
        "LoD/1.09": 3,
        "LoD/1.09b": 3,
        "LoD/1.09d": 3,
        "LoD/1.10": 3
      },
      "loop_counts": {
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.08": "52c1fd74bf5286f0a00443d23b376ba5",
        "LoD/1.09": "52c1fd74bf5286f0a00443d23b376ba5",
        "LoD/1.09b": "52c1fd74bf5286f0a00443d23b376ba5",
        "LoD/1.09d": "52c1fd74bf5286f0a00443d23b376ba5",
        "LoD/1.10": "52c1fd74bf5286f0a00443d23b376ba5"
      }
    },
    "d2mcpclient.dll_API_b8393bcbef34": {
      "addresses": {
        "LoD/1.08": "0x6FA51140",
        "LoD/1.09": "0x6F9F1140",
        "LoD/1.09b": "0x6F9F1140",
        "LoD/1.09d": "0x6F9F1140",
        "LoD/1.10": "0x6F9F1F20"
      },
      "rvas": {
        "LoD/1.08": "0x1140",
        "LoD/1.09": "0x1140",
        "LoD/1.09b": "0x1140",
        "LoD/1.09d": "0x1140",
        "LoD/1.10": "0x1F20"
      },
      "sizes": {
        "LoD/1.08": 245,
        "LoD/1.09": 245,
        "LoD/1.09b": 245,
        "LoD/1.09d": 245,
        "LoD/1.10": 245
      },
      "name_source": "LoD/1.08",
      "method": "API",
      "index": "API:b8393bcbef349c7d3b02776e2127364a",
      "callees": {
        "LoD/1.08": [
          "Ordinal_10047",
          "Ordinal_10047"
        ],
        "LoD/1.09": [
          "Ordinal_10047",
          "Ordinal_10047"
        ],
        "LoD/1.09b": [
          "Ordinal_10047",
          "Ordinal_10047"
        ],
        "LoD/1.09d": [
          "Ordinal_10047",
          "Ordinal_10047"
        ],
        "LoD/1.10": [
          "Ordinal_10047",
          "FogAssert",
          "FogAssert",
          "Ordinal_10070"
        ]
      },
      "strings": {
        "LoD/1.10": [
          "\"C:\\\\projects\\\\D2\\\\head\\\\Diablo2\\\\Source\\\\D2MCPCli...",
          "\"dwSize < USHRT_MAX\"",
          "\"*lpdwSize < dwMaxSize\""
        ]
      },
      "basic_block_counts": {
        "LoD/1.08": 7,
        "LoD/1.09": 7,
        "LoD/1.09b": 7,
        "LoD/1.09d": 7,
        "LoD/1.10": 7
      },
      "loop_counts": {
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.08": "1c25fd498b779d5357d17507259e1c3d",
        "LoD/1.09": "1c25fd498b779d5357d17507259e1c3d",
        "LoD/1.09b": "1c25fd498b779d5357d17507259e1c3d",
        "LoD/1.09d": "1c25fd498b779d5357d17507259e1c3d",
        "LoD/1.10": "1ed7dd8f3b87a5bc08d967cf179f49fc"
      }
    },
    "d2mcpclient.dll_API_b8393bcbef34_1240": {
      "addresses": {
        "LoD/1.08": "0x6FA51240",
        "LoD/1.09": "0x6F9F1240",
        "LoD/1.09b": "0x6F9F1240",
        "LoD/1.09d": "0x6F9F1240"
      },
      "rvas": {
        "LoD/1.08": "0x1240",
        "LoD/1.09": "0x1240",
        "LoD/1.09b": "0x1240",
        "LoD/1.09d": "0x1240"
      },
      "sizes": {
        "LoD/1.08": 355,
        "LoD/1.09": 355,
        "LoD/1.09b": 355,
        "LoD/1.09d": 355
      },
      "name_source": "LoD/1.08",
      "method": "API",
      "index": "API:b8393bcbef349c7d3b02776e2127364a",
      "callees": {
        "LoD/1.08": [
          "Ordinal_10047",
          "Ordinal_10047"
        ],
        "LoD/1.09": [
          "Ordinal_10047",
          "Ordinal_10047"
        ],
        "LoD/1.09b": [
          "Ordinal_10047",
          "Ordinal_10047"
        ],
        "LoD/1.09d": [
          "Ordinal_10047",
          "Ordinal_10047"
        ]
      },
      "basic_block_counts": {
        "LoD/1.08": 10,
        "LoD/1.09": 10,
        "LoD/1.09b": 10,
        "LoD/1.09d": 10
      },
      "loop_counts": {
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.08": "865b66764c74f9c6e1244b178b4705fa",
        "LoD/1.09": "865b66764c74f9c6e1244b178b4705fa",
        "LoD/1.09b": "865b66764c74f9c6e1244b178b4705fa",
        "LoD/1.09d": "865b66764c74f9c6e1244b178b4705fa"
      }
    },
    "d2mcpclient.dll_MNE_3d4e3339d7bc": {
      "addresses": {
        "LoD/1.08": "0x6FA513B0",
        "LoD/1.09": "0x6F9F13D0",
        "LoD/1.09b": "0x6F9F13D0",
        "LoD/1.09d": "0x6F9F13B0",
        "LoD/1.10": "0x6F9F1360",
        "LoD/1.11": "0x6FA27210",
        "LoD/1.11b": "0x6FA26000",
        "LoD/1.12a": "0x6FA269B0",
        "LoD/1.13c": "0x6FA26060",
        "LoD/1.13d": "0x6FA272D0"
      },
      "rvas": {
        "LoD/1.08": "0x13B0",
        "LoD/1.09": "0x13D0",
        "LoD/1.09b": "0x13D0",
        "LoD/1.09d": "0x13B0",
        "LoD/1.10": "0x1360",
        "LoD/1.11": "0x7210",
        "LoD/1.11b": "0x6000",
        "LoD/1.12a": "0x69B0",
        "LoD/1.13c": "0x6060",
        "LoD/1.13d": "0x72D0"
      },
      "sizes": {
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
      "name_source": "LoD/1.08",
      "method": "MNE",
      "index": "MNE:3d4e3339d7bcb6ead5f6fd1c93d47c1f",
      "basic_block_counts": {
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
        "LoD/1.08": "3d4e3339d7bcb6ead5f6fd1c93d47c1f",
        "LoD/1.09": "3d4e3339d7bcb6ead5f6fd1c93d47c1f",
        "LoD/1.09b": "3d4e3339d7bcb6ead5f6fd1c93d47c1f",
        "LoD/1.09d": "3d4e3339d7bcb6ead5f6fd1c93d47c1f",
        "LoD/1.10": "3d4e3339d7bcb6ead5f6fd1c93d47c1f",
        "LoD/1.11": "3d4e3339d7bcb6ead5f6fd1c93d47c1f",
        "LoD/1.11b": "3d4e3339d7bcb6ead5f6fd1c93d47c1f",
        "LoD/1.12a": "3d4e3339d7bcb6ead5f6fd1c93d47c1f",
        "LoD/1.13c": "3d4e3339d7bcb6ead5f6fd1c93d47c1f",
        "LoD/1.13d": "3d4e3339d7bcb6ead5f6fd1c93d47c1f"
      }
    },
    "d2mcpclient.dll_MNE_3d4e3339d7bc_13D0": {
      "addresses": {
        "LoD/1.08": "0x6FA513D0",
        "LoD/1.09": "0x6F9F13B0",
        "LoD/1.09b": "0x6F9F13B0",
        "LoD/1.09d": "0x6F9F13D0",
        "LoD/1.10": "0x6F9F1380",
        "LoD/1.11": "0x6FA271F0",
        "LoD/1.11b": "0x6FA26020",
        "LoD/1.12a": "0x6FA269D0",
        "LoD/1.13c": "0x6FA26080",
        "LoD/1.13d": "0x6FA272B0"
      },
      "rvas": {
        "LoD/1.08": "0x13D0",
        "LoD/1.09": "0x13B0",
        "LoD/1.09b": "0x13B0",
        "LoD/1.09d": "0x13D0",
        "LoD/1.10": "0x1380",
        "LoD/1.11": "0x71F0",
        "LoD/1.11b": "0x6020",
        "LoD/1.12a": "0x69D0",
        "LoD/1.13c": "0x6080",
        "LoD/1.13d": "0x72B0"
      },
      "sizes": {
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
      "name_source": "LoD/1.08",
      "method": "MNE",
      "index": "MNE:3d4e3339d7bcb6ead5f6fd1c93d47c1f",
      "basic_block_counts": {
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
        "LoD/1.08": "3d4e3339d7bcb6ead5f6fd1c93d47c1f",
        "LoD/1.09": "3d4e3339d7bcb6ead5f6fd1c93d47c1f",
        "LoD/1.09b": "3d4e3339d7bcb6ead5f6fd1c93d47c1f",
        "LoD/1.09d": "3d4e3339d7bcb6ead5f6fd1c93d47c1f",
        "LoD/1.10": "3d4e3339d7bcb6ead5f6fd1c93d47c1f",
        "LoD/1.11": "3d4e3339d7bcb6ead5f6fd1c93d47c1f",
        "LoD/1.11b": "3d4e3339d7bcb6ead5f6fd1c93d47c1f",
        "LoD/1.12a": "3d4e3339d7bcb6ead5f6fd1c93d47c1f",
        "LoD/1.13c": "3d4e3339d7bcb6ead5f6fd1c93d47c1f",
        "LoD/1.13d": "3d4e3339d7bcb6ead5f6fd1c93d47c1f"
      }
    },
    "d2mcpclient.dll_API_4fcbd90bf10b_13F0": {
      "addresses": {
        "LoD/1.08": "0x6FA513F0",
        "LoD/1.09": "0x6F9F13F0",
        "LoD/1.09b": "0x6F9F13F0",
        "LoD/1.09d": "0x6F9F13F0",
        "LoD/1.10": "0x6F9F13A0"
      },
      "rvas": {
        "LoD/1.08": "0x13F0",
        "LoD/1.09": "0x13F0",
        "LoD/1.09b": "0x13F0",
        "LoD/1.09d": "0x13F0",
        "LoD/1.10": "0x13A0"
      },
      "sizes": {
        "LoD/1.08": 35,
        "LoD/1.09": 35,
        "LoD/1.09b": 35,
        "LoD/1.09d": 35,
        "LoD/1.10": 35
      },
      "name_source": "LoD/1.08",
      "method": "API",
      "index": "API:4fcbd90bf10bd2ab26bfa04f1a8f03a4",
      "callees": {
        "LoD/1.08": [
          "Ordinal_10047",
          "SetErrorHandlingDisabled"
        ],
        "LoD/1.09": [
          "Ordinal_10047",
          "SetErrorHandlingDisabled"
        ],
        "LoD/1.09b": [
          "Ordinal_10047",
          "SetErrorHandlingDisabled"
        ],
        "LoD/1.09d": [
          "Ordinal_10047",
          "SetErrorHandlingDisabled"
        ],
        "LoD/1.10": [
          "Ordinal_10047",
          "SetErrorHandlingDisabled"
        ]
      },
      "basic_block_counts": {
        "LoD/1.08": 3,
        "LoD/1.09": 3,
        "LoD/1.09b": 3,
        "LoD/1.09d": 3,
        "LoD/1.10": 3
      },
      "loop_counts": {
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.08": "fd7b7a115c143cdd5e3d4e7cd68e1848",
        "LoD/1.09": "fd7b7a115c143cdd5e3d4e7cd68e1848",
        "LoD/1.09b": "fd7b7a115c143cdd5e3d4e7cd68e1848",
        "LoD/1.09d": "fd7b7a115c143cdd5e3d4e7cd68e1848",
        "LoD/1.10": "fd7b7a115c143cdd5e3d4e7cd68e1848"
      }
    },
    "d2mcpclient.dll_API_4fcbd90bf10b_1420": {
      "addresses": {
        "LoD/1.08": "0x6FA51420",
        "LoD/1.09": "0x6F9F1420",
        "LoD/1.09b": "0x6F9F1420",
        "LoD/1.09d": "0x6F9F1420",
        "LoD/1.10": "0x6F9F1480"
      },
      "rvas": {
        "LoD/1.08": "0x1420",
        "LoD/1.09": "0x1420",
        "LoD/1.09b": "0x1420",
        "LoD/1.09d": "0x1420",
        "LoD/1.10": "0x1480"
      },
      "sizes": {
        "LoD/1.08": 22,
        "LoD/1.09": 22,
        "LoD/1.09b": 22,
        "LoD/1.09d": 22,
        "LoD/1.10": 22
      },
      "name_source": "LoD/1.08",
      "method": "API",
      "index": "API:4fcbd90bf10bd2ab26bfa04f1a8f03a4",
      "callees": {
        "LoD/1.08": [
          "Ordinal_10047",
          "SetErrorHandlingDisabled"
        ],
        "LoD/1.09": [
          "Ordinal_10047",
          "SetErrorHandlingDisabled"
        ],
        "LoD/1.09b": [
          "Ordinal_10047",
          "SetErrorHandlingDisabled"
        ],
        "LoD/1.09d": [
          "Ordinal_10047",
          "SetErrorHandlingDisabled"
        ],
        "LoD/1.10": [
          "Ordinal_10047",
          "SetErrorHandlingDisabled"
        ]
      },
      "basic_block_counts": {
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1
      },
      "loop_counts": {
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.08": "f32811193b2d3afd67fe60449b44f48d",
        "LoD/1.09": "f32811193b2d3afd67fe60449b44f48d",
        "LoD/1.09b": "f32811193b2d3afd67fe60449b44f48d",
        "LoD/1.09d": "f32811193b2d3afd67fe60449b44f48d",
        "LoD/1.10": "f32811193b2d3afd67fe60449b44f48d"
      }
    },
    "d2mcpclient.dll_API_4fcbd90bf10b_1440": {
      "addresses": {
        "LoD/1.08": "0x6FA51440",
        "LoD/1.09": "0x6F9F1440",
        "LoD/1.09b": "0x6F9F1440",
        "LoD/1.09d": "0x6F9F1440",
        "LoD/1.10": "0x6F9F1410"
      },
      "rvas": {
        "LoD/1.08": "0x1440",
        "LoD/1.09": "0x1440",
        "LoD/1.09b": "0x1440",
        "LoD/1.09d": "0x1440",
        "LoD/1.10": "0x1410"
      },
      "sizes": {
        "LoD/1.08": 22,
        "LoD/1.09": 22,
        "LoD/1.09b": 22,
        "LoD/1.09d": 22,
        "LoD/1.10": 22
      },
      "name_source": "LoD/1.08",
      "method": "API",
      "index": "API:4fcbd90bf10bd2ab26bfa04f1a8f03a4",
      "callees": {
        "LoD/1.08": [
          "Ordinal_10047",
          "SetErrorHandlingDisabled"
        ],
        "LoD/1.09": [
          "Ordinal_10047",
          "SetErrorHandlingDisabled"
        ],
        "LoD/1.09b": [
          "Ordinal_10047",
          "SetErrorHandlingDisabled"
        ],
        "LoD/1.09d": [
          "Ordinal_10047",
          "SetErrorHandlingDisabled"
        ],
        "LoD/1.10": [
          "Ordinal_10047",
          "SetErrorHandlingDisabled"
        ]
      },
      "basic_block_counts": {
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1
      },
      "loop_counts": {
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.08": "f32811193b2d3afd67fe60449b44f48d",
        "LoD/1.09": "f32811193b2d3afd67fe60449b44f48d",
        "LoD/1.09b": "f32811193b2d3afd67fe60449b44f48d",
        "LoD/1.09d": "f32811193b2d3afd67fe60449b44f48d",
        "LoD/1.10": "f32811193b2d3afd67fe60449b44f48d"
      }
    },
    "d2mcpclient.dll_API_4fcbd90bf10b_1460": {
      "addresses": {
        "LoD/1.08": "0x6FA51460",
        "LoD/1.09": "0x6F9F1460",
        "LoD/1.09b": "0x6F9F1460",
        "LoD/1.09d": "0x6F9F1460",
        "LoD/1.10": "0x6F9F13F0"
      },
      "rvas": {
        "LoD/1.08": "0x1460",
        "LoD/1.09": "0x1460",
        "LoD/1.09b": "0x1460",
        "LoD/1.09d": "0x1460",
        "LoD/1.10": "0x13F0"
      },
      "sizes": {
        "LoD/1.08": 22,
        "LoD/1.09": 22,
        "LoD/1.09b": 22,
        "LoD/1.09d": 22,
        "LoD/1.10": 22
      },
      "name_source": "LoD/1.08",
      "method": "API",
      "index": "API:4fcbd90bf10bd2ab26bfa04f1a8f03a4",
      "callees": {
        "LoD/1.08": [
          "Ordinal_10047",
          "SetErrorHandlingDisabled"
        ],
        "LoD/1.09": [
          "Ordinal_10047",
          "SetErrorHandlingDisabled"
        ],
        "LoD/1.09b": [
          "Ordinal_10047",
          "SetErrorHandlingDisabled"
        ],
        "LoD/1.09d": [
          "Ordinal_10047",
          "SetErrorHandlingDisabled"
        ],
        "LoD/1.10": [
          "Ordinal_10047",
          "SetErrorHandlingDisabled"
        ]
      },
      "basic_block_counts": {
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1
      },
      "loop_counts": {
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.08": "f32811193b2d3afd67fe60449b44f48d",
        "LoD/1.09": "f32811193b2d3afd67fe60449b44f48d",
        "LoD/1.09b": "f32811193b2d3afd67fe60449b44f48d",
        "LoD/1.09d": "f32811193b2d3afd67fe60449b44f48d",
        "LoD/1.10": "f32811193b2d3afd67fe60449b44f48d"
      }
    },
    "d2mcpclient.dll_MNE_11c5f8471f92": {
      "addresses": {
        "LoD/1.08": "0x6FA51480",
        "LoD/1.09": "0x6F9F1480",
        "LoD/1.09b": "0x6F9F1480",
        "LoD/1.09d": "0x6F9F1480",
        "LoD/1.10": "0x6F9F1430"
      },
      "rvas": {
        "LoD/1.08": "0x1480",
        "LoD/1.09": "0x1480",
        "LoD/1.09b": "0x1480",
        "LoD/1.09d": "0x1480",
        "LoD/1.10": "0x1430"
      },
      "sizes": {
        "LoD/1.08": 36,
        "LoD/1.09": 36,
        "LoD/1.09b": 36,
        "LoD/1.09d": 36,
        "LoD/1.10": 36
      },
      "name_source": "LoD/1.08",
      "method": "MNE",
      "index": "MNE:11c5f8471f92d36e63fbd91d4e0a41d8",
      "callees": {
        "LoD/1.08": [
          "Ordinal_10039"
        ],
        "LoD/1.09": [
          "Ordinal_10039"
        ],
        "LoD/1.09b": [
          "Ordinal_10039"
        ],
        "LoD/1.09d": [
          "Ordinal_10039"
        ],
        "LoD/1.10": [
          "Ordinal_10039"
        ]
      },
      "basic_block_counts": {
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1
      },
      "loop_counts": {
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.08": "11c5f8471f92d36e63fbd91d4e0a41d8",
        "LoD/1.09": "11c5f8471f92d36e63fbd91d4e0a41d8",
        "LoD/1.09b": "11c5f8471f92d36e63fbd91d4e0a41d8",
        "LoD/1.09d": "11c5f8471f92d36e63fbd91d4e0a41d8",
        "LoD/1.10": "11c5f8471f92d36e63fbd91d4e0a41d8"
      }
    },
    "d2mcpclient.dll_API_4fcbd90bf10b_14B0": {
      "addresses": {
        "LoD/1.08": "0x6FA514B0",
        "LoD/1.09": "0x6F9F14B0",
        "LoD/1.09b": "0x6F9F14B0",
        "LoD/1.09d": "0x6F9F14B0",
        "LoD/1.10": "0x6F9F1460"
      },
      "rvas": {
        "LoD/1.08": "0x14B0",
        "LoD/1.09": "0x14B0",
        "LoD/1.09b": "0x14B0",
        "LoD/1.09d": "0x14B0",
        "LoD/1.10": "0x1460"
      },
      "sizes": {
        "LoD/1.08": 22,
        "LoD/1.09": 22,
        "LoD/1.09b": 22,
        "LoD/1.09d": 22,
        "LoD/1.10": 22
      },
      "name_source": "LoD/1.08",
      "method": "API",
      "index": "API:4fcbd90bf10bd2ab26bfa04f1a8f03a4",
      "callees": {
        "LoD/1.08": [
          "Ordinal_10047",
          "SetErrorHandlingDisabled"
        ],
        "LoD/1.09": [
          "Ordinal_10047",
          "SetErrorHandlingDisabled"
        ],
        "LoD/1.09b": [
          "Ordinal_10047",
          "SetErrorHandlingDisabled"
        ],
        "LoD/1.09d": [
          "Ordinal_10047",
          "SetErrorHandlingDisabled"
        ],
        "LoD/1.10": [
          "Ordinal_10047",
          "SetErrorHandlingDisabled"
        ]
      },
      "basic_block_counts": {
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1
      },
      "loop_counts": {
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.08": "f32811193b2d3afd67fe60449b44f48d",
        "LoD/1.09": "f32811193b2d3afd67fe60449b44f48d",
        "LoD/1.09b": "f32811193b2d3afd67fe60449b44f48d",
        "LoD/1.09d": "f32811193b2d3afd67fe60449b44f48d",
        "LoD/1.10": "f32811193b2d3afd67fe60449b44f48d"
      }
    },
    "d2mcpclient.dll_API_4fcbd90bf10b_14D0": {
      "addresses": {
        "LoD/1.08": "0x6FA514D0",
        "LoD/1.09": "0x6F9F14D0",
        "LoD/1.09b": "0x6F9F14D0",
        "LoD/1.09d": "0x6F9F14D0",
        "LoD/1.10": "0x6F9F1060"
      },
      "rvas": {
        "LoD/1.08": "0x14D0",
        "LoD/1.09": "0x14D0",
        "LoD/1.09b": "0x14D0",
        "LoD/1.09d": "0x14D0",
        "LoD/1.10": "0x1060"
      },
      "sizes": {
        "LoD/1.08": 22,
        "LoD/1.09": 22,
        "LoD/1.09b": 22,
        "LoD/1.09d": 22,
        "LoD/1.10": 22
      },
      "name_source": "LoD/1.08",
      "method": "API",
      "index": "API:4fcbd90bf10bd2ab26bfa04f1a8f03a4",
      "callees": {
        "LoD/1.08": [
          "Ordinal_10047",
          "SetErrorHandlingDisabled"
        ],
        "LoD/1.09": [
          "Ordinal_10047",
          "SetErrorHandlingDisabled"
        ],
        "LoD/1.09b": [
          "Ordinal_10047",
          "SetErrorHandlingDisabled"
        ],
        "LoD/1.09d": [
          "Ordinal_10047",
          "SetErrorHandlingDisabled"
        ],
        "LoD/1.10": [
          "Ordinal_10047",
          "SetErrorHandlingDisabled"
        ]
      },
      "basic_block_counts": {
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1
      },
      "loop_counts": {
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.08": "f32811193b2d3afd67fe60449b44f48d",
        "LoD/1.09": "f32811193b2d3afd67fe60449b44f48d",
        "LoD/1.09b": "f32811193b2d3afd67fe60449b44f48d",
        "LoD/1.09d": "f32811193b2d3afd67fe60449b44f48d",
        "LoD/1.10": "f32811193b2d3afd67fe60449b44f48d"
      }
    },
    "d2mcpclient.dll_API_c91c4430cbec": {
      "addresses": {
        "LoD/1.08": "0x6FA514F0",
        "LoD/1.09": "0x6F9F14F0",
        "LoD/1.09b": "0x6F9F14F0",
        "LoD/1.09d": "0x6F9F14F0",
        "LoD/1.10": "0x6F9F14A0"
      },
      "rvas": {
        "LoD/1.08": "0x14F0",
        "LoD/1.09": "0x14F0",
        "LoD/1.09b": "0x14F0",
        "LoD/1.09d": "0x14F0",
        "LoD/1.10": "0x14A0"
      },
      "sizes": {
        "LoD/1.08": 126,
        "LoD/1.09": 126,
        "LoD/1.09b": 126,
        "LoD/1.09d": 126,
        "LoD/1.10": 126
      },
      "name_source": "LoD/1.08",
      "method": "API",
      "index": "API:c91c4430cbec7e58227b0559e60012e8",
      "callees": {
        "LoD/1.08": [
          "Ordinal_10047",
          "Ordinal_10047",
          "SetErrorHandlingDisabled",
          "Ordinal_10047",
          "SetErrorHandlingDisabled",
          "InetNtoaToStaticBuffer",
          "Ordinal_501",
          "SetErrorHandlingDisabled"
        ],
        "LoD/1.09": [
          "Ordinal_10047",
          "Ordinal_10047",
          "SetErrorHandlingDisabled",
          "Ordinal_10047",
          "SetErrorHandlingDisabled",
          "InetNtoaToStaticBuffer",
          "Ordinal_501",
          "SetErrorHandlingDisabled"
        ],
        "LoD/1.09b": [
          "Ordinal_10047",
          "Ordinal_10047",
          "SetErrorHandlingDisabled",
          "Ordinal_10047",
          "SetErrorHandlingDisabled",
          "InetNtoaToStaticBuffer",
          "Ordinal_501",
          "SetErrorHandlingDisabled"
        ],
        "LoD/1.09d": [
          "Ordinal_10047",
          "Ordinal_10047",
          "SetErrorHandlingDisabled",
          "Ordinal_10047",
          "SetErrorHandlingDisabled",
          "InetNtoaToStaticBuffer",
          "Ordinal_501",
          "SetErrorHandlingDisabled"
        ],
        "LoD/1.10": [
          "Ordinal_10047",
          "Ordinal_10047",
          "SetErrorHandlingDisabled",
          "Ordinal_10047",
          "SetErrorHandlingDisabled",
          "Ordinal_10014",
          "Ordinal_501",
          "SetErrorHandlingDisabled"
        ]
      },
      "basic_block_counts": {
        "LoD/1.08": 5,
        "LoD/1.09": 5,
        "LoD/1.09b": 5,
        "LoD/1.09d": 5,
        "LoD/1.10": 5
      },
      "loop_counts": {
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.08": "47ab2ff3f42e6119e7dcfd2de333fe0b",
        "LoD/1.09": "47ab2ff3f42e6119e7dcfd2de333fe0b",
        "LoD/1.09b": "47ab2ff3f42e6119e7dcfd2de333fe0b",
        "LoD/1.09d": "47ab2ff3f42e6119e7dcfd2de333fe0b",
        "LoD/1.10": "47ab2ff3f42e6119e7dcfd2de333fe0b"
      }
    },
    "d2mcpclient.dll_MNE_48c7dccd9461": {
      "addresses": {
        "LoD/1.08": "0x6FA51720",
        "LoD/1.09": "0x6F9F1720",
        "LoD/1.09b": "0x6F9F1720",
        "LoD/1.09d": "0x6F9F1720"
      },
      "rvas": {
        "LoD/1.08": "0x1720",
        "LoD/1.09": "0x1720",
        "LoD/1.09b": "0x1720",
        "LoD/1.09d": "0x1720"
      },
      "sizes": {
        "LoD/1.08": 42,
        "LoD/1.09": 42,
        "LoD/1.09b": 42,
        "LoD/1.09d": 42
      },
      "name_source": "LoD/1.08",
      "method": "MNE",
      "index": "MNE:48c7dccd9461b223c1a724502ab69018",
      "basic_block_counts": {
        "LoD/1.08": 5,
        "LoD/1.09": 5,
        "LoD/1.09b": 5,
        "LoD/1.09d": 5
      },
      "loop_counts": {
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.08": "48c7dccd9461b223c1a724502ab69018",
        "LoD/1.09": "48c7dccd9461b223c1a724502ab69018",
        "LoD/1.09b": "48c7dccd9461b223c1a724502ab69018",
        "LoD/1.09d": "48c7dccd9461b223c1a724502ab69018"
      }
    },
    "d2mcpclient.dll_API_202a20615cbc": {
      "addresses": {
        "LoD/1.08": "0x6FA51750",
        "LoD/1.09": "0x6F9F1750",
        "LoD/1.09b": "0x6F9F1750",
        "LoD/1.09d": "0x6F9F1750",
        "LoD/1.10": "0x6F9F16C0"
      },
      "rvas": {
        "LoD/1.08": "0x1750",
        "LoD/1.09": "0x1750",
        "LoD/1.09b": "0x1750",
        "LoD/1.09d": "0x1750",
        "LoD/1.10": "0x16C0"
      },
      "sizes": {
        "LoD/1.08": 22,
        "LoD/1.09": 22,
        "LoD/1.09b": 22,
        "LoD/1.09d": 22,
        "LoD/1.10": 22
      },
      "name_source": "LoD/1.08",
      "method": "API",
      "index": "API:202a20615cbcbe78fe2d6af297bea21a",
      "callees": {
        "LoD/1.08": [
          "SetErrorHandlingDisabled",
          "SetErrorHandlingDisabled"
        ],
        "LoD/1.09": [
          "SetErrorHandlingDisabled",
          "SetErrorHandlingDisabled"
        ],
        "LoD/1.09b": [
          "SetErrorHandlingDisabled",
          "SetErrorHandlingDisabled"
        ],
        "LoD/1.09d": [
          "SetErrorHandlingDisabled",
          "SetErrorHandlingDisabled"
        ],
        "LoD/1.10": [
          "SetErrorHandlingDisabled",
          "SetErrorHandlingDisabled"
        ]
      },
      "basic_block_counts": {
        "LoD/1.08": 1,
        "LoD/1.09": 1,
        "LoD/1.09b": 1,
        "LoD/1.09d": 1,
        "LoD/1.10": 1
      },
      "loop_counts": {
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.08": "f32811193b2d3afd67fe60449b44f48d",
        "LoD/1.09": "f32811193b2d3afd67fe60449b44f48d",
        "LoD/1.09b": "f32811193b2d3afd67fe60449b44f48d",
        "LoD/1.09d": "f32811193b2d3afd67fe60449b44f48d",
        "LoD/1.10": "f32811193b2d3afd67fe60449b44f48d"
      }
    },
    "d2mcpclient.dll_MNE_a91afe2c7b8c": {
      "addresses": {
        "LoD/1.08": "0x6FA51770",
        "LoD/1.09": "0x6F9F1770",
        "LoD/1.09b": "0x6F9F1770",
        "LoD/1.09d": "0x6F9F1770",
        "LoD/1.10": "0x6F9F16E0",
        "LoD/1.11": "0x6FA26EB0",
        "LoD/1.11b": "0x6FA26060",
        "LoD/1.12a": "0x6FA26A00",
        "LoD/1.13c": "0x6FA260C0",
        "LoD/1.13d": "0x6FA26F70"
      },
      "rvas": {
        "LoD/1.08": "0x1770",
        "LoD/1.09": "0x1770",
        "LoD/1.09b": "0x1770",
        "LoD/1.09d": "0x1770",
        "LoD/1.10": "0x16E0",
        "LoD/1.11": "0x6EB0",
        "LoD/1.11b": "0x6060",
        "LoD/1.12a": "0x6A00",
        "LoD/1.13c": "0x60C0",
        "LoD/1.13d": "0x6F70"
      },
      "sizes": {
        "LoD/1.08": 13,
        "LoD/1.09": 13,
        "LoD/1.09b": 13,
        "LoD/1.09d": 13,
        "LoD/1.10": 13,
        "LoD/1.11": 13,
        "LoD/1.11b": 13,
        "LoD/1.12a": 13,
        "LoD/1.13c": 13,
        "LoD/1.13d": 13
      },
      "name_source": "LoD/1.08",
      "method": "MNE",
      "index": "MNE:a91afe2c7b8cc0467b750e3c20af01b2",
      "callees": {
        "LoD/1.08": [
          "Ordinal_10058"
        ],
        "LoD/1.09": [
          "Ordinal_10058"
        ],
        "LoD/1.09b": [
          "Ordinal_10058"
        ],
        "LoD/1.09d": [
          "Ordinal_10058"
        ],
        "LoD/1.10": [
          "Ordinal_10058"
        ],
        "LoD/1.11": [
          "Ordinal_10050"
        ],
        "LoD/1.11b": [
          "Ordinal_10003"
        ],
        "LoD/1.12a": [
          "Ordinal_10049"
        ],
        "LoD/1.13c": [
          "Ordinal_10034"
        ],
        "LoD/1.13d": [
          "Ordinal_10010"
        ]
      },
      "basic_block_counts": {
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
        "LoD/1.08": "a91afe2c7b8cc0467b750e3c20af01b2",
        "LoD/1.09": "a91afe2c7b8cc0467b750e3c20af01b2",
        "LoD/1.09b": "a91afe2c7b8cc0467b750e3c20af01b2",
        "LoD/1.09d": "a91afe2c7b8cc0467b750e3c20af01b2",
        "LoD/1.10": "a91afe2c7b8cc0467b750e3c20af01b2",
        "LoD/1.11": "a91afe2c7b8cc0467b750e3c20af01b2",
        "LoD/1.11b": "a91afe2c7b8cc0467b750e3c20af01b2",
        "LoD/1.12a": "a91afe2c7b8cc0467b750e3c20af01b2",
        "LoD/1.13c": "a91afe2c7b8cc0467b750e3c20af01b2",
        "LoD/1.13d": "a91afe2c7b8cc0467b750e3c20af01b2"
      }
    },
    "d2mcpclient.dll_MNE_ac0bb02da58c": {
      "addresses": {
        "LoD/1.08": "0x6FA517C0",
        "LoD/1.09": "0x6F9F17C0",
        "LoD/1.09b": "0x6F9F17C0",
        "LoD/1.09d": "0x6F9F17C0",
        "LoD/1.10": "0x6F9F1730"
      },
      "rvas": {
        "LoD/1.08": "0x17C0",
        "LoD/1.09": "0x17C0",
        "LoD/1.09b": "0x17C0",
        "LoD/1.09d": "0x17C0",
        "LoD/1.10": "0x1730"
      },
      "sizes": {
        "LoD/1.08": 65,
        "LoD/1.09": 65,
        "LoD/1.09b": 65,
        "LoD/1.09d": 65,
        "LoD/1.10": 65
      },
      "name_source": "LoD/1.08",
      "method": "MNE",
      "index": "MNE:ac0bb02da58cbfcc4f1cbafa9f32511e",
      "basic_block_counts": {
        "LoD/1.08": 7,
        "LoD/1.09": 7,
        "LoD/1.09b": 7,
        "LoD/1.09d": 7,
        "LoD/1.10": 7
      },
      "loop_counts": {
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.08": "ac0bb02da58cbfcc4f1cbafa9f32511e",
        "LoD/1.09": "ac0bb02da58cbfcc4f1cbafa9f32511e",
        "LoD/1.09b": "ac0bb02da58cbfcc4f1cbafa9f32511e",
        "LoD/1.09d": "ac0bb02da58cbfcc4f1cbafa9f32511e",
        "LoD/1.10": "ac0bb02da58cbfcc4f1cbafa9f32511e"
      }
    },
    "d2mcpclient.dll_STR_0af683b335f7": {
      "addresses": {
        "LoD/1.08": "0x6FA518A0",
        "LoD/1.09": "0x6F9F18A0",
        "LoD/1.09b": "0x6F9F18A0",
        "LoD/1.09d": "0x6F9F18A0",
        "LoD/1.10": "0x6F9F1810",
        "LoD/1.11": "0x6FA263A0",
        "LoD/1.11b": "0x6FA26B40",
        "LoD/1.12a": "0x6FA27500",
        "LoD/1.13c": "0x6FA26BA0",
        "LoD/1.13d": "0x6FA263B0"
      },
      "rvas": {
        "LoD/1.08": "0x18A0",
        "LoD/1.09": "0x18A0",
        "LoD/1.09b": "0x18A0",
        "LoD/1.09d": "0x18A0",
        "LoD/1.10": "0x1810",
        "LoD/1.11": "0x63A0",
        "LoD/1.11b": "0x6B40",
        "LoD/1.12a": "0x7500",
        "LoD/1.13c": "0x6BA0",
        "LoD/1.13d": "0x63B0"
      },
      "sizes": {
        "LoD/1.08": 366,
        "LoD/1.09": 366,
        "LoD/1.09b": 366,
        "LoD/1.09d": 366,
        "LoD/1.10": 366,
        "LoD/1.11": 196,
        "LoD/1.11b": 196,
        "LoD/1.12a": 196,
        "LoD/1.13c": 196,
        "LoD/1.13d": 196
      },
      "name_source": "LoD/1.08",
      "method": "STR",
      "index": "STR:0af683b335f7e2b9350edc43a789c24f",
      "callees": {
        "LoD/1.08": [
          "InetNtoaToStaticBuffer",
          "CreateNetSession",
          "SetUnitTargetPosition",
          "InitializeWorkerThread",
          "GetField0x110",
          "GetStructPositionXY",
          "SignalResourceStop",
          "SendNetworkData",
          "GetField0x110",
          "GetPeerName"
        ],
        "LoD/1.09": [
          "InetNtoaToStaticBuffer",
          "CreateNetSession",
          "SetUnitTargetPosition",
          "InitializeWorkerThread",
          "GetField0x110",
          "GetStructPositionXY",
          "SignalResourceStop",
          "SendNetworkData",
          "GetField0x110",
          "GetPeerName"
        ],
        "LoD/1.09b": [
          "InetNtoaToStaticBuffer",
          "CreateNetSession",
          "SetUnitTargetPosition",
          "InitializeWorkerThread",
          "GetField0x110",
          "GetStructPositionXY",
          "SignalResourceStop",
          "SendNetworkData",
          "GetField0x110",
          "GetPeerName"
        ],
        "LoD/1.09d": [
          "InetNtoaToStaticBuffer",
          "CreateNetSession",
          "SetUnitTargetPosition",
          "InitializeWorkerThread",
          "GetField0x110",
          "GetStructPositionXY",
          "SignalResourceStop",
          "SendNetworkData",
          "GetField0x110",
          "GetPeerName"
        ],
        "LoD/1.10": [
          "Ordinal_10014",
          "Ordinal_10068",
          "SetGameStateFields",
          "Ordinal_10073",
          "GetField0x110",
          "GetStructPositionXY",
          "Ordinal_10075",
          "SendNetworkData",
          "GetField0x110",
          "Ordinal_10012"
        ],
        "LoD/1.11": [
          "CopyInetNtoaToBuffer",
          "Ordinal_10068",
          "SetGameStateFields",
          "InitializeThreadedSubsystem",
          "GetField0x110",
          "ExtractUnitFields",
          "ConditionallyExecuteSystemTask",
          "Ordinal_10071"
        ],
        "LoD/1.11b": [
          "CopyInetNtoaToBuffer",
          "Ordinal_10068",
          "SetGameStateFields",
          "InitializeThreadedSubsystem",
          "GetField0x110",
          "ExtractUnitFields",
          "ConditionallyExecuteSystemTask",
          "Ordinal_10071"
        ],
        "LoD/1.12a": [
          "CopyInetNtoaToBuffer",
          "CreateAndInitializeSocket",
          "SetGameStateFields",
          "InitializeThreadedSubsystem",
          "GetField0x110",
          "ExtractUnitFields",
          "ConditionallyExecuteSystemTask",
          "WriteDataWithSizeVerification"
        ],
        "LoD/1.13c": [
          "CopyInetNtoaToBuffer",
          "CreateAndInitializeSocket",
          "SetGameStateFields",
          "InitializeThreadedSubsystem",
          "GetField0x110",
          "ExtractUnitFields",
          "ConditionallyExecuteSystemTask",
          "WriteDataWithSizeVerification"
        ],
        "LoD/1.13d": [
          "CopyInetNtoaToBuffer",
          "CreateAndInitializeSocket",
          "SetGameStateFields",
          "InitializeThreadedSubsystem",
          "GetField0x110",
          "ExtractUnitFields",
          "ConditionallyExecuteSystemTask",
          "WriteDataWithSizeVerification"
        ]
      },
      "strings": {
        "LoD/1.08": [
          "\"clt->mcp\""
        ],
        "LoD/1.09": [
          "\"clt->mcp\""
        ],
        "LoD/1.09b": [
          "\"clt->mcp\""
        ],
        "LoD/1.09d": [
          "\"clt->mcp\""
        ],
        "LoD/1.10": [
          "\"clt->mcp\""
        ],
        "LoD/1.11": [
          "\"clt->mcp\""
        ],
        "LoD/1.11b": [
          "\"clt->mcp\""
        ],
        "LoD/1.12a": [
          "\"clt->mcp\""
        ],
        "LoD/1.13c": [
          "\"clt->mcp\""
        ],
        "LoD/1.13d": [
          "\"clt->mcp\""
        ]
      },
      "basic_block_counts": {
        "LoD/1.08": 18,
        "LoD/1.09": 18,
        "LoD/1.09b": 18,
        "LoD/1.09d": 18,
        "LoD/1.10": 18,
        "LoD/1.11": 6,
        "LoD/1.11b": 6,
        "LoD/1.12a": 6,
        "LoD/1.13c": 6,
        "LoD/1.13d": 6
      },
      "loop_counts": {
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
        "LoD/1.08": "655743488ea301cd558d3a0b0bceb45f",
        "LoD/1.09": "655743488ea301cd558d3a0b0bceb45f",
        "LoD/1.09b": "655743488ea301cd558d3a0b0bceb45f",
        "LoD/1.09d": "655743488ea301cd558d3a0b0bceb45f",
        "LoD/1.10": "655743488ea301cd558d3a0b0bceb45f",
        "LoD/1.11": "1ad0aa58b066f67b53a51443d73d705b",
        "LoD/1.11b": "1ad0aa58b066f67b53a51443d73d705b",
        "LoD/1.12a": "1ad0aa58b066f67b53a51443d73d705b",
        "LoD/1.13c": "1ad0aa58b066f67b53a51443d73d705b",
        "LoD/1.13d": "1ad0aa58b066f67b53a51443d73d705b"
      }
    },
    "d2mcpclient.dll_DecrementValue": {
      "addresses": {
        "LoD/1.08": "0x6FA54A40",
        "LoD/1.09": "0x6F9F4A60",
        "LoD/1.09b": "0x6F9F4A60",
        "LoD/1.09d": "0x6F9F4A60",
        "LoD/1.10": "0x6F9F4920",
        "LoD/1.11": "0x6FA25C90",
        "LoD/1.11b": "0x6FA25C90",
        "LoD/1.12a": "0x6FA25D00",
        "LoD/1.13c": "0x6FA25D00",
        "LoD/1.13d": "0x6FA25C90"
      },
      "rvas": {
        "LoD/1.08": "0x4A40",
        "LoD/1.09": "0x4A60",
        "LoD/1.09b": "0x4A60",
        "LoD/1.09d": "0x4A60",
        "LoD/1.10": "0x4920",
        "LoD/1.11": "0x5C90",
        "LoD/1.11b": "0x5C90",
        "LoD/1.12a": "0x5D00",
        "LoD/1.13c": "0x5D00",
        "LoD/1.13d": "0x5C90"
      },
      "sizes": {
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
      "name": "DecrementValue",
      "signature": "int DecrementValue(int nUnused, int nValue)",
      "calling_convention": "__fastcall",
      "comment": "Decrements an integer value by 1 and returns the result.\n\nAlgorithm:\n1. Ignore the first parameter (unused placeholder for fastcall convention)\n2. Load the second parameter value into a register\n3. Subtract 1 from the value using LEA instruction\n4. Return the decremented result\n\nParameters:\nnUnused - int: Unused parameter (fastcall ECX register placeholder)\nnValue - int: The integer value to decrement\n\nReturns:\nint: The input value decreased by 1\n\nSpecial Cases:\n- Function ignores the first parameter completely\n- Uses LEA instruction for efficient decrement: LEA EAX,[EDX + -0x1]\n- Contains orphaned POP EBX instruction from compiler optimization\n\nError Handling:\nNone - this is a simple arithmetic helper function",
      "name_source": "LoD/1.08",
      "method": "MNE",
      "index": "MNE:3ecdb5e459e29b4117490dc114e98574",
      "basic_block_counts": {
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
    "d2mcpclient.dll_FindCharacterInString": {
      "addresses": {
        "LoD/1.08": "0x6FA54A50",
        "LoD/1.09": "0x6F9F4A70",
        "LoD/1.09b": "0x6F9F4A70",
        "LoD/1.09d": "0x6F9F4A70",
        "LoD/1.10": "0x6F9F4930"
      },
      "rvas": {
        "LoD/1.08": "0x4A50",
        "LoD/1.09": "0x4A70",
        "LoD/1.09b": "0x4A70",
        "LoD/1.09d": "0x4A70",
        "LoD/1.10": "0x4930"
      },
      "sizes": {
        "LoD/1.08": 188,
        "LoD/1.09": 188,
        "LoD/1.09b": 188,
        "LoD/1.09d": 188,
        "LoD/1.10": 188
      },
      "name": "FindCharacterInString",
      "signature": "char * FindCharacterInString(char * szString, int nSearchChar)",
      "calling_convention": "__cdecl",
      "comment": "Locate first occurrence of character in string using optimized DWORD scanning\n\nAlgorithm:\n1. Handle unaligned bytes one-by-one until pointer is DWORD-aligned\n2. Check each unaligned byte for target character or null terminator\n3. Build 32-bit search pattern by replicating target character 4 times\n4. Scan aligned memory in 4-byte chunks using bit manipulation tricks\n5. Use XOR and arithmetic to detect target character or null terminator\n6. When match detected, examine individual bytes to find exact position\n7. Return pointer to matching character or NULL if not found\n\nParameters:\nszString (char *): Input string to search, must be null-terminated\nnSearchChar (int): Character to find (only low byte used)\n\nReturns:\nchar *: Pointer to first occurrence of character in string\n        NULL if character not found or string is null\n\nSpecial Cases:\nSearch character 0x00 finds null terminator location\nOptimized for x86 architecture with DWORD-aligned memory access\nUses magic constant 0x7EFEFEFF for simultaneous null detection\n\nMagic Numbers Reference:\n0x7EFEFEFF: Magic constant for null byte detection in DWORD\n0x81010100: Bit mask to isolate null detection results\n0x1010100: Secondary mask for null detection edge cases\n0x80000000: Sign bit mask for overflow detection\n\nPerformance Notes:\nHandles 1-3 unaligned bytes individually for alignment\nProcesses 4 bytes per iteration in main loop\nReturns immediately upon finding target or null terminator",
      "name_source": "LoD/1.08",
      "method": "MNE",
      "index": "MNE:85de0cee1ebe7ed32270da528f819b99",
      "basic_block_counts": {
        "LoD/1.08": 25,
        "LoD/1.09": 25,
        "LoD/1.09b": 25,
        "LoD/1.09d": 25,
        "LoD/1.10": 25
      },
      "loop_counts": {
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.08": "85de0cee1ebe7ed32270da528f819b99",
        "LoD/1.09": "85de0cee1ebe7ed32270da528f819b99",
        "LoD/1.09b": "85de0cee1ebe7ed32270da528f819b99",
        "LoD/1.09d": "85de0cee1ebe7ed32270da528f819b99",
        "LoD/1.10": "85de0cee1ebe7ed32270da528f819b99"
      }
    },
    "d2mcpclient.dll_CompareStrings": {
      "addresses": {
        "LoD/1.08": "0x6FA566E0",
        "LoD/1.09": "0x6F9F6700",
        "LoD/1.09b": "0x6F9F6700",
        "LoD/1.09d": "0x6F9F6700",
        "LoD/1.10": "0x6F9F65C0"
      },
      "rvas": {
        "LoD/1.08": "0x66E0",
        "LoD/1.09": "0x6700",
        "LoD/1.09b": "0x6700",
        "LoD/1.09d": "0x6700",
        "LoD/1.10": "0x65C0"
      },
      "sizes": {
        "LoD/1.08": 129,
        "LoD/1.09": 129,
        "LoD/1.09b": 129,
        "LoD/1.09d": 129,
        "LoD/1.10": 129
      },
      "name": "CompareStrings",
      "signature": "int CompareStrings(char * lpszStr1, char * lpszStr2)",
      "calling_convention": "__cdecl",
      "comment": "High-performance string comparison function using DWORD-aligned memory access for optimal speed.\n\nAlgorithm:\n1. Check if lpszStr1 is not aligned on 4-byte boundary\n2. If unaligned, handle 1-byte alignment by comparing single byte and advancing\n3. If still unaligned, handle 2-byte alignment by comparing word and advancing  \n4. Enter main comparison loop using 4-byte DWORD reads for maximum throughput\n5. Extract each byte from DWORD using bit shifting (0, 8, 16, 24 bits)\n6. Compare corresponding bytes between strings and check for null termination\n7. Return 0 if strings are equal, or signed comparison result (-1/+1) if different\n8. Handle early termination when null character is encountered in either string\n\nParameters:\nlpszStr1 (char *): First null-terminated string to compare\nlpszStr2 (char *): Second null-terminated string to compare\n\nReturns:\n0 if strings are identical\n-1 if lpszStr1 is lexicographically less than lpszStr2\n+1 if lpszStr1 is lexicographically greater than lpszStr2\n\nSpecial Cases:\nAlgorithm uses optimized memory access patterns to compare 4 bytes simultaneously\nHandles unaligned memory addresses by processing 1-2 bytes individually first\nNull termination check occurs after each byte comparison to ensure proper string bounds\n\nMagic Numbers Reference:\n0x3 (0b11): Alignment mask to check if address is 4-byte aligned\n0x1: Single byte alignment check mask  \n0x2: Two-byte alignment check mask\n0x8: Bit shift amount for second byte extraction\n0x10: Bit shift amount for third byte extraction (16 bits)\n0x18: Bit shift amount for fourth byte extraction (24 bits)\n-2: Multiplier used in final comparison calculation\n1: Base value for comparison result calculation",
      "name_source": "LoD/1.08",
      "method": "MNE",
      "index": "MNE:f93a26193b15127770b523718dea2fb3",
      "basic_block_counts": {
        "LoD/1.08": 21,
        "LoD/1.09": 21,
        "LoD/1.09b": 21,
        "LoD/1.09d": 21,
        "LoD/1.10": 21
      },
      "loop_counts": {
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.08": "f93a26193b15127770b523718dea2fb3",
        "LoD/1.09": "f93a26193b15127770b523718dea2fb3",
        "LoD/1.09b": "f93a26193b15127770b523718dea2fb3",
        "LoD/1.09d": "f93a26193b15127770b523718dea2fb3",
        "LoD/1.10": "f93a26193b15127770b523718dea2fb3"
      }
    },
    "d2mcpclient.dll_AullDiv": {
      "addresses": {
        "LoD/1.08": "0x6FA569D0",
        "LoD/1.09": "0x6F9F69F0",
        "LoD/1.09b": "0x6F9F69F0",
        "LoD/1.09d": "0x6F9F69F0",
        "LoD/1.10": "0x6F9F68B0"
      },
      "rvas": {
        "LoD/1.08": "0x69D0",
        "LoD/1.09": "0x69F0",
        "LoD/1.09b": "0x69F0",
        "LoD/1.09d": "0x69F0",
        "LoD/1.10": "0x68B0"
      },
      "sizes": {
        "LoD/1.08": 104,
        "LoD/1.09": 104,
        "LoD/1.09b": 104,
        "LoD/1.09d": 104,
        "LoD/1.10": 104
      },
      "name": "AullDiv",
      "signature": "undefined8 AullDiv(uint dwDividendLow, uint dwDividendHigh, uint dwDivisorLow, uint dwDivisorHigh)",
      "calling_convention": "__stdcall",
      "comment": "Performs 64-bit unsigned integer division (__aulldiv runtime library function).\n\nAlgorithm:\n1. Combine 32-bit parameter pairs into 64-bit dividend and divisor values\n2. Check if divisor high word is zero (simple 64/32 division case)\n3. Simple case: Use 32-bit division operations to compute quotient directly\n4. Complex case: Normalize both operands by shifting right until divisor fits in 32 bits\n5. Perform approximate division using normalized 32-bit values\n6. Multiply trial quotient by original divisor to get product\n7. Compare product with original dividend to verify quotient accuracy\n8. Decrement quotient if product exceeds dividend (correction step)\n9. Return 64-bit quotient as combined high/low 32-bit words\n\nParameters:\n  dwDividendLow   - Low 32 bits of 64-bit dividend\n  dwDividendHigh  - High 32 bits of 64-bit dividend  \n  dwDivisorLow    - Low 32 bits of 64-bit divisor\n  dwDivisorHigh   - High 32 bits of 64-bit divisor\n\nReturns:\n  Success: 64-bit quotient (dividend / divisor)\n  \nSpecial Cases:\n  Division by zero: Undefined behavior (not validated)\n  Overflow: Cannot occur with unsigned division\n  \nAlgorithm Details:\n  - Uses binary long division when divisor > 32 bits\n  - Normalizes operands to avoid overflow during intermediate calculations\n  - Trial-and-error approach with correction ensures accuracy\n  - Optimized for common case where divisor fits in 32 bits",
      "name_source": "LoD/1.08",
      "method": "MNE",
      "index": "MNE:9e01ab6a0c2f67c73794c17804322b4d",
      "basic_block_counts": {
        "LoD/1.08": 11,
        "LoD/1.09": 11,
        "LoD/1.09b": 11,
        "LoD/1.09d": 11,
        "LoD/1.10": 11
      },
      "loop_counts": {
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.08": "9e01ab6a0c2f67c73794c17804322b4d",
        "LoD/1.09": "9e01ab6a0c2f67c73794c17804322b4d",
        "LoD/1.09b": "9e01ab6a0c2f67c73794c17804322b4d",
        "LoD/1.09d": "9e01ab6a0c2f67c73794c17804322b4d",
        "LoD/1.10": "9e01ab6a0c2f67c73794c17804322b4d"
      }
    },
    "d2mcpclient.dll_UnsignedLongLongRemainder": {
      "addresses": {
        "LoD/1.08": "0x6FA56A40",
        "LoD/1.09": "0x6F9F6A60",
        "LoD/1.09b": "0x6F9F6A60",
        "LoD/1.09d": "0x6F9F6A60",
        "LoD/1.10": "0x6F9F6920"
      },
      "rvas": {
        "LoD/1.08": "0x6A40",
        "LoD/1.09": "0x6A60",
        "LoD/1.09b": "0x6A60",
        "LoD/1.09d": "0x6A60",
        "LoD/1.10": "0x6920"
      },
      "sizes": {
        "LoD/1.08": 117,
        "LoD/1.09": 117,
        "LoD/1.09b": 117,
        "LoD/1.09d": 117,
        "LoD/1.10": 117
      },
      "name": "UnsignedLongLongRemainder",
      "signature": "undefined8 UnsignedLongLongRemainder(uint dwDividendLow, uint dwDividendHigh, uint dwDivisorLow, uint dwDivisorHigh)",
      "calling_convention": "__stdcall",
      "comment": "Calculates 64-bit unsigned remainder (dividend % divisor) using optimized division algorithm.\n\nAlgorithm:\n1. Check if high 32 bits of divisor are zero for fast path optimization\n2. If divisor fits in 32 bits, perform standard division on combined 64-bit dividend\n3. Otherwise, normalize operands by right-shifting until divisor fits in 32 bits\n4. Perform division on normalized values to get approximate quotient\n5. Calculate full product of quotient and original divisor\n6. Compare product with original dividend and adjust quotient if needed\n7. Subtract final quotient\u00d7divisor from dividend to get remainder\n8. Return 64-bit remainder as combined high/low 32-bit values\n\nParameters:\ndwDividendLow (uint): Low 32 bits of 64-bit unsigned dividend\ndwDividendHigh (uint): High 32 bits of 64-bit unsigned dividend  \ndwDivisorLow (uint): Low 32 bits of 64-bit unsigned divisor\ndwDivisorHigh (uint): High 32 bits of 64-bit unsigned divisor\n\nReturns:\n64-bit unsigned remainder as ulonglong (high 32 bits in EDX, low 32 bits in EAX)\nReturns 0 for division by zero (undefined behavior)\n\nSpecial Cases:\nFast path when dwDivisorHigh == 0: Uses hardware DIV instruction directly\nNormalization loop when divisor > 32 bits: Shifts both operands right until divisor fits in 32 bits\nQuotient adjustment: If initial quotient estimate is too large, decrements and recalculates\n\nMagic Numbers Reference:\n0x20 (32 decimal): Left shift amount for combining high/low 32-bit parts into 64-bit value\n0x1f (31 decimal): Right shift amount for propagating carry bit during normalization\n0xffffffff: Mask to extract low 32 bits from 64-bit intermediate results",
      "name_source": "LoD/1.08",
      "method": "MNE",
      "index": "MNE:e318b2efa2b7ed9dcb619fe5ba3fc2d5",
      "basic_block_counts": {
        "LoD/1.08": 11,
        "LoD/1.09": 11,
        "LoD/1.09b": 11,
        "LoD/1.09d": 11,
        "LoD/1.10": 11
      },
      "loop_counts": {
        "LoD/1.08": 0,
        "LoD/1.09": 0,
        "LoD/1.09b": 0,
        "LoD/1.09d": 0,
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.08": "e318b2efa2b7ed9dcb619fe5ba3fc2d5",
        "LoD/1.09": "e318b2efa2b7ed9dcb619fe5ba3fc2d5",
        "LoD/1.09b": "e318b2efa2b7ed9dcb619fe5ba3fc2d5",
        "LoD/1.09d": "e318b2efa2b7ed9dcb619fe5ba3fc2d5",
        "LoD/1.10": "e318b2efa2b7ed9dcb619fe5ba3fc2d5"
      }
    },
    "d2mcpclient.dll_API_b8393bcbef34_1140": {
      "addresses": {
        "LoD/1.10": "0x6F9F1140"
      },
      "rvas": {
        "LoD/1.10": "0x1140"
      },
      "sizes": {
        "LoD/1.10": 207
      },
      "name_source": "LoD/1.10",
      "method": "API",
      "index": "API:b8393bcbef349c7d3b02776e2127364a",
      "callees": {
        "LoD/1.10": [
          "Ordinal_10047",
          "Ordinal_10047"
        ]
      },
      "basic_block_counts": {
        "LoD/1.10": 11
      },
      "loop_counts": {
        "LoD/1.10": 0
      },
      "mnemonic_hashes": {
        "LoD/1.10": "64a02ff964e056acd3328435c64ac337"
      }
    },
    "d2mcpclient.dll____crtExitProcess": {
      "addresses": {
        "LoD/1.11": "0x6FA21000",
        "LoD/1.11b": "0x6FA21000",
        "LoD/1.12a": "0x6FA21000",
        "LoD/1.13c": "0x6FA21000",
        "LoD/1.13d": "0x6FA2133D"
      },
      "rvas": {
        "LoD/1.11": "0x1000",
        "LoD/1.11b": "0x1000",
        "LoD/1.12a": "0x1000",
        "LoD/1.13c": "0x1000",
        "LoD/1.13d": "0x133D"
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
    "d2mcpclient.dll_AcquireFileHandleLock8": {
      "addresses": {
        "LoD/1.11": "0x6FA21030",
        "LoD/1.11b": "0x6FA21030",
        "LoD/1.12a": "0x6FA21030",
        "LoD/1.13c": "0x6FA21030",
        "LoD/1.13d": "0x6FA2136D"
      },
      "rvas": {
        "LoD/1.11": "0x1030",
        "LoD/1.11b": "0x1030",
        "LoD/1.12a": "0x1030",
        "LoD/1.13c": "0x1030",
        "LoD/1.13d": "0x136D"
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
    "d2mcpclient.dll___initterm": {
      "addresses": {
        "LoD/1.11": "0x6FA21042",
        "LoD/1.11b": "0x6FA21042",
        "LoD/1.12a": "0x6FA21042",
        "LoD/1.13c": "0x6FA21042",
        "LoD/1.13d": "0x6FA2137F"
      },
      "rvas": {
        "LoD/1.11": "0x1042",
        "LoD/1.11b": "0x1042",
        "LoD/1.12a": "0x1042",
        "LoD/1.13c": "0x1042",
        "LoD/1.13d": "0x137F"
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
    "d2mcpclient.dll___cinit": {
      "addresses": {
        "LoD/1.11": "0x6FA2105A",
        "LoD/1.11b": "0x6FA2105A",
        "LoD/1.12a": "0x6FA2105A",
        "LoD/1.13c": "0x6FA2105A",
        "LoD/1.13d": "0x6FA21397"
      },
      "rvas": {
        "LoD/1.11": "0x105A",
        "LoD/1.11b": "0x105A",
        "LoD/1.12a": "0x105A",
        "LoD/1.13c": "0x105A",
        "LoD/1.13d": "0x1397"
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
    "d2mcpclient.dll_ProcessTerminationHandler": {
      "addresses": {
        "LoD/1.11": "0x6FA210C4",
        "LoD/1.11b": "0x6FA210C4",
        "LoD/1.12a": "0x6FA210C4",
        "LoD/1.13c": "0x6FA210C4",
        "LoD/1.13d": "0x6FA21401"
      },
      "rvas": {
        "LoD/1.11": "0x10C4",
        "LoD/1.11b": "0x10C4",
        "LoD/1.12a": "0x10C4",
        "LoD/1.13c": "0x10C4",
        "LoD/1.13d": "0x1401"
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
    "d2mcpclient.dll_VerifyCriticalSectionExitLock": {
      "addresses": {
        "LoD/1.11": "0x6FA21173",
        "LoD/1.11b": "0x6FA21173",
        "LoD/1.12a": "0x6FA21173",
        "LoD/1.13c": "0x6FA21173",
        "LoD/1.13d": "0x6FA214B0"
      },
      "rvas": {
        "LoD/1.11": "0x1173",
        "LoD/1.11b": "0x1173",
        "LoD/1.12a": "0x1173",
        "LoD/1.13c": "0x1173",
        "LoD/1.13d": "0x14B0"
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
    "d2mcpclient.dll___CRT_INIT@12": {
      "addresses": {
        "LoD/1.11": "0x6FA211B8",
        "LoD/1.11b": "0x6FA211B8",
        "LoD/1.12a": "0x6FA211B8",
        "LoD/1.13c": "0x6FA211B8",
        "LoD/1.13d": "0x6FA214F5"
      },
      "rvas": {
        "LoD/1.11": "0x11B8",
        "LoD/1.11b": "0x11B8",
        "LoD/1.12a": "0x11B8",
        "LoD/1.13c": "0x11B8",
        "LoD/1.13d": "0x14F5"
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
    "d2mcpclient.dll___DllMainCRTStartup@12": {
      "addresses": {
        "LoD/1.11": "0x6FA21339",
        "LoD/1.11b": "0x6FA21339",
        "LoD/1.12a": "0x6FA21339",
        "LoD/1.13c": "0x6FA21339",
        "LoD/1.13d": "0x6FA21676"
      },
      "rvas": {
        "LoD/1.11": "0x1339",
        "LoD/1.11b": "0x1339",
        "LoD/1.12a": "0x1339",
        "LoD/1.13c": "0x1339",
        "LoD/1.13d": "0x1676"
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
    "d2mcpclient.dll___mtinitlocks": {
      "addresses": {
        "LoD/1.11": "0x6FA21450",
        "LoD/1.11b": "0x6FA21450",
        "LoD/1.12a": "0x6FA21450",
        "LoD/1.13c": "0x6FA21450",
        "LoD/1.13d": "0x6FA2178D"
      },
      "rvas": {
        "LoD/1.11": "0x1450",
        "LoD/1.11b": "0x1450",
        "LoD/1.12a": "0x1450",
        "LoD/1.13c": "0x1450",
        "LoD/1.13d": "0x178D"
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
    "d2mcpclient.dll___mtdeletelocks": {
      "addresses": {
        "LoD/1.11": "0x6FA21499",
        "LoD/1.11b": "0x6FA21499",
        "LoD/1.12a": "0x6FA21499",
        "LoD/1.13c": "0x6FA21499",
        "LoD/1.13d": "0x6FA217D6"
      },
      "rvas": {
        "LoD/1.11": "0x1499",
        "LoD/1.11b": "0x1499",
        "LoD/1.12a": "0x1499",
        "LoD/1.13c": "0x1499",
        "LoD/1.13d": "0x17D6"
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
    "d2mcpclient.dll___mtinitlocknum": {
      "addresses": {
        "LoD/1.11": "0x6FA21503",
        "LoD/1.11b": "0x6FA21503",
        "LoD/1.12a": "0x6FA21503",
        "LoD/1.13c": "0x6FA21503",
        "LoD/1.13d": "0x6FA21840"
      },
      "rvas": {
        "LoD/1.11": "0x1503",
        "LoD/1.11b": "0x1503",
        "LoD/1.12a": "0x1503",
        "LoD/1.13c": "0x1503",
        "LoD/1.13d": "0x1840"
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
    "d2mcpclient.dll_ReleaseMTInitLock": {
      "addresses": {
        "LoD/1.11": "0x6FA2159A",
        "LoD/1.11b": "0x6FA2159A",
        "LoD/1.12a": "0x6FA2159A",
        "LoD/1.13c": "0x6FA2159A",
        "LoD/1.13d": "0x6FA218D7"
      },
      "rvas": {
        "LoD/1.11": "0x159A",
        "LoD/1.11b": "0x159A",
        "LoD/1.12a": "0x159A",
        "LoD/1.13c": "0x159A",
        "LoD/1.13d": "0x18D7"
      },
      "sizes": {
        "LoD/1.11": 9,
        "LoD/1.11b": 9,
        "LoD/1.12a": 9,
        "LoD/1.13c": 9,
        "LoD/1.13d": 9
      },
      "name": "ReleaseMTInitLock",
      "signature": "void ReleaseMTInitLock(void)",
      "calling_convention": "__stdcall",
      "comment": "Releases the multi-threaded initialization critical section lock.\n\nAlgorithm:\n1. Push lock index 10 onto stack (multi-threaded initialization lock identifier)\n2. Call LeaveCriticalSectionByIndex to release the critical section lock\n3. Stack cleanup with POP ECX per __stdcall convention\n4. Return to caller\n\nParameters:\nNone - No parameters required\n\nReturns:\nvoid - No return value\n\nSpecial Cases:\n- Lock index 10 is reserved for multi-threaded initialization synchronization\n- This function is part of the CRT (C Runtime) initialization system\n- Called after successfully initializing thread-local critical sections\n- Serves as a simple wrapper to simplify calling code",
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
    "d2mcpclient.dll___lock": {
      "addresses": {
        "LoD/1.11": "0x6FA215A3",
        "LoD/1.11b": "0x6FA215A3",
        "LoD/1.12a": "0x6FA215A3",
        "LoD/1.13c": "0x6FA215A3",
        "LoD/1.13d": "0x6FA218E0"
      },
      "rvas": {
        "LoD/1.11": "0x15A3",
        "LoD/1.11b": "0x15A3",
        "LoD/1.12a": "0x15A3",
        "LoD/1.13c": "0x15A3",
        "LoD/1.13d": "0x18E0"
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
    "d2mcpclient.dll___onexit_lk": {
      "addresses": {
        "LoD/1.11": "0x6FA215D4",
        "LoD/1.11b": "0x6FA215D4",
        "LoD/1.12a": "0x6FA215D4",
        "LoD/1.13c": "0x6FA215D4",
        "LoD/1.13d": "0x6FA21911"
      },
      "rvas": {
        "LoD/1.11": "0x15D4",
        "LoD/1.11b": "0x15D4",
        "LoD/1.12a": "0x15D4",
        "LoD/1.13c": "0x15D4",
        "LoD/1.13d": "0x1911"
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
    "d2mcpclient.dll____onexitinit": {
      "addresses": {
        "LoD/1.11": "0x6FA21654",
        "LoD/1.11b": "0x6FA21654",
        "LoD/1.12a": "0x6FA21654",
        "LoD/1.13c": "0x6FA21654",
        "LoD/1.13d": "0x6FA21991"
      },
      "rvas": {
        "LoD/1.11": "0x1654",
        "LoD/1.11b": "0x1654",
        "LoD/1.12a": "0x1654",
        "LoD/1.13c": "0x1654",
        "LoD/1.13d": "0x1991"
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
    "d2mcpclient.dll___onexit": {
      "addresses": {
        "LoD/1.11": "0x6FA2167C",
        "LoD/1.11b": "0x6FA2167C",
        "LoD/1.12a": "0x6FA2167C",
        "LoD/1.13c": "0x6FA2167C",
        "LoD/1.13d": "0x6FA219B9"
      },
      "rvas": {
        "LoD/1.11": "0x167C",
        "LoD/1.11b": "0x167C",
        "LoD/1.12a": "0x167C",
        "LoD/1.13c": "0x167C",
        "LoD/1.13d": "0x19B9"
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
    "d2mcpclient.dll_ExitHandlerCleanup": {
      "addresses": {
        "LoD/1.11": "0x6FA216AE",
        "LoD/1.11b": "0x6FA216AE",
        "LoD/1.12a": "0x6FA216AE",
        "LoD/1.13c": "0x6FA216AE",
        "LoD/1.13d": "0x6FA219EB"
      },
      "rvas": {
        "LoD/1.11": "0x16AE",
        "LoD/1.11b": "0x16AE",
        "LoD/1.12a": "0x16AE",
        "LoD/1.13c": "0x16AE",
        "LoD/1.13d": "0x19EB"
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
    "d2mcpclient.dll__atexit": {
      "addresses": {
        "LoD/1.11": "0x6FA216B4",
        "LoD/1.11b": "0x6FA216B4",
        "LoD/1.12a": "0x6FA216B4",
        "LoD/1.13c": "0x6FA216B4",
        "LoD/1.13d": "0x6FA219F1"
      },
      "rvas": {
        "LoD/1.11": "0x16B4",
        "LoD/1.11b": "0x16B4",
        "LoD/1.12a": "0x16B4",
        "LoD/1.13c": "0x16B4",
        "LoD/1.13d": "0x19F1"
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
    "d2mcpclient.dll___RTC_Initialize": {
      "addresses": {
        "LoD/1.11": "0x6FA216C6",
        "LoD/1.11b": "0x6FA216C6",
        "LoD/1.12a": "0x6FA216C6",
        "LoD/1.13c": "0x6FA216C6",
        "LoD/1.13d": "0x6FA21A03"
      },
      "rvas": {
        "LoD/1.11": "0x16C6",
        "LoD/1.11b": "0x16C6",
        "LoD/1.12a": "0x16C6",
        "LoD/1.13c": "0x16C6",
        "LoD/1.13d": "0x1A03"
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
    "d2mcpclient.dll_MNE_9882f49b4616": {
      "addresses": {
        "LoD/1.11": "0x6FA2170A",
        "LoD/1.11b": "0x6FA2170A",
        "LoD/1.12a": "0x6FA2170A",
        "LoD/1.13c": "0x6FA2170A",
        "LoD/1.13d": "0x6FA21A47"
      },
      "rvas": {
        "LoD/1.11": "0x170A",
        "LoD/1.11b": "0x170A",
        "LoD/1.12a": "0x170A",
        "LoD/1.13c": "0x170A",
        "LoD/1.13d": "0x1A47"
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
    "d2mcpclient.dll___SEH_prolog": {
      "addresses": {
        "LoD/1.11": "0x6FA21750",
        "LoD/1.11b": "0x6FA21750",
        "LoD/1.12a": "0x6FA21750",
        "LoD/1.13c": "0x6FA21750",
        "LoD/1.13d": "0x6FA21A8C"
      },
      "rvas": {
        "LoD/1.11": "0x1750",
        "LoD/1.11b": "0x1750",
        "LoD/1.12a": "0x1750",
        "LoD/1.13c": "0x1750",
        "LoD/1.13d": "0x1A8C"
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
    "d2mcpclient.dll___SEH_epilog": {
      "addresses": {
        "LoD/1.11": "0x6FA2178B",
        "LoD/1.11b": "0x6FA2178B",
        "LoD/1.12a": "0x6FA2178B",
        "LoD/1.13c": "0x6FA2178B",
        "LoD/1.13d": "0x6FA21AC7"
      },
      "rvas": {
        "LoD/1.11": "0x178B",
        "LoD/1.11b": "0x178B",
        "LoD/1.12a": "0x178B",
        "LoD/1.13c": "0x178B",
        "LoD/1.13d": "0x1AC7"
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
    "d2mcpclient.dll_AllocateTlsSlot": {
      "addresses": {
        "LoD/1.11": "0x6FA218A5",
        "LoD/1.11b": "0x6FA218A5",
        "LoD/1.12a": "0x6FA218A5",
        "LoD/1.13c": "0x6FA218A5",
        "LoD/1.13d": "0x6FA21BE1"
      },
      "rvas": {
        "LoD/1.11": "0x18A5",
        "LoD/1.11b": "0x18A5",
        "LoD/1.12a": "0x18A5",
        "LoD/1.13c": "0x18A5",
        "LoD/1.13d": "0x1BE1"
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
    "d2mcpclient.dll___mtterm": {
      "addresses": {
        "LoD/1.11": "0x6FA218AE",
        "LoD/1.11b": "0x6FA218AE",
        "LoD/1.12a": "0x6FA218AE",
        "LoD/1.13c": "0x6FA218AE",
        "LoD/1.13d": "0x6FA21BEA"
      },
      "rvas": {
        "LoD/1.11": "0x18AE",
        "LoD/1.11b": "0x18AE",
        "LoD/1.12a": "0x18AE",
        "LoD/1.13c": "0x18AE",
        "LoD/1.13d": "0x1BEA"
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
    "d2mcpclient.dll___freefls@4": {
      "addresses": {
        "LoD/1.11": "0x6FA2194F",
        "LoD/1.11b": "0x6FA2194F",
        "LoD/1.12a": "0x6FA2194F",
        "LoD/1.13c": "0x6FA2194F",
        "LoD/1.13d": "0x6FA21C8B"
      },
      "rvas": {
        "LoD/1.11": "0x194F",
        "LoD/1.11b": "0x194F",
        "LoD/1.12a": "0x194F",
        "LoD/1.13c": "0x194F",
        "LoD/1.13d": "0x1C8B"
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
    "d2mcpclient.dll___freeptd": {
      "addresses": {
        "LoD/1.11": "0x6FA21A96",
        "LoD/1.11b": "0x6FA21A96",
        "LoD/1.12a": "0x6FA21A96",
        "LoD/1.13c": "0x6FA21A96",
        "LoD/1.13d": "0x6FA21DD2"
      },
      "rvas": {
        "LoD/1.11": "0x1A96",
        "LoD/1.11b": "0x1A96",
        "LoD/1.12a": "0x1A96",
        "LoD/1.13c": "0x1A96",
        "LoD/1.13d": "0x1DD2"
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
    "d2mcpclient.dll___mtinit": {
      "addresses": {
        "LoD/1.11": "0x6FA21AC5",
        "LoD/1.11b": "0x6FA21AC5",
        "LoD/1.12a": "0x6FA21AC5",
        "LoD/1.13c": "0x6FA21AC5",
        "LoD/1.13d": "0x6FA21E01"
      },
      "rvas": {
        "LoD/1.11": "0x1AC5",
        "LoD/1.11b": "0x1AC5",
        "LoD/1.12a": "0x1AC5",
        "LoD/1.13c": "0x1AC5",
        "LoD/1.13d": "0x1E01"
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
    "d2mcpclient.dll__free": {
      "addresses": {
        "LoD/1.11": "0x6FA21BB4",
        "LoD/1.11b": "0x6FA21BB4",
        "LoD/1.12a": "0x6FA21BB4",
        "LoD/1.13c": "0x6FA21BB4",
        "LoD/1.13d": "0x6FA21EF0"
      },
      "rvas": {
        "LoD/1.11": "0x1BB4",
        "LoD/1.11b": "0x1BB4",
        "LoD/1.12a": "0x1BB4",
        "LoD/1.13c": "0x1BB4",
        "LoD/1.13d": "0x1EF0"
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
    "d2mcpclient.dll__calloc": {
      "addresses": {
        "LoD/1.11": "0x6FA21C25",
        "LoD/1.11b": "0x6FA21C25"
      },
      "rvas": {
        "LoD/1.11": "0x1C25",
        "LoD/1.11b": "0x1C25"
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
    "d2mcpclient.dll___ioinit": {
      "addresses": {
        "LoD/1.11": "0x6FA21CE0",
        "LoD/1.11b": "0x6FA21CE0",
        "LoD/1.12a": "0x6FA21CFC",
        "LoD/1.13c": "0x6FA21CFC",
        "LoD/1.13d": "0x6FA2201C"
      },
      "rvas": {
        "LoD/1.11": "0x1CE0",
        "LoD/1.11b": "0x1CE0",
        "LoD/1.12a": "0x1CFC",
        "LoD/1.13c": "0x1CFC",
        "LoD/1.13d": "0x201C"
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
    "d2mcpclient.dll___ioterm": {
      "addresses": {
        "LoD/1.11": "0x6FA21EDE",
        "LoD/1.11b": "0x6FA21EDE",
        "LoD/1.12a": "0x6FA21EFA",
        "LoD/1.13c": "0x6FA21EFA",
        "LoD/1.13d": "0x6FA2221A"
      },
      "rvas": {
        "LoD/1.11": "0x1EDE",
        "LoD/1.11b": "0x1EDE",
        "LoD/1.12a": "0x1EFA",
        "LoD/1.13c": "0x1EFA",
        "LoD/1.13d": "0x221A"
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
    "d2mcpclient.dll___setenvp": {
      "addresses": {
        "LoD/1.11": "0x6FA21F2A",
        "LoD/1.11b": "0x6FA21F2A",
        "LoD/1.12a": "0x6FA21F46",
        "LoD/1.13c": "0x6FA21F46",
        "LoD/1.13d": "0x6FA22266"
      },
      "rvas": {
        "LoD/1.11": "0x1F2A",
        "LoD/1.11b": "0x1F2A",
        "LoD/1.12a": "0x1F46",
        "LoD/1.13c": "0x1F46",
        "LoD/1.13d": "0x2266"
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
    "d2mcpclient.dll_ParseCommandLine": {
      "addresses": {
        "LoD/1.11": "0x6FA21FF1",
        "LoD/1.11b": "0x6FA21FF1",
        "LoD/1.12a": "0x6FA2200D",
        "LoD/1.13c": "0x6FA2200D",
        "LoD/1.13d": "0x6FA2232D"
      },
      "rvas": {
        "LoD/1.11": "0x1FF1",
        "LoD/1.11b": "0x1FF1",
        "LoD/1.12a": "0x200D",
        "LoD/1.13c": "0x200D",
        "LoD/1.13d": "0x232D"
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
    "d2mcpclient.dll___setargv": {
      "addresses": {
        "LoD/1.11": "0x6FA2215D",
        "LoD/1.11b": "0x6FA2215D",
        "LoD/1.12a": "0x6FA22179",
        "LoD/1.13c": "0x6FA22179",
        "LoD/1.13d": "0x6FA22499"
      },
      "rvas": {
        "LoD/1.11": "0x215D",
        "LoD/1.11b": "0x215D",
        "LoD/1.12a": "0x2179",
        "LoD/1.13c": "0x2179",
        "LoD/1.13d": "0x2499"
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
    "d2mcpclient.dll____crtGetEnvironmentStringsA": {
      "addresses": {
        "LoD/1.11": "0x6FA221FF",
        "LoD/1.11b": "0x6FA221FF",
        "LoD/1.12a": "0x6FA2221B",
        "LoD/1.13c": "0x6FA2221B",
        "LoD/1.13d": "0x6FA2253B"
      },
      "rvas": {
        "LoD/1.11": "0x21FF",
        "LoD/1.11b": "0x21FF",
        "LoD/1.12a": "0x221B",
        "LoD/1.13c": "0x221B",
        "LoD/1.13d": "0x253B"
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
    "d2mcpclient.dll____heap_select": {
      "addresses": {
        "LoD/1.11": "0x6FA22321",
        "LoD/1.11b": "0x6FA22321",
        "LoD/1.12a": "0x6FA2233D",
        "LoD/1.13c": "0x6FA2233D",
        "LoD/1.13d": "0x6FA2265D"
      },
      "rvas": {
        "LoD/1.11": "0x2321",
        "LoD/1.11b": "0x2321",
        "LoD/1.12a": "0x233D",
        "LoD/1.13c": "0x233D",
        "LoD/1.13d": "0x265D"
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
    "d2mcpclient.dll___heap_init": {
      "addresses": {
        "LoD/1.11": "0x6FA2233B",
        "LoD/1.11b": "0x6FA2233B",
        "LoD/1.12a": "0x6FA22357",
        "LoD/1.13c": "0x6FA22357",
        "LoD/1.13d": "0x6FA22677"
      },
      "rvas": {
        "LoD/1.11": "0x233B",
        "LoD/1.11b": "0x233B",
        "LoD/1.12a": "0x2357",
        "LoD/1.13c": "0x2357",
        "LoD/1.13d": "0x2677"
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
    "d2mcpclient.dll___heap_term": {
      "addresses": {
        "LoD/1.11": "0x6FA2238C",
        "LoD/1.11b": "0x6FA2238C",
        "LoD/1.12a": "0x6FA223A8",
        "LoD/1.13c": "0x6FA223A8",
        "LoD/1.13d": "0x6FA226C8"
      },
      "rvas": {
        "LoD/1.11": "0x238C",
        "LoD/1.11b": "0x238C",
        "LoD/1.12a": "0x23A8",
        "LoD/1.13c": "0x23A8",
        "LoD/1.13d": "0x26C8"
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
    "d2mcpclient.dll___chkstk": {
      "addresses": {
        "LoD/1.11": "0x6FA22410",
        "LoD/1.11b": "0x6FA22410",
        "LoD/1.12a": "0x6FA22430",
        "LoD/1.13c": "0x6FA22430",
        "LoD/1.13d": "0x6FA22750"
      },
      "rvas": {
        "LoD/1.11": "0x2410",
        "LoD/1.11b": "0x2410",
        "LoD/1.12a": "0x2430",
        "LoD/1.13c": "0x2430",
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
    "d2mcpclient.dll___XcptFilter": {
      "addresses": {
        "LoD/1.11": "0x6FA2244D",
        "LoD/1.11b": "0x6FA2244D",
        "LoD/1.12a": "0x6FA2246D",
        "LoD/1.13c": "0x6FA2246D",
        "LoD/1.13d": "0x6FA2278D"
      },
      "rvas": {
        "LoD/1.11": "0x244D",
        "LoD/1.11b": "0x244D",
        "LoD/1.12a": "0x246D",
        "LoD/1.13c": "0x246D",
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
    "d2mcpclient.dll_FilterCppException": {
      "addresses": {
        "LoD/1.11": "0x6FA225B1",
        "LoD/1.11b": "0x6FA225B1",
        "LoD/1.12a": "0x6FA225D1",
        "LoD/1.13c": "0x6FA225D1",
        "LoD/1.13d": "0x6FA228F1"
      },
      "rvas": {
        "LoD/1.11": "0x25B1",
        "LoD/1.11b": "0x25B1",
        "LoD/1.12a": "0x25D1",
        "LoD/1.13c": "0x25D1",
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
    "d2mcpclient.dll____crtInitCritSecNoSpinCount@8": {
      "addresses": {
        "LoD/1.11": "0x6FA2277C",
        "LoD/1.11b": "0x6FA2277C",
        "LoD/1.12a": "0x6FA2279D",
        "LoD/1.13c": "0x6FA2279D",
        "LoD/1.13d": "0x6FA22ABC"
      },
      "rvas": {
        "LoD/1.11": "0x277C",
        "LoD/1.11b": "0x277C",
        "LoD/1.12a": "0x279D",
        "LoD/1.13c": "0x279D",
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
    "d2mcpclient.dll____crtInitCritSecAndSpinCount": {
      "addresses": {
        "LoD/1.11": "0x6FA2278C",
        "LoD/1.11b": "0x6FA2278C",
        "LoD/1.12a": "0x6FA227AD",
        "LoD/1.13c": "0x6FA227AD",
        "LoD/1.13d": "0x6FA22ACC"
      },
      "rvas": {
        "LoD/1.11": "0x278C",
        "LoD/1.11b": "0x278C",
        "LoD/1.12a": "0x27AD",
        "LoD/1.13c": "0x27AD",
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
    "d2mcpclient.dll_AllocateMemoryWithCache": {
      "addresses": {
        "LoD/1.11": "0x6FA22820",
        "LoD/1.11b": "0x6FA22820",
        "LoD/1.12a": "0x6FA22841",
        "LoD/1.13c": "0x6FA22841",
        "LoD/1.13d": "0x6FA22B60"
      },
      "rvas": {
        "LoD/1.11": "0x2820",
        "LoD/1.11b": "0x2820",
        "LoD/1.12a": "0x2841",
        "LoD/1.13c": "0x2841",
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
    "d2mcpclient.dll__realloc": {
      "addresses": {
        "LoD/1.11": "0x6FA229CA",
        "LoD/1.11b": "0x6FA229CA"
      },
      "rvas": {
        "LoD/1.11": "0x29CA",
        "LoD/1.11b": "0x29CA"
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
    "d2mcpclient.dll_LeaveCriticalSectionForMemoryF": {
      "addresses": {
        "LoD/1.11": "0x6FA22B32",
        "LoD/1.11b": "0x6FA22B32",
        "LoD/1.12a": "0x6FA22C09",
        "LoD/1.13c": "0x6FA22C09",
        "LoD/1.13d": "0x6FA22E72"
      },
      "rvas": {
        "LoD/1.11": "0x2B32",
        "LoD/1.11b": "0x2B32",
        "LoD/1.12a": "0x2C09",
        "LoD/1.13c": "0x2C09",
        "LoD/1.13d": "0x2E72"
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
    "d2mcpclient.dll___msize": {
      "addresses": {
        "LoD/1.11": "0x6FA22B77",
        "LoD/1.11b": "0x6FA22B77",
        "LoD/1.12a": "0x6FA22B9C",
        "LoD/1.13c": "0x6FA22B9C",
        "LoD/1.13d": "0x6FA22EB7"
      },
      "rvas": {
        "LoD/1.11": "0x2B77",
        "LoD/1.11b": "0x2B77",
        "LoD/1.12a": "0x2B9C",
        "LoD/1.13c": "0x2B9C",
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
    "d2mcpclient.dll___ValidateEH3RN": {
      "addresses": {
        "LoD/1.11": "0x6FA22BED",
        "LoD/1.11b": "0x6FA22BED",
        "LoD/1.12a": "0x6FA22C12",
        "LoD/1.13c": "0x6FA22C12",
        "LoD/1.13d": "0x6FA22F2D"
      },
      "rvas": {
        "LoD/1.11": "0x2BED",
        "LoD/1.11b": "0x2BED",
        "LoD/1.12a": "0x2C12",
        "LoD/1.13c": "0x2C12",
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
    "d2mcpclient.dll____freetlocinfo": {
      "addresses": {
        "LoD/1.11": "0x6FA22E16",
        "LoD/1.11b": "0x6FA22E16",
        "LoD/1.12a": "0x6FA22E3B",
        "LoD/1.13c": "0x6FA22E3B",
        "LoD/1.13d": "0x6FA23156"
      },
      "rvas": {
        "LoD/1.11": "0x2E16",
        "LoD/1.11b": "0x2E16",
        "LoD/1.12a": "0x2E3B",
        "LoD/1.13c": "0x2E3B",
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
    "d2mcpclient.dll____updatetlocinfo_lk": {
      "addresses": {
        "LoD/1.11": "0x6FA22EE6",
        "LoD/1.11b": "0x6FA22EE6",
        "LoD/1.12a": "0x6FA22F0B",
        "LoD/1.13c": "0x6FA22F0B",
        "LoD/1.13d": "0x6FA23226"
      },
      "rvas": {
        "LoD/1.11": "0x2EE6",
        "LoD/1.11b": "0x2EE6",
        "LoD/1.12a": "0x2F0B",
        "LoD/1.13c": "0x2F0B",
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
    "d2mcpclient.dll____updatetlocinfo": {
      "addresses": {
        "LoD/1.11": "0x6FA22FA7",
        "LoD/1.11b": "0x6FA22FA7",
        "LoD/1.12a": "0x6FA22FCC",
        "LoD/1.13c": "0x6FA22FCC",
        "LoD/1.13d": "0x6FA232E7"
      },
      "rvas": {
        "LoD/1.11": "0x2FA7",
        "LoD/1.11b": "0x2FA7",
        "LoD/1.12a": "0x2FCC",
        "LoD/1.13c": "0x2FCC",
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
    "d2mcpclient.dll_UnlockCriticalSection12": {
      "addresses": {
        "LoD/1.11": "0x6FA22FD9",
        "LoD/1.11b": "0x6FA22FD9",
        "LoD/1.12a": "0x6FA22FFE",
        "LoD/1.13c": "0x6FA22FFE",
        "LoD/1.13d": "0x6FA23319"
      },
      "rvas": {
        "LoD/1.11": "0x2FD9",
        "LoD/1.11b": "0x2FD9",
        "LoD/1.12a": "0x2FFE",
        "LoD/1.13c": "0x2FFE",
        "LoD/1.13d": "0x3319"
      },
      "sizes": {
        "LoD/1.11": 9,
        "LoD/1.11b": 9,
        "LoD/1.12a": 9,
        "LoD/1.13c": 9,
        "LoD/1.13d": 9
      },
      "name": "UnlockCriticalSection12",
      "signature": "void UnlockCriticalSection12(void)",
      "calling_convention": "__stdcall",
      "comment": "Unlocks critical section 12 during thread-local info updates.\n\nAlgorithm:\n1. Push lock index constant 0xc (12) as argument\n2. Call LeaveCriticalSectionByIndex to release the lock\n3. Return to caller\n\nParameters:\nNone - wrapper stub with no parameters\n\nReturns:\nvoid - no return value\n\nSpecial Cases:\n- Lock index 12 (0xc) is hardcoded as a constant pushed directly\n- This is a Visual Studio runtime stub for thread-local storage management\n- Used exclusively by ___updatetlocinfo during thread-local info updates\n- Part of thread-safety infrastructure for runtime initialization",
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
    "d2mcpclient.dll_MapMessageIdToCommand": {
      "addresses": {
        "LoD/1.11": "0x6FA22FE2",
        "LoD/1.11b": "0x6FA22FE2",
        "LoD/1.12a": "0x6FA23007",
        "LoD/1.13c": "0x6FA23007",
        "LoD/1.13d": "0x6FA23322"
      },
      "rvas": {
        "LoD/1.11": "0x2FE2",
        "LoD/1.11b": "0x2FE2",
        "LoD/1.12a": "0x3007",
        "LoD/1.13c": "0x3007",
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
    "d2mcpclient.dll_setSBCS": {
      "addresses": {
        "LoD/1.11": "0x6FA23011",
        "LoD/1.11b": "0x6FA23011",
        "LoD/1.12a": "0x6FA23036",
        "LoD/1.13c": "0x6FA23036",
        "LoD/1.13d": "0x6FA23351"
      },
      "rvas": {
        "LoD/1.11": "0x3011",
        "LoD/1.11b": "0x3011",
        "LoD/1.12a": "0x3036",
        "LoD/1.13c": "0x3036",
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
    "d2mcpclient.dll_setSBUpLow": {
      "addresses": {
        "LoD/1.11": "0x6FA2303A",
        "LoD/1.11b": "0x6FA2303A"
      },
      "rvas": {
        "LoD/1.11": "0x303A",
        "LoD/1.11b": "0x303A"
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
    "d2mcpclient.dll___setmbcp_lk": {
      "addresses": {
        "LoD/1.11": "0x6FA231C6",
        "LoD/1.11b": "0x6FA231C6"
      },
      "rvas": {
        "LoD/1.11": "0x31C6",
        "LoD/1.11b": "0x31C6"
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
    "d2mcpclient.dll___setmbcp": {
      "addresses": {
        "LoD/1.11": "0x6FA23356",
        "LoD/1.11b": "0x6FA23356",
        "LoD/1.12a": "0x6FA2338E",
        "LoD/1.13c": "0x6FA2338E",
        "LoD/1.13d": "0x6FA23696"
      },
      "rvas": {
        "LoD/1.11": "0x3356",
        "LoD/1.11b": "0x3356",
        "LoD/1.12a": "0x338E",
        "LoD/1.13c": "0x338E",
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
    "d2mcpclient.dll____sbh_free_block": {
      "addresses": {
        "LoD/1.11": "0x6FA23537",
        "LoD/1.11b": "0x6FA23537",
        "LoD/1.12a": "0x6FA2356F",
        "LoD/1.13c": "0x6FA2356F",
        "LoD/1.13d": "0x6FA23877"
      },
      "rvas": {
        "LoD/1.11": "0x3537",
        "LoD/1.11b": "0x3537",
        "LoD/1.12a": "0x356F",
        "LoD/1.13c": "0x356F",
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
    "d2mcpclient.dll____sbh_alloc_new_region": {
      "addresses": {
        "LoD/1.11": "0x6FA2384F",
        "LoD/1.11b": "0x6FA2384F",
        "LoD/1.12a": "0x6FA23887",
        "LoD/1.13c": "0x6FA23887",
        "LoD/1.13d": "0x6FA23B8F"
      },
      "rvas": {
        "LoD/1.11": "0x384F",
        "LoD/1.11b": "0x384F",
        "LoD/1.12a": "0x3887",
        "LoD/1.13c": "0x3887",
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
    "d2mcpclient.dll____sbh_alloc_new_group": {
      "addresses": {
        "LoD/1.11": "0x6FA23906",
        "LoD/1.11b": "0x6FA23906",
        "LoD/1.12a": "0x6FA2393E",
        "LoD/1.13c": "0x6FA2393E",
        "LoD/1.13d": "0x6FA23C46"
      },
      "rvas": {
        "LoD/1.11": "0x3906",
        "LoD/1.11b": "0x3906",
        "LoD/1.12a": "0x393E",
        "LoD/1.13c": "0x393E",
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
    "d2mcpclient.dll____sbh_resize_block": {
      "addresses": {
        "LoD/1.11": "0x6FA23A0C",
        "LoD/1.11b": "0x6FA23A0C",
        "LoD/1.12a": "0x6FA23A44",
        "LoD/1.13c": "0x6FA23A44",
        "LoD/1.13d": "0x6FA23D4C"
      },
      "rvas": {
        "LoD/1.11": "0x3A0C",
        "LoD/1.11b": "0x3A0C",
        "LoD/1.12a": "0x3A44",
        "LoD/1.13c": "0x3A44",
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
    "d2mcpclient.dll____sbh_alloc_block": {
      "addresses": {
        "LoD/1.11": "0x6FA23CEB",
        "LoD/1.11b": "0x6FA23CEB",
        "LoD/1.12a": "0x6FA23D23",
        "LoD/1.13c": "0x6FA23D23",
        "LoD/1.13d": "0x6FA2402B"
      },
      "rvas": {
        "LoD/1.11": "0x3CEB",
        "LoD/1.11b": "0x3CEB",
        "LoD/1.12a": "0x3D23",
        "LoD/1.13c": "0x3D23",
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
    "d2mcpclient.dll_StringConcatenate": {
      "addresses": {
        "LoD/1.11": "0x6FA24080",
        "LoD/1.11b": "0x6FA24080",
        "LoD/1.12a": "0x6FA240B0",
        "LoD/1.13c": "0x6FA240B0",
        "LoD/1.13d": "0x6FA243C0"
      },
      "rvas": {
        "LoD/1.11": "0x4080",
        "LoD/1.11b": "0x4080",
        "LoD/1.12a": "0x40B0",
        "LoD/1.13c": "0x40B0",
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
    "d2mcpclient.dll__memmove": {
      "addresses": {
        "LoD/1.11": "0x6FA24200",
        "LoD/1.11b": "0x6FA24200",
        "LoD/1.12a": "0x6FA24230",
        "LoD/1.13c": "0x6FA24230",
        "LoD/1.13d": "0x6FA24540"
      },
      "rvas": {
        "LoD/1.11": "0x4200",
        "LoD/1.11b": "0x4200",
        "LoD/1.12a": "0x4230",
        "LoD/1.13c": "0x4230",
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
    "d2mcpclient.dll____crtMessageBoxA": {
      "addresses": {
        "LoD/1.11": "0x6FA2453D",
        "LoD/1.11b": "0x6FA2453D",
        "LoD/1.12a": "0x6FA2456D",
        "LoD/1.13c": "0x6FA2456D",
        "LoD/1.13d": "0x6FA2487D"
      },
      "rvas": {
        "LoD/1.11": "0x453D",
        "LoD/1.11b": "0x453D",
        "LoD/1.12a": "0x456D",
        "LoD/1.13c": "0x456D",
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
    "d2mcpclient.dll_ReportSecurityFailure": {
      "addresses": {
        "LoD/1.11": "0x6FA24764",
        "LoD/1.11b": "0x6FA24764",
        "LoD/1.12a": "0x6FA24794",
        "LoD/1.13c": "0x6FA24794",
        "LoD/1.13d": "0x6FA24AA4"
      },
      "rvas": {
        "LoD/1.11": "0x4764",
        "LoD/1.11b": "0x4764",
        "LoD/1.12a": "0x4794",
        "LoD/1.13c": "0x4794",
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
    "d2mcpclient.dll_VerifyStackCanary": {
      "addresses": {
        "LoD/1.11": "0x6FA24795",
        "LoD/1.11b": "0x6FA24795",
        "LoD/1.12a": "0x6FA247C5",
        "LoD/1.13c": "0x6FA247C5",
        "LoD/1.13d": "0x6FA24AD5"
      },
      "rvas": {
        "LoD/1.11": "0x4795",
        "LoD/1.11b": "0x4795",
        "LoD/1.12a": "0x47C5",
        "LoD/1.13c": "0x47C5",
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
    "d2mcpclient.dll____free_lc_time": {
      "addresses": {
        "LoD/1.11": "0x6FA247A3",
        "LoD/1.11b": "0x6FA247A3",
        "LoD/1.12a": "0x6FA247D3",
        "LoD/1.13c": "0x6FA247D3",
        "LoD/1.13d": "0x6FA24AE3"
      },
      "rvas": {
        "LoD/1.11": "0x47A3",
        "LoD/1.11b": "0x47A3",
        "LoD/1.12a": "0x47D3",
        "LoD/1.13c": "0x47D3",
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
    "d2mcpclient.dll____free_lconv_num": {
      "addresses": {
        "LoD/1.11": "0x6FA24933",
        "LoD/1.11b": "0x6FA24933",
        "LoD/1.12a": "0x6FA24963",
        "LoD/1.13c": "0x6FA24963",
        "LoD/1.13d": "0x6FA24C73"
      },
      "rvas": {
        "LoD/1.11": "0x4933",
        "LoD/1.11b": "0x4933",
        "LoD/1.12a": "0x4963",
        "LoD/1.13c": "0x4963",
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
    "d2mcpclient.dll____free_lconv_mon": {
      "addresses": {
        "LoD/1.11": "0x6FA24992",
        "LoD/1.11b": "0x6FA24992",
        "LoD/1.12a": "0x6FA249C2",
        "LoD/1.13c": "0x6FA249C2",
        "LoD/1.13d": "0x6FA24CD2"
      },
      "rvas": {
        "LoD/1.11": "0x4992",
        "LoD/1.11b": "0x4992",
        "LoD/1.12a": "0x49C2",
        "LoD/1.13c": "0x49C2",
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
    "d2mcpclient.dll__strcspn": {
      "addresses": {
        "LoD/1.11": "0x6FA24A70",
        "LoD/1.11b": "0x6FA24A70",
        "LoD/1.12a": "0x6FA24AA0",
        "LoD/1.13c": "0x6FA24AA0",
        "LoD/1.13d": "0x6FA24DB0"
      },
      "rvas": {
        "LoD/1.11": "0x4A70",
        "LoD/1.11b": "0x4A70",
        "LoD/1.12a": "0x4AA0",
        "LoD/1.13c": "0x4AA0",
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
    "d2mcpclient.dll__strcmp": {
      "addresses": {
        "LoD/1.11": "0x6FA24AC0",
        "LoD/1.11b": "0x6FA24AC0",
        "LoD/1.12a": "0x6FA24AF0",
        "LoD/1.13c": "0x6FA24AF0",
        "LoD/1.13d": "0x6FA24E00"
      },
      "rvas": {
        "LoD/1.11": "0x4AC0",
        "LoD/1.11b": "0x4AC0",
        "LoD/1.12a": "0x4AF0",
        "LoD/1.13c": "0x4AF0",
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
    "d2mcpclient.dll__memcmp": {
      "addresses": {
        "LoD/1.11": "0x6FA24B50",
        "LoD/1.11b": "0x6FA24B50",
        "LoD/1.12a": "0x6FA24B80",
        "LoD/1.13c": "0x6FA24B80",
        "LoD/1.13d": "0x6FA24E90"
      },
      "rvas": {
        "LoD/1.11": "0x4B50",
        "LoD/1.11b": "0x4B50",
        "LoD/1.12a": "0x4B80",
        "LoD/1.13c": "0x4B80",
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
    "d2mcpclient.dll____crtGetStringTypeA": {
      "addresses": {
        "LoD/1.11": "0x6FA24C08",
        "LoD/1.11b": "0x6FA24C08",
        "LoD/1.12a": "0x6FA24C38",
        "LoD/1.13c": "0x6FA24C38",
        "LoD/1.13d": "0x6FA24F48"
      },
      "rvas": {
        "LoD/1.11": "0x4C08",
        "LoD/1.11b": "0x4C08",
        "LoD/1.12a": "0x4C38",
        "LoD/1.13c": "0x4C38",
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
    "d2mcpclient.dll__strpbrk": {
      "addresses": {
        "LoD/1.11": "0x6FA24E10",
        "LoD/1.11b": "0x6FA24E10",
        "LoD/1.12a": "0x6FA24E40",
        "LoD/1.13c": "0x6FA24E40",
        "LoD/1.13d": "0x6FA25150"
      },
      "rvas": {
        "LoD/1.11": "0x4E10",
        "LoD/1.11b": "0x4E10",
        "LoD/1.12a": "0x4E40",
        "LoD/1.13c": "0x4E40",
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
    "d2mcpclient.dll____crtLCMapStringA": {
      "addresses": {
        "LoD/1.11": "0x6FA24E50",
        "LoD/1.11b": "0x6FA24E50"
      },
      "rvas": {
        "LoD/1.11": "0x4E50",
        "LoD/1.11b": "0x4E50"
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
    "d2mcpclient.dll__memmove_5210": {
      "addresses": {
        "LoD/1.11": "0x6FA25210",
        "LoD/1.11b": "0x6FA25210",
        "LoD/1.12a": "0x6FA25260",
        "LoD/1.13c": "0x6FA25260",
        "LoD/1.13d": "0x6FA21000"
      },
      "rvas": {
        "LoD/1.11": "0x5210",
        "LoD/1.11b": "0x5210",
        "LoD/1.12a": "0x5260",
        "LoD/1.13c": "0x5260",
        "LoD/1.13d": "0x1000"
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
    "d2mcpclient.dll____security_init_cookie": {
      "addresses": {
        "LoD/1.11": "0x6FA2554D",
        "LoD/1.11b": "0x6FA2554D",
        "LoD/1.12a": "0x6FA2559D",
        "LoD/1.13c": "0x6FA2559D",
        "LoD/1.13d": "0x6FA2554C"
      },
      "rvas": {
        "LoD/1.11": "0x554D",
        "LoD/1.11b": "0x554D",
        "LoD/1.12a": "0x559D",
        "LoD/1.13c": "0x559D",
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
    "d2mcpclient.dll____security_error_handler": {
      "addresses": {
        "LoD/1.11": "0x6FA255B3",
        "LoD/1.11b": "0x6FA255B3",
        "LoD/1.12a": "0x6FA25603",
        "LoD/1.13c": "0x6FA25603",
        "LoD/1.13d": "0x6FA255B2"
      },
      "rvas": {
        "LoD/1.11": "0x55B3",
        "LoD/1.11b": "0x55B3",
        "LoD/1.12a": "0x5603",
        "LoD/1.13c": "0x5603",
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
    "d2mcpclient.dll____ascii_stricmp": {
      "addresses": {
        "LoD/1.11": "0x6FA25700",
        "LoD/1.11b": "0x6FA25700",
        "LoD/1.12a": "0x6FA25750",
        "LoD/1.13c": "0x6FA25750",
        "LoD/1.13d": "0x6FA25700"
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
    "d2mcpclient.dll___resetstkoflw": {
      "addresses": {
        "LoD/1.11": "0x6FA2574E",
        "LoD/1.11b": "0x6FA2574E",
        "LoD/1.12a": "0x6FA2579E",
        "LoD/1.13c": "0x6FA2579E",
        "LoD/1.13d": "0x6FA2574E"
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
    "d2mcpclient.dll__atol": {
      "addresses": {
        "LoD/1.11": "0x6FA25831",
        "LoD/1.11b": "0x6FA25831",
        "LoD/1.12a": "0x6FA25881",
        "LoD/1.13c": "0x6FA25881",
        "LoD/1.13d": "0x6FA25831"
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
    "d2mcpclient.dll____ansicp": {
      "addresses": {
        "LoD/1.11": "0x6FA258B9",
        "LoD/1.11b": "0x6FA258B9"
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
    "d2mcpclient.dll____convertcp": {
      "addresses": {
        "LoD/1.11": "0x6FA258FC",
        "LoD/1.11b": "0x6FA258FC"
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
    "d2mcpclient.dll____isctype_mt": {
      "addresses": {
        "LoD/1.11": "0x6FA25AC5",
        "LoD/1.11b": "0x6FA25AC5",
        "LoD/1.12a": "0x6FA25B2A",
        "LoD/1.13c": "0x6FA25B2A",
        "LoD/1.13d": "0x6FA25AC5"
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
    "d2mcpclient.dll___allmul": {
      "addresses": {
        "LoD/1.11": "0x6FA25B40",
        "LoD/1.11b": "0x6FA25B40",
        "LoD/1.12a": "0x6FA25BB0",
        "LoD/1.13c": "0x6FA25BB0",
        "LoD/1.13d": "0x6FA25B40"
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
    "d2mcpclient.dll____ascii_strnicmp": {
      "addresses": {
        "LoD/1.11": "0x6FA25B80",
        "LoD/1.11b": "0x6FA25B80",
        "LoD/1.12a": "0x6FA25BF0",
        "LoD/1.13c": "0x6FA25BF0",
        "LoD/1.13d": "0x6FA25B80"
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
    "d2mcpclient.dll___aulldvrm": {
      "addresses": {
        "LoD/1.11": "0x6FA25BF0",
        "LoD/1.11b": "0x6FA25BF0",
        "LoD/1.12a": "0x6FA25C60",
        "LoD/1.13c": "0x6FA25C60",
        "LoD/1.13d": "0x6FA25BF0"
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
    "d2mcpclient.dll_InitializeModule": {
      "addresses": {
        "LoD/1.11": "0x6FA25DAC",
        "LoD/1.11b": "0x6FA25DAC",
        "LoD/1.12a": "0x6FA25E10",
        "LoD/1.13c": "0x6FA25E1C",
        "LoD/1.13d": "0x6FA25DAC"
      },
      "rvas": {
        "LoD/1.11": "0x5DAC",
        "LoD/1.11b": "0x5DAC",
        "LoD/1.12a": "0x5E10",
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
      "name": "InitializeModule",
      "signature": "int InitializeModule(void)",
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
    "d2mcpclient.dll_EXP_10050_5DD0": {
      "addresses": {
        "LoD/1.11": "0x6FA25DD0",
        "LoD/1.11b": "0x6FA26570",
        "LoD/1.12a": "0x6FA26F30",
        "LoD/1.13c": "0x6FA265D0",
        "LoD/1.13d": "0x6FA25DE0"
      },
      "rvas": {
        "LoD/1.11": "0x5DD0",
        "LoD/1.11b": "0x6570",
        "LoD/1.12a": "0x6F30",
        "LoD/1.13c": "0x65D0",
        "LoD/1.13d": "0x5DE0"
      },
      "sizes": {
        "LoD/1.11": 308,
        "LoD/1.11b": 308,
        "LoD/1.12a": 308,
        "LoD/1.13c": 308,
        "LoD/1.13d": 308
      },
      "name": "Ordinal_10050",
      "signature": "undefined Ordinal_10050(char * param_1, uint param_2)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.11",
      "method": "EXP",
      "index": "EXP:10050",
      "callees": {
        "LoD/1.11": [
          "InitializeModule",
          "Ordinal_10042",
          "GetReturnAddress",
          "CleanupAndAbort"
        ],
        "LoD/1.11b": [
          "InitializeModule",
          "AllocateMemoryWithTracking",
          "GetReturnAddress",
          "CleanupAndAbort"
        ],
        "LoD/1.12a": [
          "InitializeModule",
          "AllocateMemoryWithTracking",
          "GetReturnAddress",
          "CleanupAndAbort"
        ],
        "LoD/1.13c": [
          "InitializeModule",
          "AllocateMemoryWithTracking",
          "GetReturnAddress",
          "CleanupAndAbort"
        ],
        "LoD/1.13d": [
          "InitializeModule",
          "AllocateMemoryWithTracking",
          "GetReturnAddress",
          "CleanupAndAbort"
        ]
      },
      "strings": {
        "LoD/1.11": [
          "\"..\\\\Source\\\\D2MCPClient\\\\Src\\\\McpConnect.cpp\""
        ],
        "LoD/1.11b": [
          "\"..\\\\Source\\\\D2MCPClient\\\\Src\\\\McpConnect.cpp\""
        ],
        "LoD/1.12a": [
          "\"..\\\\Source\\\\D2MCPClient\\\\Src\\\\McpConnect.cpp\""
        ],
        "LoD/1.13c": [
          "\"..\\\\Source\\\\D2MCPClient\\\\Src\\\\McpConnect.cpp\""
        ],
        "LoD/1.13d": [
          "\"..\\\\Source\\\\D2MCPClient\\\\Src\\\\McpConnect.cpp\""
        ]
      },
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
        "LoD/1.11": "1503ba58f2c2e8a4c2a25e871b10f891",
        "LoD/1.11b": "1503ba58f2c2e8a4c2a25e871b10f891",
        "LoD/1.12a": "1503ba58f2c2e8a4c2a25e871b10f891",
        "LoD/1.13c": "1503ba58f2c2e8a4c2a25e871b10f891",
        "LoD/1.13d": "1503ba58f2c2e8a4c2a25e871b10f891"
      }
    },
    "d2mcpclient.dll_EXP_10015_6000": {
      "addresses": {
        "LoD/1.11": "0x6FA26000",
        "LoD/1.11b": "0x6FA267A0",
        "LoD/1.12a": "0x6FA27160",
        "LoD/1.13c": "0x6FA26800",
        "LoD/1.13d": "0x6FA26010"
      },
      "rvas": {
        "LoD/1.11": "0x6000",
        "LoD/1.11b": "0x67A0",
        "LoD/1.12a": "0x7160",
        "LoD/1.13c": "0x6800",
        "LoD/1.13d": "0x6010"
      },
      "sizes": {
        "LoD/1.11": 56,
        "LoD/1.11b": 56,
        "LoD/1.12a": 56,
        "LoD/1.13c": 56,
        "LoD/1.13d": 56
      },
      "name": "Ordinal_10015",
      "signature": "undefined Ordinal_10015(undefined4 param_1, char * param_2, char * param_3)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.11",
      "method": "EXP",
      "index": "EXP:10015",
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
        "LoD/1.11": "71702cb0060b633b906652bf511194ad",
        "LoD/1.11b": "71702cb0060b633b906652bf511194ad",
        "LoD/1.12a": "71702cb0060b633b906652bf511194ad",
        "LoD/1.13c": "71702cb0060b633b906652bf511194ad",
        "LoD/1.13d": "71702cb0060b633b906652bf511194ad"
      }
    },
    "d2mcpclient.dll_SetErrorHandlingDisabled": {
      "addresses": {
        "LoD/1.11": "0x6FA260B0",
        "LoD/1.11b": "0x6FA26850",
        "LoD/1.12a": "0x6FA27210",
        "LoD/1.13c": "0x6FA268B0",
        "LoD/1.13d": "0x6FA25FC0"
      },
      "rvas": {
        "LoD/1.11": "0x60B0",
        "LoD/1.11b": "0x6850",
        "LoD/1.12a": "0x7210",
        "LoD/1.13c": "0x68B0",
        "LoD/1.13d": "0x5FC0"
      },
      "sizes": {
        "LoD/1.11": 12,
        "LoD/1.11b": 12,
        "LoD/1.12a": 12,
        "LoD/1.13c": 12,
        "LoD/1.13d": 12
      },
      "name": "SetErrorHandlingDisabled",
      "signature": "void SetErrorHandlingDisabled(uint dwDisable)",
      "calling_convention": "__stdcall",
      "comment": "Sets the error handling disabled flag.\n\nAlgorithm:\n1. Store dwDisable value to g_fErrorHandlingDisabled global\n\nWhen enabled (dwDisable != 0), DisplayCriticalError returns\nimmediately without showing dialogs or terminating the process.\nCalled with 1 during process termination in DisplayCriticalError.\n\nParameters:\n- dwDisable (uint): Non-zero to disable error handling\n\nReturns:\n- void",
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:0f26f5ebbb6562741331dd6e6bdd0342",
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
        "LoD/1.11": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.11b": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.12a": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.13c": "0f26f5ebbb6562741331dd6e6bdd0342",
        "LoD/1.13d": "0f26f5ebbb6562741331dd6e6bdd0342"
      }
    },
    "d2mcpclient.dll_EXP_10017_6190": {
      "addresses": {
        "LoD/1.11": "0x6FA26190",
        "LoD/1.11b": "0x6FA26990",
        "LoD/1.12a": "0x6FA25FD0",
        "LoD/1.13c": "0x6FA27230",
        "LoD/1.13d": "0x6FA26A40"
      },
      "rvas": {
        "LoD/1.11": "0x6190",
        "LoD/1.11b": "0x6990",
        "LoD/1.12a": "0x5FD0",
        "LoD/1.13c": "0x7230",
        "LoD/1.13d": "0x6A40"
      },
      "sizes": {
        "LoD/1.11": 49,
        "LoD/1.11b": 49,
        "LoD/1.12a": 46,
        "LoD/1.13c": 93,
        "LoD/1.13d": 93
      },
      "name": "Ordinal_10017",
      "signature": "undefined Ordinal_10017(void)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.11",
      "method": "EXP",
      "index": "EXP:10017",
      "callees": {
        "LoD/1.11": [
          "GetField0x110",
          "Ordinal_10012"
        ],
        "LoD/1.11b": [
          "GetField0x110",
          "Ordinal_10012"
        ],
        "LoD/1.12a": [
          "EncodeBufferWithContext"
        ],
        "LoD/1.13c": [
          "EncodeBufferWithContext"
        ],
        "LoD/1.13d": [
          "EncodeBufferWithContext"
        ]
      },
      "basic_block_counts": {
        "LoD/1.11": 3,
        "LoD/1.11b": 3,
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
        "LoD/1.11": "76e08142858bd44edddd131220046bd1",
        "LoD/1.11b": "76e08142858bd44edddd131220046bd1",
        "LoD/1.12a": "8cf6081513f31f17087d887ea495c3ca",
        "LoD/1.13c": "e1e6665f63af39e13482dd75650e8ebc",
        "LoD/1.13d": "e1e6665f63af39e13482dd75650e8ebc"
      }
    },
    "d2mcpclient.dll_EXP_10057_61D0": {
      "addresses": {
        "LoD/1.11": "0x6FA261D0",
        "LoD/1.11b": "0x6FA271D0",
        "LoD/1.12a": "0x6FA25F30",
        "LoD/1.13c": "0x6FA26CB0",
        "LoD/1.13d": "0x6FA264C0"
      },
      "rvas": {
        "LoD/1.11": "0x61D0",
        "LoD/1.11b": "0x71D0",
        "LoD/1.12a": "0x5F30",
        "LoD/1.13c": "0x6CB0",
        "LoD/1.13d": "0x64C0"
      },
      "sizes": {
        "LoD/1.11": 92,
        "LoD/1.11b": 93,
        "LoD/1.12a": 49,
        "LoD/1.13c": 49,
        "LoD/1.13d": 49
      },
      "name": "Ordinal_10057",
      "signature": "undefined Ordinal_10057(void)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.11",
      "method": "EXP",
      "index": "EXP:10057",
      "callees": {
        "LoD/1.11": [
          "Ordinal_10069"
        ],
        "LoD/1.11b": [
          "Ordinal_10070"
        ],
        "LoD/1.12a": [
          "EncodeBufferWithContext"
        ],
        "LoD/1.13c": [
          "EncodeBufferWithContext"
        ],
        "LoD/1.13d": [
          "EncodeBufferWithContext"
        ]
      },
      "basic_block_counts": {
        "LoD/1.11": 7,
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
        "LoD/1.11": "93ad0a806324402857b0c67ebe3a594f",
        "LoD/1.11b": "e1e6665f63af39e13482dd75650e8ebc",
        "LoD/1.12a": "4279ccfee5b4a0c14e808a53f9c93ba5",
        "LoD/1.13c": "4279ccfee5b4a0c14e808a53f9c93ba5",
        "LoD/1.13d": "4279ccfee5b4a0c14e808a53f9c93ba5"
      }
    },
    "d2mcpclient.dll_EXP_10045_62B0": {
      "addresses": {
        "LoD/1.11": "0x6FA262B0",
        "LoD/1.11b": "0x6FA26A50",
        "LoD/1.12a": "0x6FA27410",
        "LoD/1.13c": "0x6FA26AB0",
        "LoD/1.13d": "0x6FA262C0"
      },
      "rvas": {
        "LoD/1.11": "0x62B0",
        "LoD/1.11b": "0x6A50",
        "LoD/1.12a": "0x7410",
        "LoD/1.13c": "0x6AB0",
        "LoD/1.13d": "0x62C0"
      },
      "sizes": {
        "LoD/1.11": 22,
        "LoD/1.11b": 22,
        "LoD/1.12a": 22,
        "LoD/1.13c": 22,
        "LoD/1.13d": 22
      },
      "name": "Ordinal_10045",
      "signature": "undefined Ordinal_10045(char * param_1, undefined4 param_2)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.11",
      "method": "EXP",
      "index": "EXP:10045",
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
        "LoD/1.11": "20fa0a1b4bf10db53d482912bd0b3fe7",
        "LoD/1.11b": "20fa0a1b4bf10db53d482912bd0b3fe7",
        "LoD/1.12a": "20fa0a1b4bf10db53d482912bd0b3fe7",
        "LoD/1.13c": "20fa0a1b4bf10db53d482912bd0b3fe7",
        "LoD/1.13d": "20fa0a1b4bf10db53d482912bd0b3fe7"
      }
    },
    "d2mcpclient.dll_API_505ef52f6007": {
      "addresses": {
        "LoD/1.11": "0x6FA262D0",
        "LoD/1.11b": "0x6FA26A70",
        "LoD/1.12a": "0x6FA27430",
        "LoD/1.13c": "0x6FA26AD0",
        "LoD/1.13d": "0x6FA262E0"
      },
      "rvas": {
        "LoD/1.11": "0x62D0",
        "LoD/1.11b": "0x6A70",
        "LoD/1.12a": "0x7430",
        "LoD/1.13c": "0x6AD0",
        "LoD/1.13d": "0x62E0"
      },
      "sizes": {
        "LoD/1.11": 196,
        "LoD/1.11b": 196,
        "LoD/1.12a": 196,
        "LoD/1.13c": 196,
        "LoD/1.13d": 196
      },
      "name_source": "LoD/1.11",
      "method": "API",
      "index": "API:505ef52f6007dceacf0b603b3184876b",
      "callees": {
        "LoD/1.11": [
          "GetField0x110",
          "Ordinal_10012"
        ],
        "LoD/1.11b": [
          "GetField0x110",
          "Ordinal_10012"
        ],
        "LoD/1.12a": [
          "GetField0x110",
          "GetPeerSocketAddress"
        ],
        "LoD/1.13c": [
          "GetField0x110",
          "GetPeerSocketAddress"
        ],
        "LoD/1.13d": [
          "GetField0x110",
          "GetPeerSocketAddress"
        ]
      },
      "basic_block_counts": {
        "LoD/1.11": 13,
        "LoD/1.11b": 13,
        "LoD/1.12a": 13,
        "LoD/1.13c": 13,
        "LoD/1.13d": 13
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "8410422f634ddc993ddd52883e649a84",
        "LoD/1.11b": "8410422f634ddc993ddd52883e649a84",
        "LoD/1.12a": "8410422f634ddc993ddd52883e649a84",
        "LoD/1.13c": "8410422f634ddc993ddd52883e649a84",
        "LoD/1.13d": "8410422f634ddc993ddd52883e649a84"
      }
    },
    "d2mcpclient.dll_EXP_10012_6470": {
      "addresses": {
        "LoD/1.11": "0x6FA26470",
        "LoD/1.11b": "0x6FA26C10",
        "LoD/1.12a": "0x6FA275D0",
        "LoD/1.13c": "0x6FA26C70",
        "LoD/1.13d": "0x6FA26480"
      },
      "rvas": {
        "LoD/1.11": "0x6470",
        "LoD/1.11b": "0x6C10",
        "LoD/1.12a": "0x75D0",
        "LoD/1.13c": "0x6C70",
        "LoD/1.13d": "0x6480"
      },
      "sizes": {
        "LoD/1.11": 61,
        "LoD/1.11b": 61,
        "LoD/1.12a": 61,
        "LoD/1.13c": 61,
        "LoD/1.13d": 61
      },
      "name": "Ordinal_10012",
      "signature": "undefined Ordinal_10012(undefined4 * param_1)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.11",
      "method": "EXP",
      "index": "EXP:10012",
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
        "LoD/1.11": "cd8f01065d48c767738521c09b4c50fa",
        "LoD/1.11b": "cd8f01065d48c767738521c09b4c50fa",
        "LoD/1.12a": "cd8f01065d48c767738521c09b4c50fa",
        "LoD/1.13c": "cd8f01065d48c767738521c09b4c50fa",
        "LoD/1.13d": "cd8f01065d48c767738521c09b4c50fa"
      }
    },
    "d2mcpclient.dll_EXP_10035_6550": {
      "addresses": {
        "LoD/1.11": "0x6FA26550",
        "LoD/1.11b": "0x6FA26CF0"
      },
      "rvas": {
        "LoD/1.11": "0x6550",
        "LoD/1.11b": "0x6CF0"
      },
      "sizes": {
        "LoD/1.11": 46,
        "LoD/1.11b": 46
      },
      "name": "Ordinal_10035",
      "signature": "undefined Ordinal_10035(byte param_1, undefined2 param_2)",
      "calling_convention": "__fastcall",
      "name_source": "LoD/1.11",
      "method": "EXP",
      "index": "EXP:10035",
      "callees": {
        "LoD/1.11": [
          "Ordinal_10070"
        ],
        "LoD/1.11b": [
          "Ordinal_10070"
        ]
      },
      "basic_block_counts": {
        "LoD/1.11": 1,
        "LoD/1.11b": 1
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "8cf6081513f31f17087d887ea495c3ca",
        "LoD/1.11b": "8cf6081513f31f17087d887ea495c3ca"
      }
    },
    "d2mcpclient.dll_EXP_10053_65B0": {
      "addresses": {
        "LoD/1.11": "0x6FA265B0",
        "LoD/1.11b": "0x6FA26D20",
        "LoD/1.12a": "0x6FA25F70",
        "LoD/1.13c": "0x6FA26DB0",
        "LoD/1.13d": "0x6FA26530"
      },
      "rvas": {
        "LoD/1.11": "0x65B0",
        "LoD/1.11b": "0x6D20",
        "LoD/1.12a": "0x5F70",
        "LoD/1.13c": "0x6DB0",
        "LoD/1.13d": "0x6530"
      },
      "sizes": {
        "LoD/1.11": 37,
        "LoD/1.11b": 37,
        "LoD/1.12a": 37,
        "LoD/1.13c": 37,
        "LoD/1.13d": 37
      },
      "name": "Ordinal_10053",
      "signature": "undefined Ordinal_10053(void)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.11",
      "method": "EXP",
      "index": "EXP:10053",
      "callees": {
        "LoD/1.11": [
          "Ordinal_10070"
        ],
        "LoD/1.11b": [
          "Ordinal_10070"
        ],
        "LoD/1.12a": [
          "EncodeBufferWithContext"
        ],
        "LoD/1.13c": [
          "EncodeBufferWithContext"
        ],
        "LoD/1.13d": [
          "EncodeBufferWithContext"
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
        "LoD/1.11": "27cf70e216d5f82ac091c77f63637746",
        "LoD/1.11b": "27cf70e216d5f82ac091c77f63637746",
        "LoD/1.12a": "27cf70e216d5f82ac091c77f63637746",
        "LoD/1.13c": "27cf70e216d5f82ac091c77f63637746",
        "LoD/1.13d": "27cf70e216d5f82ac091c77f63637746"
      }
    },
    "d2mcpclient.dll_EXP_10009_65E0": {
      "addresses": {
        "LoD/1.11": "0x6FA265E0"
      },
      "rvas": {
        "LoD/1.11": "0x65E0"
      },
      "sizes": {
        "LoD/1.11": 37
      },
      "name": "Ordinal_10009",
      "signature": "undefined Ordinal_10009(void)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.11",
      "method": "EXP",
      "index": "EXP:10009",
      "callees": {
        "LoD/1.11": [
          "Ordinal_10070"
        ]
      },
      "basic_block_counts": {
        "LoD/1.11": 1
      },
      "loop_counts": {
        "LoD/1.11": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "27cf70e216d5f82ac091c77f63637746"
      }
    },
    "d2mcpclient.dll_EXP_10018_6610": {
      "addresses": {
        "LoD/1.11": "0x6FA26610",
        "LoD/1.11b": "0x6FA26DB0",
        "LoD/1.12a": "0x6FA26190",
        "LoD/1.13c": "0x6FA26E10",
        "LoD/1.13d": "0x6FA26620"
      },
      "rvas": {
        "LoD/1.11": "0x6610",
        "LoD/1.11b": "0x6DB0",
        "LoD/1.12a": "0x6190",
        "LoD/1.13c": "0x6E10",
        "LoD/1.13d": "0x6620"
      },
      "sizes": {
        "LoD/1.11": 74,
        "LoD/1.11b": 74,
        "LoD/1.12a": 74,
        "LoD/1.13c": 74,
        "LoD/1.13d": 74
      },
      "name": "Ordinal_10018",
      "signature": "undefined Ordinal_10018(byte * param_1)",
      "calling_convention": "__fastcall",
      "name_source": "LoD/1.11",
      "method": "EXP",
      "index": "EXP:10018",
      "callees": {
        "LoD/1.11": [
          "CopyMemoryAndDetectTerminator",
          "CalculateStringLength",
          "Ordinal_10070"
        ],
        "LoD/1.11b": [
          "CopyMemoryAndDetectTerminator",
          "CalculateStringLength",
          "Ordinal_10070"
        ],
        "LoD/1.12a": [
          "CopyMemoryAndDetectTerminator",
          "CalculateStringLength",
          "EncodeBufferWithContext"
        ],
        "LoD/1.13c": [
          "CopyMemoryAndDetectTerminator",
          "CalculateStringLength",
          "EncodeBufferWithContext"
        ],
        "LoD/1.13d": [
          "CopyMemoryAndDetectTerminator",
          "CalculateStringLength",
          "EncodeBufferWithContext"
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
        "LoD/1.11": "f45ae6b75ac9c3c7988c5676b9dea37b",
        "LoD/1.11b": "f45ae6b75ac9c3c7988c5676b9dea37b",
        "LoD/1.12a": "f45ae6b75ac9c3c7988c5676b9dea37b",
        "LoD/1.13c": "f45ae6b75ac9c3c7988c5676b9dea37b",
        "LoD/1.13d": "f45ae6b75ac9c3c7988c5676b9dea37b"
      }
    },
    "d2mcpclient.dll_API_c01fa6e1a170": {
      "addresses": {
        "LoD/1.11": "0x6FA266C0",
        "LoD/1.11b": "0x6FA26E60",
        "LoD/1.12a": "0x6FA25E40",
        "LoD/1.13c": "0x6FA26EC0",
        "LoD/1.13d": "0x6FA266D0"
      },
      "rvas": {
        "LoD/1.11": "0x66C0",
        "LoD/1.11b": "0x6E60",
        "LoD/1.12a": "0x5E40",
        "LoD/1.13c": "0x6EC0",
        "LoD/1.13d": "0x66D0"
      },
      "sizes": {
        "LoD/1.11": 86,
        "LoD/1.11b": 86,
        "LoD/1.12a": 86,
        "LoD/1.13c": 86,
        "LoD/1.13d": 86
      },
      "name_source": "LoD/1.11",
      "method": "API",
      "index": "API:c01fa6e1a170b59bdfbcc5c6da6138f7",
      "callees": {
        "LoD/1.11": [
          "GetReturnAddress",
          "CleanupAndAbort"
        ],
        "LoD/1.11b": [
          "GetReturnAddress",
          "CleanupAndAbort"
        ],
        "LoD/1.12a": [
          "GetReturnAddress",
          "CleanupAndAbort"
        ],
        "LoD/1.13c": [
          "GetReturnAddress",
          "CleanupAndAbort"
        ],
        "LoD/1.13d": [
          "GetReturnAddress",
          "CleanupAndAbort"
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
        "LoD/1.11": "239d0cdf1bf43138f685b3ffd49816fe",
        "LoD/1.11b": "239d0cdf1bf43138f685b3ffd49816fe",
        "LoD/1.12a": "239d0cdf1bf43138f685b3ffd49816fe",
        "LoD/1.13c": "239d0cdf1bf43138f685b3ffd49816fe",
        "LoD/1.13d": "239d0cdf1bf43138f685b3ffd49816fe"
      }
    },
    "d2mcpclient.dll_EXP_10036_6720": {
      "addresses": {
        "LoD/1.11": "0x6FA26720",
        "LoD/1.11b": "0x6FA26EC0",
        "LoD/1.12a": "0x6FA25EA0",
        "LoD/1.13c": "0x6FA26F20",
        "LoD/1.13d": "0x6FA26730"
      },
      "rvas": {
        "LoD/1.11": "0x6720",
        "LoD/1.11b": "0x6EC0",
        "LoD/1.12a": "0x5EA0",
        "LoD/1.13c": "0x6F20",
        "LoD/1.13d": "0x6730"
      },
      "sizes": {
        "LoD/1.11": 129,
        "LoD/1.11b": 129,
        "LoD/1.12a": 129,
        "LoD/1.13c": 129,
        "LoD/1.13d": 129
      },
      "name": "Ordinal_10036",
      "signature": "undefined Ordinal_10036(char * param_1, undefined4 param_2, undefined4 param_3)",
      "calling_convention": "__fastcall",
      "name_source": "LoD/1.11",
      "method": "EXP",
      "index": "EXP:10036",
      "callees": {
        "LoD/1.11": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "Ordinal_10070"
        ],
        "LoD/1.11b": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "Ordinal_10070"
        ],
        "LoD/1.12a": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "EncodeBufferWithContext"
        ],
        "LoD/1.13c": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "EncodeBufferWithContext"
        ],
        "LoD/1.13d": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "EncodeBufferWithContext"
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
        "LoD/1.11": "84101a4d4284e70a1041cc690a0213ed",
        "LoD/1.11b": "84101a4d4284e70a1041cc690a0213ed",
        "LoD/1.12a": "84101a4d4284e70a1041cc690a0213ed",
        "LoD/1.13c": "84101a4d4284e70a1041cc690a0213ed",
        "LoD/1.13d": "84101a4d4284e70a1041cc690a0213ed"
      }
    },
    "d2mcpclient.dll_BigIntTrimLeadingZerosAndCheck": {
      "addresses": {
        "LoD/1.11": "0x6FA26C10",
        "LoD/1.11b": "0x6FA273B0",
        "LoD/1.12a": "0x6FA265A0",
        "LoD/1.13c": "0x6FA27410",
        "LoD/1.13d": "0x6FA26C20"
      },
      "rvas": {
        "LoD/1.11": "0x6C10",
        "LoD/1.11b": "0x73B0",
        "LoD/1.12a": "0x65A0",
        "LoD/1.13c": "0x7410",
        "LoD/1.13d": "0x6C20"
      },
      "sizes": {
        "LoD/1.11": 110,
        "LoD/1.11b": 110,
        "LoD/1.12a": 110,
        "LoD/1.13c": 110,
        "LoD/1.13d": 110
      },
      "name": "BigIntTrimLeadingZerosAndCheckUnity",
      "signature": "undefined BigIntTrimLeadingZerosAndCheckUnity(char * param_1)",
      "calling_convention": "__fastcall",
      "name_source": "LoD/1.11",
      "method": "API",
      "index": "API:1b144bb219e9ca2a3de4614f720c4ba7",
      "callees": {
        "LoD/1.11": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "Ordinal_10070"
        ],
        "LoD/1.11b": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "Ordinal_10070"
        ],
        "LoD/1.12a": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "EncodeBufferWithContext"
        ],
        "LoD/1.13c": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "EncodeBufferWithContext"
        ],
        "LoD/1.13d": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "EncodeBufferWithContext"
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
        "LoD/1.11": "309c7651d80129250d0c2018c96c4c58",
        "LoD/1.11b": "309c7651d80129250d0c2018c96c4c58",
        "LoD/1.12a": "309c7651d80129250d0c2018c96c4c58",
        "LoD/1.13c": "309c7651d80129250d0c2018c96c4c58",
        "LoD/1.13d": "309c7651d80129250d0c2018c96c4c58"
      }
    },
    "d2mcpclient.dll_API_1b144bb219e9": {
      "addresses": {
        "LoD/1.11": "0x6FA26C80",
        "LoD/1.11b": "0x6FA27420",
        "LoD/1.12a": "0x6FA26610",
        "LoD/1.13c": "0x6FA27480",
        "LoD/1.13d": "0x6FA26C90"
      },
      "rvas": {
        "LoD/1.11": "0x6C80",
        "LoD/1.11b": "0x7420",
        "LoD/1.12a": "0x6610",
        "LoD/1.13c": "0x7480",
        "LoD/1.13d": "0x6C90"
      },
      "sizes": {
        "LoD/1.11": 138,
        "LoD/1.11b": 138,
        "LoD/1.12a": 138,
        "LoD/1.13c": 138,
        "LoD/1.13d": 138
      },
      "name_source": "LoD/1.11",
      "method": "API",
      "index": "API:1b144bb219e9ca2a3de4614f720c4ba7",
      "callees": {
        "LoD/1.11": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "Ordinal_10070"
        ],
        "LoD/1.11b": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "Ordinal_10070"
        ],
        "LoD/1.12a": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "EncodeBufferWithContext"
        ],
        "LoD/1.13c": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "EncodeBufferWithContext"
        ],
        "LoD/1.13d": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "EncodeBufferWithContext"
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
        "LoD/1.11": "c6a8021bd0567ccb9f8a08a0ad7fa22f",
        "LoD/1.11b": "c6a8021bd0567ccb9f8a08a0ad7fa22f",
        "LoD/1.12a": "c6a8021bd0567ccb9f8a08a0ad7fa22f",
        "LoD/1.13c": "c6a8021bd0567ccb9f8a08a0ad7fa22f",
        "LoD/1.13d": "c6a8021bd0567ccb9f8a08a0ad7fa22f"
      }
    },
    "d2mcpclient.dll_API_1b144bb219e9_6D10": {
      "addresses": {
        "LoD/1.11": "0x6FA26D10",
        "LoD/1.11b": "0x6FA274B0",
        "LoD/1.12a": "0x6FA266A0",
        "LoD/1.13c": "0x6FA27510",
        "LoD/1.13d": "0x6FA26D20"
      },
      "rvas": {
        "LoD/1.11": "0x6D10",
        "LoD/1.11b": "0x74B0",
        "LoD/1.12a": "0x66A0",
        "LoD/1.13c": "0x7510",
        "LoD/1.13d": "0x6D20"
      },
      "sizes": {
        "LoD/1.11": 226,
        "LoD/1.11b": 226,
        "LoD/1.12a": 226,
        "LoD/1.13c": 226,
        "LoD/1.13d": 226
      },
      "name_source": "LoD/1.11",
      "method": "API",
      "index": "API:1b144bb219e9ca2a3de4614f720c4ba7",
      "callees": {
        "LoD/1.11": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "Ordinal_10070"
        ],
        "LoD/1.11b": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "Ordinal_10070"
        ],
        "LoD/1.12a": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "EncodeBufferWithContext"
        ],
        "LoD/1.13c": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "EncodeBufferWithContext"
        ],
        "LoD/1.13d": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "EncodeBufferWithContext"
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
        "LoD/1.11": "d38fb128b2ee82654c680930cfe10026",
        "LoD/1.11b": "d38fb128b2ee82654c680930cfe10026",
        "LoD/1.12a": "d38fb128b2ee82654c680930cfe10026",
        "LoD/1.13c": "d38fb128b2ee82654c680930cfe10026",
        "LoD/1.13d": "d38fb128b2ee82654c680930cfe10026"
      }
    },
    "d2mcpclient.dll_MNE_33bf3b9f777a": {
      "addresses": {
        "LoD/1.11": "0x6FA26E40",
        "LoD/1.11b": "0x6FA25E20",
        "LoD/1.12a": "0x6FA267D0",
        "LoD/1.13c": "0x6FA25E80",
        "LoD/1.13d": "0x6FA26F00"
      },
      "rvas": {
        "LoD/1.11": "0x6E40",
        "LoD/1.11b": "0x5E20",
        "LoD/1.12a": "0x67D0",
        "LoD/1.13c": "0x5E80",
        "LoD/1.13d": "0x6F00"
      },
      "sizes": {
        "LoD/1.11": 45,
        "LoD/1.11b": 45,
        "LoD/1.12a": 45,
        "LoD/1.13c": 45,
        "LoD/1.13d": 45
      },
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:33bf3b9f777a0c0fe52bf59b2e5f28f5",
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
        "LoD/1.11": "33bf3b9f777a0c0fe52bf59b2e5f28f5",
        "LoD/1.11b": "33bf3b9f777a0c0fe52bf59b2e5f28f5",
        "LoD/1.12a": "33bf3b9f777a0c0fe52bf59b2e5f28f5",
        "LoD/1.13c": "33bf3b9f777a0c0fe52bf59b2e5f28f5",
        "LoD/1.13d": "33bf3b9f777a0c0fe52bf59b2e5f28f5"
      }
    },
    "d2mcpclient.dll_MNE_5c8fb64e115e": {
      "addresses": {
        "LoD/1.11": "0x6FA26E70",
        "LoD/1.11b": "0x6FA25E50",
        "LoD/1.12a": "0x6FA26800",
        "LoD/1.13c": "0x6FA25EB0",
        "LoD/1.13d": "0x6FA26F30"
      },
      "rvas": {
        "LoD/1.11": "0x6E70",
        "LoD/1.11b": "0x5E50",
        "LoD/1.12a": "0x6800",
        "LoD/1.13c": "0x5EB0",
        "LoD/1.13d": "0x6F30"
      },
      "sizes": {
        "LoD/1.11": 39,
        "LoD/1.11b": 39,
        "LoD/1.12a": 39,
        "LoD/1.13c": 39,
        "LoD/1.13d": 39
      },
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:5c8fb64e115ed90705890fa6136650f5",
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
        "LoD/1.11": "5c8fb64e115ed90705890fa6136650f5",
        "LoD/1.11b": "5c8fb64e115ed90705890fa6136650f5",
        "LoD/1.12a": "5c8fb64e115ed90705890fa6136650f5",
        "LoD/1.13c": "5c8fb64e115ed90705890fa6136650f5",
        "LoD/1.13d": "5c8fb64e115ed90705890fa6136650f5"
      }
    },
    "d2mcpclient.dll_MNE_a91afe2c7b8c_6EA0": {
      "addresses": {
        "LoD/1.11": "0x6FA26EA0",
        "LoD/1.11b": "0x6FA26050",
        "LoD/1.12a": "0x6FA26A10",
        "LoD/1.13c": "0x6FA260B0",
        "LoD/1.13d": "0x6FA26F60"
      },
      "rvas": {
        "LoD/1.11": "0x6EA0",
        "LoD/1.11b": "0x6050",
        "LoD/1.12a": "0x6A10",
        "LoD/1.13c": "0x60B0",
        "LoD/1.13d": "0x6F60"
      },
      "sizes": {
        "LoD/1.11": 13,
        "LoD/1.11b": 13,
        "LoD/1.12a": 13,
        "LoD/1.13c": 13,
        "LoD/1.13d": 13
      },
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:a91afe2c7b8cc0467b750e3c20af01b2",
      "callees": {
        "LoD/1.11": [
          "Ordinal_10050"
        ],
        "LoD/1.11b": [
          "Ordinal_10003"
        ],
        "LoD/1.12a": [
          "Ordinal_10049"
        ],
        "LoD/1.13c": [
          "Ordinal_10034"
        ],
        "LoD/1.13d": [
          "Ordinal_10010"
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
        "LoD/1.11": "a91afe2c7b8cc0467b750e3c20af01b2",
        "LoD/1.11b": "a91afe2c7b8cc0467b750e3c20af01b2",
        "LoD/1.12a": "a91afe2c7b8cc0467b750e3c20af01b2",
        "LoD/1.13c": "a91afe2c7b8cc0467b750e3c20af01b2",
        "LoD/1.13d": "a91afe2c7b8cc0467b750e3c20af01b2"
      }
    },
    "d2mcpclient.dll_MNE_6e7e0feb4b46": {
      "addresses": {
        "LoD/1.11": "0x6FA26EC0",
        "LoD/1.11b": "0x6FA26070",
        "LoD/1.12a": "0x6FA26A20",
        "LoD/1.13c": "0x6FA260D0",
        "LoD/1.13d": "0x6FA27650"
      },
      "rvas": {
        "LoD/1.11": "0x6EC0",
        "LoD/1.11b": "0x6070",
        "LoD/1.12a": "0x6A20",
        "LoD/1.13c": "0x60D0",
        "LoD/1.13d": "0x7650"
      },
      "sizes": {
        "LoD/1.11": 19,
        "LoD/1.11b": 19,
        "LoD/1.12a": 19,
        "LoD/1.13c": 19,
        "LoD/1.13d": 19
      },
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:6e7e0feb4b46a367301e751c476210ca",
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
        "LoD/1.11": "6e7e0feb4b46a367301e751c476210ca",
        "LoD/1.11b": "6e7e0feb4b46a367301e751c476210ca",
        "LoD/1.12a": "6e7e0feb4b46a367301e751c476210ca",
        "LoD/1.13c": "6e7e0feb4b46a367301e751c476210ca",
        "LoD/1.13d": "6e7e0feb4b46a367301e751c476210ca"
      }
    },
    "d2mcpclient.dll_MNE_95bf8a1d8c64": {
      "addresses": {
        "LoD/1.11": "0x6FA26EE0",
        "LoD/1.11b": "0x6FA25E80",
        "LoD/1.12a": "0x6FA26830",
        "LoD/1.13c": "0x6FA25EE0",
        "LoD/1.13d": "0x6FA26FA0"
      },
      "rvas": {
        "LoD/1.11": "0x6EE0",
        "LoD/1.11b": "0x5E80",
        "LoD/1.12a": "0x6830",
        "LoD/1.13c": "0x5EE0",
        "LoD/1.13d": "0x6FA0"
      },
      "sizes": {
        "LoD/1.11": 38,
        "LoD/1.11b": 38,
        "LoD/1.12a": 38,
        "LoD/1.13c": 38,
        "LoD/1.13d": 38
      },
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:95bf8a1d8c64d3366518d225902b65ad",
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
        "LoD/1.11": "95bf8a1d8c64d3366518d225902b65ad",
        "LoD/1.11b": "95bf8a1d8c64d3366518d225902b65ad",
        "LoD/1.12a": "95bf8a1d8c64d3366518d225902b65ad",
        "LoD/1.13c": "95bf8a1d8c64d3366518d225902b65ad",
        "LoD/1.13d": "95bf8a1d8c64d3366518d225902b65ad"
      }
    },
    "d2mcpclient.dll_MNE_79ca210bfeef": {
      "addresses": {
        "LoD/1.11": "0x6FA26F10",
        "LoD/1.11b": "0x6FA25EB0",
        "LoD/1.12a": "0x6FA26860",
        "LoD/1.13c": "0x6FA25F10",
        "LoD/1.13d": "0x6FA26FD0"
      },
      "rvas": {
        "LoD/1.11": "0x6F10",
        "LoD/1.11b": "0x5EB0",
        "LoD/1.12a": "0x6860",
        "LoD/1.13c": "0x5F10",
        "LoD/1.13d": "0x6FD0"
      },
      "sizes": {
        "LoD/1.11": 333,
        "LoD/1.11b": 333,
        "LoD/1.12a": 333,
        "LoD/1.13c": 333,
        "LoD/1.13d": 333
      },
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:79ca210bfeefe9d3ca773506e6cbcea9",
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
        "LoD/1.11": "79ca210bfeefe9d3ca773506e6cbcea9",
        "LoD/1.11b": "79ca210bfeefe9d3ca773506e6cbcea9",
        "LoD/1.12a": "79ca210bfeefe9d3ca773506e6cbcea9",
        "LoD/1.13c": "79ca210bfeefe9d3ca773506e6cbcea9",
        "LoD/1.13d": "79ca210bfeefe9d3ca773506e6cbcea9"
      }
    },
    "d2mcpclient.dll_API_1a41a9ae65ba": {
      "addresses": {
        "LoD/1.11": "0x6FA27060",
        "LoD/1.11b": "0x6FA26090",
        "LoD/1.12a": "0x6FA26A40",
        "LoD/1.13c": "0x6FA260F0",
        "LoD/1.13d": "0x6FA27120"
      },
      "rvas": {
        "LoD/1.11": "0x7060",
        "LoD/1.11b": "0x6090",
        "LoD/1.12a": "0x6A40",
        "LoD/1.13c": "0x60F0",
        "LoD/1.13d": "0x7120"
      },
      "sizes": {
        "LoD/1.11": 98,
        "LoD/1.11b": 98,
        "LoD/1.12a": 98,
        "LoD/1.13c": 98,
        "LoD/1.13d": 98
      },
      "name_source": "LoD/1.11",
      "method": "API",
      "index": "API:1a41a9ae65ba4a49a682fa836b821504",
      "callees": {
        "LoD/1.11": [
          "CopyInetNtoaToBuffer",
          "CopyMemoryAndDetectTerminator"
        ],
        "LoD/1.11b": [
          "CopyInetNtoaToBuffer",
          "CopyMemoryAndDetectTerminator"
        ],
        "LoD/1.12a": [
          "CopyInetNtoaToBuffer",
          "CopyMemoryAndDetectTerminator"
        ],
        "LoD/1.13c": [
          "CopyInetNtoaToBuffer",
          "CopyMemoryAndDetectTerminator"
        ],
        "LoD/1.13d": [
          "CopyInetNtoaToBuffer",
          "CopyMemoryAndDetectTerminator"
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
        "LoD/1.11": "7af24b078c044e258f5e500e160e54fb",
        "LoD/1.11b": "7af24b078c044e258f5e500e160e54fb",
        "LoD/1.12a": "7af24b078c044e258f5e500e160e54fb",
        "LoD/1.13c": "7af24b078c044e258f5e500e160e54fb",
        "LoD/1.13d": "7af24b078c044e258f5e500e160e54fb"
      }
    },
    "d2mcpclient.dll_MNE_6e7e0feb4b46_70D0": {
      "addresses": {
        "LoD/1.11": "0x6FA270D0",
        "LoD/1.11b": "0x6FA26100",
        "LoD/1.12a": "0x6FA26AB0",
        "LoD/1.13c": "0x6FA26160",
        "LoD/1.13d": "0x6FA27190"
      },
      "rvas": {
        "LoD/1.11": "0x70D0",
        "LoD/1.11b": "0x6100",
        "LoD/1.12a": "0x6AB0",
        "LoD/1.13c": "0x6160",
        "LoD/1.13d": "0x7190"
      },
      "sizes": {
        "LoD/1.11": 19,
        "LoD/1.11b": 19,
        "LoD/1.12a": 19,
        "LoD/1.13c": 19,
        "LoD/1.13d": 19
      },
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:6e7e0feb4b46a367301e751c476210ca",
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
        "LoD/1.11": "6e7e0feb4b46a367301e751c476210ca",
        "LoD/1.11b": "6e7e0feb4b46a367301e751c476210ca",
        "LoD/1.12a": "6e7e0feb4b46a367301e751c476210ca",
        "LoD/1.13c": "6e7e0feb4b46a367301e751c476210ca",
        "LoD/1.13d": "6e7e0feb4b46a367301e751c476210ca"
      }
    },
    "d2mcpclient.dll_MNE_6e7e0feb4b46_70F0": {
      "addresses": {
        "LoD/1.11": "0x6FA270F0",
        "LoD/1.11b": "0x6FA26120",
        "LoD/1.12a": "0x6FA26AD0",
        "LoD/1.13c": "0x6FA26180",
        "LoD/1.13d": "0x6FA27630"
      },
      "rvas": {
        "LoD/1.11": "0x70F0",
        "LoD/1.11b": "0x6120",
        "LoD/1.12a": "0x6AD0",
        "LoD/1.13c": "0x6180",
        "LoD/1.13d": "0x7630"
      },
      "sizes": {
        "LoD/1.11": 19,
        "LoD/1.11b": 19,
        "LoD/1.12a": 19,
        "LoD/1.13c": 19,
        "LoD/1.13d": 19
      },
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:6e7e0feb4b46a367301e751c476210ca",
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
        "LoD/1.11": "6e7e0feb4b46a367301e751c476210ca",
        "LoD/1.11b": "6e7e0feb4b46a367301e751c476210ca",
        "LoD/1.12a": "6e7e0feb4b46a367301e751c476210ca",
        "LoD/1.13c": "6e7e0feb4b46a367301e751c476210ca",
        "LoD/1.13d": "6e7e0feb4b46a367301e751c476210ca"
      }
    },
    "d2mcpclient.dll_MNE_8424744ab81a": {
      "addresses": {
        "LoD/1.11": "0x6FA27110",
        "LoD/1.11b": "0x6FA26140",
        "LoD/1.12a": "0x6FA26AF0",
        "LoD/1.13c": "0x6FA261A0",
        "LoD/1.13d": "0x6FA271D0"
      },
      "rvas": {
        "LoD/1.11": "0x7110",
        "LoD/1.11b": "0x6140",
        "LoD/1.12a": "0x6AF0",
        "LoD/1.13c": "0x61A0",
        "LoD/1.13d": "0x71D0"
      },
      "sizes": {
        "LoD/1.11": 73,
        "LoD/1.11b": 73,
        "LoD/1.12a": 73,
        "LoD/1.13c": 73,
        "LoD/1.13d": 73
      },
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:8424744ab81a0815d3a6cb7d46a8fc5b",
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
        "LoD/1.11": "8424744ab81a0815d3a6cb7d46a8fc5b",
        "LoD/1.11b": "8424744ab81a0815d3a6cb7d46a8fc5b",
        "LoD/1.12a": "8424744ab81a0815d3a6cb7d46a8fc5b",
        "LoD/1.13c": "8424744ab81a0815d3a6cb7d46a8fc5b",
        "LoD/1.13d": "8424744ab81a0815d3a6cb7d46a8fc5b"
      }
    },
    "d2mcpclient.dll_MNE_6e7e0feb4b46_7160": {
      "addresses": {
        "LoD/1.11": "0x6FA27160",
        "LoD/1.11b": "0x6FA26190",
        "LoD/1.12a": "0x6FA26B40",
        "LoD/1.13c": "0x6FA261F0",
        "LoD/1.13d": "0x6FA26F80"
      },
      "rvas": {
        "LoD/1.11": "0x7160",
        "LoD/1.11b": "0x6190",
        "LoD/1.12a": "0x6B40",
        "LoD/1.13c": "0x61F0",
        "LoD/1.13d": "0x6F80"
      },
      "sizes": {
        "LoD/1.11": 19,
        "LoD/1.11b": 19,
        "LoD/1.12a": 19,
        "LoD/1.13c": 19,
        "LoD/1.13d": 19
      },
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:6e7e0feb4b46a367301e751c476210ca",
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
        "LoD/1.11": "6e7e0feb4b46a367301e751c476210ca",
        "LoD/1.11b": "6e7e0feb4b46a367301e751c476210ca",
        "LoD/1.12a": "6e7e0feb4b46a367301e751c476210ca",
        "LoD/1.13c": "6e7e0feb4b46a367301e751c476210ca",
        "LoD/1.13d": "6e7e0feb4b46a367301e751c476210ca"
      }
    },
    "d2mcpclient.dll_MNE_6e7e0feb4b46_7180": {
      "addresses": {
        "LoD/1.11": "0x6FA27180",
        "LoD/1.11b": "0x6FA261B0",
        "LoD/1.12a": "0x6FA26B60",
        "LoD/1.13c": "0x6FA26210",
        "LoD/1.13d": "0x6FA271B0"
      },
      "rvas": {
        "LoD/1.11": "0x7180",
        "LoD/1.11b": "0x61B0",
        "LoD/1.12a": "0x6B60",
        "LoD/1.13c": "0x6210",
        "LoD/1.13d": "0x71B0"
      },
      "sizes": {
        "LoD/1.11": 19,
        "LoD/1.11b": 19,
        "LoD/1.12a": 19,
        "LoD/1.13c": 19,
        "LoD/1.13d": 19
      },
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:6e7e0feb4b46a367301e751c476210ca",
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
        "LoD/1.11": "6e7e0feb4b46a367301e751c476210ca",
        "LoD/1.11b": "6e7e0feb4b46a367301e751c476210ca",
        "LoD/1.12a": "6e7e0feb4b46a367301e751c476210ca",
        "LoD/1.13c": "6e7e0feb4b46a367301e751c476210ca",
        "LoD/1.13d": "6e7e0feb4b46a367301e751c476210ca"
      }
    },
    "d2mcpclient.dll_MNE_6e7e0feb4b46_71A0": {
      "addresses": {
        "LoD/1.11": "0x6FA271A0",
        "LoD/1.11b": "0x6FA261D0",
        "LoD/1.12a": "0x6FA26B80",
        "LoD/1.13c": "0x6FA26230",
        "LoD/1.13d": "0x6FA27220"
      },
      "rvas": {
        "LoD/1.11": "0x71A0",
        "LoD/1.11b": "0x61D0",
        "LoD/1.12a": "0x6B80",
        "LoD/1.13c": "0x6230",
        "LoD/1.13d": "0x7220"
      },
      "sizes": {
        "LoD/1.11": 19,
        "LoD/1.11b": 19,
        "LoD/1.12a": 19,
        "LoD/1.13c": 19,
        "LoD/1.13d": 19
      },
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:6e7e0feb4b46a367301e751c476210ca",
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
        "LoD/1.11": "6e7e0feb4b46a367301e751c476210ca",
        "LoD/1.11b": "6e7e0feb4b46a367301e751c476210ca",
        "LoD/1.12a": "6e7e0feb4b46a367301e751c476210ca",
        "LoD/1.13c": "6e7e0feb4b46a367301e751c476210ca",
        "LoD/1.13d": "6e7e0feb4b46a367301e751c476210ca"
      }
    },
    "d2mcpclient.dll_MNE_c30b587601b8": {
      "addresses": {
        "LoD/1.11": "0x6FA271C0",
        "LoD/1.11b": "0x6FA261F0",
        "LoD/1.12a": "0x6FA26BA0",
        "LoD/1.13c": "0x6FA26250",
        "LoD/1.13d": "0x6FA27280"
      },
      "rvas": {
        "LoD/1.11": "0x71C0",
        "LoD/1.11b": "0x61F0",
        "LoD/1.12a": "0x6BA0",
        "LoD/1.13c": "0x6250",
        "LoD/1.13d": "0x7280"
      },
      "sizes": {
        "LoD/1.11": 33,
        "LoD/1.11b": 33,
        "LoD/1.12a": 33,
        "LoD/1.13c": 33,
        "LoD/1.13d": 33
      },
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:c30b587601b86c2d03637e875dbc219e",
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
        "LoD/1.11": "c30b587601b86c2d03637e875dbc219e",
        "LoD/1.11b": "c30b587601b86c2d03637e875dbc219e",
        "LoD/1.12a": "c30b587601b86c2d03637e875dbc219e",
        "LoD/1.13c": "c30b587601b86c2d03637e875dbc219e",
        "LoD/1.13d": "c30b587601b86c2d03637e875dbc219e"
      }
    },
    "d2mcpclient.dll_MNE_99b0b599d293": {
      "addresses": {
        "LoD/1.11": "0x6FA27230",
        "LoD/1.11b": "0x6FA26220",
        "LoD/1.12a": "0x6FA26BD0",
        "LoD/1.13c": "0x6FA26280",
        "LoD/1.13d": "0x6FA272F0"
      },
      "rvas": {
        "LoD/1.11": "0x7230",
        "LoD/1.11b": "0x6220",
        "LoD/1.12a": "0x6BD0",
        "LoD/1.13c": "0x6280",
        "LoD/1.13d": "0x72F0"
      },
      "sizes": {
        "LoD/1.11": 337,
        "LoD/1.11b": 337,
        "LoD/1.12a": 337,
        "LoD/1.13c": 337,
        "LoD/1.13d": 337
      },
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:99b0b599d293192c328753fff6a8054a",
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
        "LoD/1.11": "99b0b599d293192c328753fff6a8054a",
        "LoD/1.11b": "99b0b599d293192c328753fff6a8054a",
        "LoD/1.12a": "99b0b599d293192c328753fff6a8054a",
        "LoD/1.13c": "99b0b599d293192c328753fff6a8054a",
        "LoD/1.13d": "99b0b599d293192c328753fff6a8054a"
      }
    },
    "d2mcpclient.dll_MNE_72ebf684a6a4": {
      "addresses": {
        "LoD/1.11": "0x6FA27390",
        "LoD/1.11b": "0x6FA26380",
        "LoD/1.12a": "0x6FA26D30",
        "LoD/1.13c": "0x6FA263E0"
      },
      "rvas": {
        "LoD/1.11": "0x7390",
        "LoD/1.11b": "0x6380",
        "LoD/1.12a": "0x6D30",
        "LoD/1.13c": "0x63E0"
      },
      "sizes": {
        "LoD/1.11": 230,
        "LoD/1.11b": 230,
        "LoD/1.12a": 230,
        "LoD/1.13c": 230
      },
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:72ebf684a6a4bc05802dfb63e0bbf085",
      "basic_block_counts": {
        "LoD/1.11": 15,
        "LoD/1.11b": 15,
        "LoD/1.12a": 15,
        "LoD/1.13c": 15
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "72ebf684a6a4bc05802dfb63e0bbf085",
        "LoD/1.11b": "72ebf684a6a4bc05802dfb63e0bbf085",
        "LoD/1.12a": "72ebf684a6a4bc05802dfb63e0bbf085",
        "LoD/1.13c": "72ebf684a6a4bc05802dfb63e0bbf085"
      }
    },
    "d2mcpclient.dll_API_1a41a9ae65ba_7480": {
      "addresses": {
        "LoD/1.11": "0x6FA27480",
        "LoD/1.11b": "0x6FA26470",
        "LoD/1.12a": "0x6FA26E20",
        "LoD/1.13c": "0x6FA264D0"
      },
      "rvas": {
        "LoD/1.11": "0x7480",
        "LoD/1.11b": "0x6470",
        "LoD/1.12a": "0x6E20",
        "LoD/1.13c": "0x64D0"
      },
      "sizes": {
        "LoD/1.11": 104,
        "LoD/1.11b": 104,
        "LoD/1.12a": 104,
        "LoD/1.13c": 104
      },
      "name_source": "LoD/1.11",
      "method": "API",
      "index": "API:1a41a9ae65ba4a49a682fa836b821504",
      "callees": {
        "LoD/1.11": [
          "CopyInetNtoaToBuffer",
          "CopyMemoryAndDetectTerminator"
        ],
        "LoD/1.11b": [
          "CopyInetNtoaToBuffer",
          "CopyMemoryAndDetectTerminator"
        ],
        "LoD/1.12a": [
          "CopyInetNtoaToBuffer",
          "CopyMemoryAndDetectTerminator"
        ],
        "LoD/1.13c": [
          "CopyInetNtoaToBuffer",
          "CopyMemoryAndDetectTerminator"
        ]
      },
      "basic_block_counts": {
        "LoD/1.11": 7,
        "LoD/1.11b": 7,
        "LoD/1.12a": 7,
        "LoD/1.13c": 7
      },
      "loop_counts": {
        "LoD/1.11": 0,
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11": "476b335589665c55440223fb5f94c4bb",
        "LoD/1.11b": "476b335589665c55440223fb5f94c4bb",
        "LoD/1.12a": "476b335589665c55440223fb5f94c4bb",
        "LoD/1.13c": "476b335589665c55440223fb5f94c4bb"
      }
    },
    "d2mcpclient.dll_MNE_caf365b58f88": {
      "addresses": {
        "LoD/1.11": "0x6FA274F0",
        "LoD/1.11b": "0x6FA264E0",
        "LoD/1.12a": "0x6FA26E90",
        "LoD/1.13c": "0x6FA26540",
        "LoD/1.13d": "0x6FA27600"
      },
      "rvas": {
        "LoD/1.11": "0x74F0",
        "LoD/1.11b": "0x64E0",
        "LoD/1.12a": "0x6E90",
        "LoD/1.13c": "0x6540",
        "LoD/1.13d": "0x7600"
      },
      "sizes": {
        "LoD/1.11": 41,
        "LoD/1.11b": 41,
        "LoD/1.12a": 41,
        "LoD/1.13c": 41,
        "LoD/1.13d": 41
      },
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:caf365b58f88965de85f0334b7756ab2",
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
        "LoD/1.11": "caf365b58f88965de85f0334b7756ab2",
        "LoD/1.11b": "caf365b58f88965de85f0334b7756ab2",
        "LoD/1.12a": "caf365b58f88965de85f0334b7756ab2",
        "LoD/1.13c": "caf365b58f88965de85f0334b7756ab2",
        "LoD/1.13d": "caf365b58f88965de85f0334b7756ab2"
      }
    },
    "d2mcpclient.dll_MNE_6e7e0feb4b46_7520": {
      "addresses": {
        "LoD/1.11": "0x6FA27520",
        "LoD/1.11b": "0x6FA26510",
        "LoD/1.12a": "0x6FA26EC0",
        "LoD/1.13c": "0x6FA26570",
        "LoD/1.13d": "0x6FA27260"
      },
      "rvas": {
        "LoD/1.11": "0x7520",
        "LoD/1.11b": "0x6510",
        "LoD/1.12a": "0x6EC0",
        "LoD/1.13c": "0x6570",
        "LoD/1.13d": "0x7260"
      },
      "sizes": {
        "LoD/1.11": 19,
        "LoD/1.11b": 19,
        "LoD/1.12a": 19,
        "LoD/1.13c": 19,
        "LoD/1.13d": 19
      },
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:6e7e0feb4b46a367301e751c476210ca",
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
        "LoD/1.11": "6e7e0feb4b46a367301e751c476210ca",
        "LoD/1.11b": "6e7e0feb4b46a367301e751c476210ca",
        "LoD/1.12a": "6e7e0feb4b46a367301e751c476210ca",
        "LoD/1.13c": "6e7e0feb4b46a367301e751c476210ca",
        "LoD/1.13d": "6e7e0feb4b46a367301e751c476210ca"
      }
    },
    "d2mcpclient.dll_MNE_6e7e0feb4b46_7540": {
      "addresses": {
        "LoD/1.11": "0x6FA27540",
        "LoD/1.11b": "0x6FA26530",
        "LoD/1.12a": "0x6FA26EE0",
        "LoD/1.13c": "0x6FA26590",
        "LoD/1.13d": "0x6FA27240"
      },
      "rvas": {
        "LoD/1.11": "0x7540",
        "LoD/1.11b": "0x6530",
        "LoD/1.12a": "0x6EE0",
        "LoD/1.13c": "0x6590",
        "LoD/1.13d": "0x7240"
      },
      "sizes": {
        "LoD/1.11": 19,
        "LoD/1.11b": 19,
        "LoD/1.12a": 19,
        "LoD/1.13c": 19,
        "LoD/1.13d": 19
      },
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:6e7e0feb4b46a367301e751c476210ca",
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
        "LoD/1.11": "6e7e0feb4b46a367301e751c476210ca",
        "LoD/1.11b": "6e7e0feb4b46a367301e751c476210ca",
        "LoD/1.12a": "6e7e0feb4b46a367301e751c476210ca",
        "LoD/1.13c": "6e7e0feb4b46a367301e751c476210ca",
        "LoD/1.13d": "6e7e0feb4b46a367301e751c476210ca"
      }
    },
    "d2mcpclient.dll_MNE_af07c7e4a123": {
      "addresses": {
        "LoD/1.11": "0x6FA27560",
        "LoD/1.11b": "0x6FA26550",
        "LoD/1.12a": "0x6FA26F00",
        "LoD/1.13c": "0x6FA265B0",
        "LoD/1.13d": "0x6FA27670"
      },
      "rvas": {
        "LoD/1.11": "0x7560",
        "LoD/1.11b": "0x6550",
        "LoD/1.12a": "0x6F00",
        "LoD/1.13c": "0x65B0",
        "LoD/1.13d": "0x7670"
      },
      "sizes": {
        "LoD/1.11": 27,
        "LoD/1.11b": 27,
        "LoD/1.12a": 27,
        "LoD/1.13c": 27,
        "LoD/1.13d": 27
      },
      "name_source": "LoD/1.11",
      "method": "MNE",
      "index": "MNE:af07c7e4a12344e736830a37ae223b30",
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
        "LoD/1.11": "af07c7e4a12344e736830a37ae223b30",
        "LoD/1.11b": "af07c7e4a12344e736830a37ae223b30",
        "LoD/1.12a": "af07c7e4a12344e736830a37ae223b30",
        "LoD/1.13c": "af07c7e4a12344e736830a37ae223b30",
        "LoD/1.13d": "af07c7e4a12344e736830a37ae223b30"
      }
    },
    "d2mcpclient.dll_EXP_10039_69D0": {
      "addresses": {
        "LoD/1.11b": "0x6FA269D0",
        "LoD/1.12a": "0x6FA27390",
        "LoD/1.13c": "0x6FA271D0",
        "LoD/1.13d": "0x6FA269E0"
      },
      "rvas": {
        "LoD/1.11b": "0x69D0",
        "LoD/1.12a": "0x7390",
        "LoD/1.13c": "0x71D0",
        "LoD/1.13d": "0x69E0"
      },
      "sizes": {
        "LoD/1.11b": 92,
        "LoD/1.12a": 92,
        "LoD/1.13c": 86,
        "LoD/1.13d": 86
      },
      "name": "Ordinal_10039",
      "signature": "undefined Ordinal_10039(void)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.11b",
      "method": "EXP",
      "index": "EXP:10039",
      "callees": {
        "LoD/1.11b": [
          "Ordinal_10069"
        ],
        "LoD/1.12a": [
          "ShutdownGameContext"
        ],
        "LoD/1.13c": [
          "EncodeBufferWithContext"
        ],
        "LoD/1.13d": [
          "EncodeBufferWithContext"
        ]
      },
      "basic_block_counts": {
        "LoD/1.11b": 7,
        "LoD/1.12a": 7,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11b": "93ad0a806324402857b0c67ebe3a594f",
        "LoD/1.12a": "93ad0a806324402857b0c67ebe3a594f",
        "LoD/1.13c": "566dda4133f217384fb38c1f4ca1301f",
        "LoD/1.13d": "566dda4133f217384fb38c1f4ca1301f"
      }
    },
    "d2mcpclient.dll_EXP_10030_6C50": {
      "addresses": {
        "LoD/1.11b": "0x6FA26C50",
        "LoD/1.12a": "0x6FA261E0",
        "LoD/1.13c": "0x6FA26E60",
        "LoD/1.13d": "0x6FA26670"
      },
      "rvas": {
        "LoD/1.11b": "0x6C50",
        "LoD/1.12a": "0x61E0",
        "LoD/1.13c": "0x6E60",
        "LoD/1.13d": "0x6670"
      },
      "sizes": {
        "LoD/1.11b": 49,
        "LoD/1.12a": 86,
        "LoD/1.13c": 86,
        "LoD/1.13d": 86
      },
      "name": "Ordinal_10030",
      "signature": "undefined Ordinal_10030(void)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.11b",
      "method": "EXP",
      "index": "EXP:10030",
      "callees": {
        "LoD/1.11b": [
          "Ordinal_10070"
        ],
        "LoD/1.12a": [
          "CopyMemoryAndDetectTerminator",
          "CalculateStringLength",
          "EncodeBufferWithContext"
        ],
        "LoD/1.13c": [
          "CopyMemoryAndDetectTerminator",
          "CalculateStringLength",
          "EncodeBufferWithContext"
        ],
        "LoD/1.13d": [
          "CopyMemoryAndDetectTerminator",
          "CalculateStringLength",
          "EncodeBufferWithContext"
        ]
      },
      "basic_block_counts": {
        "LoD/1.11b": 1,
        "LoD/1.12a": 1,
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.11b": 0,
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.11b": "4279ccfee5b4a0c14e808a53f9c93ba5",
        "LoD/1.12a": "3b3ba9dbeb1bcd03134b7287059a3981",
        "LoD/1.13c": "3b3ba9dbeb1bcd03134b7287059a3981",
        "LoD/1.13d": "3b3ba9dbeb1bcd03134b7287059a3981"
      }
    },
    "d2mcpclient.dll_AllocateMemory": {
      "addresses": {
        "LoD/1.12a": "0x6FA21C25",
        "LoD/1.13c": "0x6FA21C25"
      },
      "rvas": {
        "LoD/1.12a": "0x1C25",
        "LoD/1.13c": "0x1C25"
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
    "d2mcpclient.dll_ReallocateMemory": {
      "addresses": {
        "LoD/1.12a": "0x6FA229EA",
        "LoD/1.13c": "0x6FA229EA"
      },
      "rvas": {
        "LoD/1.12a": "0x29EA",
        "LoD/1.13c": "0x29EA"
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
    "d2mcpclient.dll_InitializeLocaleCharacterMaps": {
      "addresses": {
        "LoD/1.12a": "0x6FA2305F",
        "LoD/1.13c": "0x6FA2305F"
      },
      "rvas": {
        "LoD/1.12a": "0x305F",
        "LoD/1.13c": "0x305F"
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
    "d2mcpclient.dll_SetupCodePage": {
      "addresses": {
        "LoD/1.12a": "0x6FA231FA",
        "LoD/1.13c": "0x6FA231FA"
      },
      "rvas": {
        "LoD/1.12a": "0x31FA",
        "LoD/1.13c": "0x31FA"
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
    "d2mcpclient.dll_LocaleMapString": {
      "addresses": {
        "LoD/1.12a": "0x6FA24E80",
        "LoD/1.13c": "0x6FA24E80"
      },
      "rvas": {
        "LoD/1.12a": "0x4E80",
        "LoD/1.13c": "0x4E80"
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
    "d2mcpclient.dll_GetLocaleDefaultCodePage": {
      "addresses": {
        "LoD/1.12a": "0x6FA25909",
        "LoD/1.13c": "0x6FA25909"
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
    "d2mcpclient.dll_ConvertStringBetweenCodePages": {
      "addresses": {
        "LoD/1.12a": "0x6FA25950",
        "LoD/1.13c": "0x6FA25950"
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
    "d2mcpclient.dll_EXP_10010_63C0": {
      "addresses": {
        "LoD/1.12a": "0x6FA263C0"
      },
      "rvas": {
        "LoD/1.12a": "0x63C0"
      },
      "sizes": {
        "LoD/1.12a": 93
      },
      "name": "Ordinal_10010",
      "signature": "undefined Ordinal_10010(char * param_1, undefined2 param_2)",
      "calling_convention": "__fastcall",
      "name_source": "LoD/1.12a",
      "method": "EXP",
      "index": "EXP:10010",
      "callees": {
        "LoD/1.12a": [
          "EncodeBufferWithContext"
        ]
      },
      "basic_block_counts": {
        "LoD/1.12a": 1
      },
      "loop_counts": {
        "LoD/1.12a": 0
      },
      "mnemonic_hashes": {
        "LoD/1.12a": "e1e6665f63af39e13482dd75650e8ebc"
      }
    },
    "d2mcpclient.dll_EXP_10028_7350": {
      "addresses": {
        "LoD/1.12a": "0x6FA27350",
        "LoD/1.13c": "0x6FA269F0",
        "LoD/1.13d": "0x6FA261A0"
      },
      "rvas": {
        "LoD/1.12a": "0x7350",
        "LoD/1.13c": "0x69F0",
        "LoD/1.13d": "0x61A0"
      },
      "sizes": {
        "LoD/1.12a": 49,
        "LoD/1.13c": 49,
        "LoD/1.13d": 49
      },
      "name": "Ordinal_10028",
      "signature": "undefined Ordinal_10028(void)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.12a",
      "method": "EXP",
      "index": "EXP:10028",
      "callees": {
        "LoD/1.12a": [
          "GetField0x110",
          "GetPeerSocketAddress"
        ],
        "LoD/1.13c": [
          "GetField0x110",
          "GetPeerSocketAddress"
        ],
        "LoD/1.13d": [
          "GetField0x110",
          "GetPeerSocketAddress"
        ]
      },
      "basic_block_counts": {
        "LoD/1.12a": 3,
        "LoD/1.13c": 3,
        "LoD/1.13d": 3
      },
      "loop_counts": {
        "LoD/1.12a": 0,
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.12a": "76e08142858bd44edddd131220046bd1",
        "LoD/1.13c": "76e08142858bd44edddd131220046bd1",
        "LoD/1.13d": "76e08142858bd44edddd131220046bd1"
      }
    },
    "d2mcpclient.dll_EXP_10018_6A30": {
      "addresses": {
        "LoD/1.13c": "0x6FA26A30",
        "LoD/1.13d": "0x6FA261E0"
      },
      "rvas": {
        "LoD/1.13c": "0x6A30",
        "LoD/1.13d": "0x61E0"
      },
      "sizes": {
        "LoD/1.13c": 92,
        "LoD/1.13d": 92
      },
      "name": "Ordinal_10018",
      "signature": "undefined Ordinal_10018(void)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.13c",
      "method": "EXP",
      "index": "EXP:10018",
      "callees": {
        "LoD/1.13c": [
          "ShutdownGameContext"
        ],
        "LoD/1.13d": [
          "ShutdownGameContext"
        ]
      },
      "basic_block_counts": {
        "LoD/1.13c": 7,
        "LoD/1.13d": 7
      },
      "loop_counts": {
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.13c": "93ad0a806324402857b0c67ebe3a594f",
        "LoD/1.13d": "93ad0a806324402857b0c67ebe3a594f"
      }
    },
    "d2mcpclient.dll_EXP_10052_6D20": {
      "addresses": {
        "LoD/1.13c": "0x6FA26D20",
        "LoD/1.13d": "0x6FA26590"
      },
      "rvas": {
        "LoD/1.13c": "0x6D20",
        "LoD/1.13d": "0x6590"
      },
      "sizes": {
        "LoD/1.13c": 37,
        "LoD/1.13d": 37
      },
      "name": "Ordinal_10052",
      "signature": "undefined Ordinal_10052(void)",
      "calling_convention": "__stdcall",
      "name_source": "LoD/1.13c",
      "method": "EXP",
      "index": "EXP:10052",
      "callees": {
        "LoD/1.13c": [
          "EncodeBufferWithContext"
        ],
        "LoD/1.13d": [
          "EncodeBufferWithContext"
        ]
      },
      "basic_block_counts": {
        "LoD/1.13c": 1,
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.13c": 0,
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.13c": "27cf70e216d5f82ac091c77f63637746",
        "LoD/1.13d": "27cf70e216d5f82ac091c77f63637746"
      }
    },
    "d2mcpclient.dll__calloc_1F61": {
      "addresses": {
        "LoD/1.13d": "0x6FA21F61"
      },
      "rvas": {
        "LoD/1.13d": "0x1F61"
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
    "d2mcpclient.dll__realloc_2D0A": {
      "addresses": {
        "LoD/1.13d": "0x6FA22D0A"
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
    "d2mcpclient.dll_setSBUpLow_337A": {
      "addresses": {
        "LoD/1.13d": "0x6FA2337A"
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
    "d2mcpclient.dll___setmbcp_lk_3506": {
      "addresses": {
        "LoD/1.13d": "0x6FA23506"
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
    "d2mcpclient.dll____crtLCMapStringA_5190": {
      "addresses": {
        "LoD/1.13d": "0x6FA25190"
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
    "d2mcpclient.dll____ansicp_58B9": {
      "addresses": {
        "LoD/1.13d": "0x6FA258B9"
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
    "d2mcpclient.dll____convertcp_58FC": {
      "addresses": {
        "LoD/1.13d": "0x6FA258FC"
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
    "d2mcpclient.dll_Ordinal_10004": {
      "addresses": {
        "LoD/1.13d": "0x6FA25DD0"
      },
      "rvas": {
        "LoD/1.13d": "0x5DD0"
      },
      "sizes": {
        "LoD/1.13d": 6
      },
      "name": "Ordinal_10004",
      "signature": "undefined Ordinal_10004(void)",
      "calling_convention": "unknown",
      "name_source": "LoD/1.13d",
      "method": "MNE",
      "index": "MNE:e3e7225badfcf3c2e051c42d71d7237a",
      "basic_block_counts": {
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.13d": "e3e7225badfcf3c2e051c42d71d7237a"
      }
    },
    "d2mcpclient.dll_EXP_10027_6560": {
      "addresses": {
        "LoD/1.13d": "0x6FA26560"
      },
      "rvas": {
        "LoD/1.13d": "0x6560"
      },
      "sizes": {
        "LoD/1.13d": 46
      },
      "name": "Ordinal_10027",
      "signature": "undefined Ordinal_10027(byte param_1, undefined2 param_2)",
      "calling_convention": "__fastcall",
      "name_source": "LoD/1.13d",
      "method": "EXP",
      "index": "EXP:10027",
      "callees": {
        "LoD/1.13d": [
          "EncodeBufferWithContext"
        ]
      },
      "basic_block_counts": {
        "LoD/1.13d": 1
      },
      "loop_counts": {
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.13d": "8cf6081513f31f17087d887ea495c3ca"
      }
    },
    "d2mcpclient.dll_API_71b27a39f00d": {
      "addresses": {
        "LoD/1.13d": "0x6FA26E20"
      },
      "rvas": {
        "LoD/1.13d": "0x6E20"
      },
      "sizes": {
        "LoD/1.13d": 153
      },
      "name_source": "LoD/1.13d",
      "method": "API",
      "index": "API:71b27a39f00d8fc47b8310569759a942",
      "callees": {
        "LoD/1.13d": [
          "GetReturnAddress",
          "CleanupAndAbort",
          "Ordinal_10004"
        ]
      },
      "basic_block_counts": {
        "LoD/1.13d": 7
      },
      "loop_counts": {
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.13d": "cc7c5aa4613692e886a0bbdd70d987a2"
      }
    },
    "d2mcpclient.dll_API_75754301eb72": {
      "addresses": {
        "LoD/1.13d": "0x6FA27450"
      },
      "rvas": {
        "LoD/1.13d": "0x7450"
      },
      "sizes": {
        "LoD/1.13d": 318
      },
      "name_source": "LoD/1.13d",
      "method": "API",
      "index": "API:75754301eb722986fb36c958a825f8fb",
      "callees": {
        "LoD/1.13d": [
          "CopyMemoryAndDetectTerminator",
          "CopyMemoryAndDetectTerminator"
        ]
      },
      "basic_block_counts": {
        "LoD/1.13d": 13
      },
      "loop_counts": {
        "LoD/1.13d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.13d": "635457d817a91e14abf09f166f375da3"
      }
    }
  }
};

if (typeof FUNCTION_DATA === 'undefined') FUNCTION_DATA = {};
FUNCTION_DATA['D2MCPClient.dll'] = FUNCTIONS_D2MCPClient_dll;
