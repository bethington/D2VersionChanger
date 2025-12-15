// Auto-generated from function_registry_v2.json
// Generated: 2025-12-15T04:04:17.126358
// Functions for Diablo II.exe
// Versions: LoD/1.07, LoD/1.08, LoD/1.09, LoD/1.09b, LoD/1.09d, LoD/1.10, LoD/1.11, LoD/1.11b, LoD/1.12a, LoD/1.13c, LoD/1.13d, LoD/1.14a, LoD/1.14b, LoD/1.14c, LoD/1.14d

var FUNCTIONS_Diablo_II_exe = {
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
    "LoD/1.13d",
    "LoD/1.14a",
    "LoD/1.14b",
    "LoD/1.14c",
    "LoD/1.14d"
  ],
  "functions": {
    "diablo ii.exe_STR_ce6d908e8553": {
      "addresses": {
        "LoD/1.07": "0x00401000",
        "LoD/1.08": "0x00401000",
        "LoD/1.09": "0x00401000",
        "LoD/1.09b": "0x00401000",
        "LoD/1.09d": "0x00401000",
        "LoD/1.10": "0x00401000",
        "LoD/1.11": "0x00401000",
        "LoD/1.11b": "0x00401000",
        "LoD/1.12a": "0x00401000",
        "LoD/1.13c": "0x00401000",
        "LoD/1.13d": "0x00401000",
        "LoD/1.14a": "0x00401000",
        "LoD/1.14b": "0x00401000",
        "LoD/1.14c": "0x00401000",
        "LoD/1.14d": "0x00401000"
      },
      "rvas": {
        "LoD/1.07": "0x1000",
        "LoD/1.08": "0x1000",
        "LoD/1.09": "0x1000",
        "LoD/1.09b": "0x1000",
        "LoD/1.09d": "0x1000",
        "LoD/1.10": "0x1000",
        "LoD/1.11": "0x1000",
        "LoD/1.11b": "0x1000",
        "LoD/1.12a": "0x1000",
        "LoD/1.13c": "0x1000",
        "LoD/1.13d": "0x1000",
        "LoD/1.14a": "0x1000",
        "LoD/1.14b": "0x1000",
        "LoD/1.14c": "0x1000",
        "LoD/1.14d": "0x1000"
      },
      "sizes": {
        "LoD/1.07": 902,
        "LoD/1.08": 902,
        "LoD/1.09": 902,
        "LoD/1.09b": 902,
        "LoD/1.09d": 902,
        "LoD/1.10": 902,
        "LoD/1.11": 902,
        "LoD/1.11b": 902,
        "LoD/1.12a": 902,
        "LoD/1.13c": 902,
        "LoD/1.13d": 902,
        "LoD/1.14a": 902,
        "LoD/1.14b": 902,
        "LoD/1.14c": 902,
        "LoD/1.14d": 902
      },
      "return_type": "DWORD",
      "name_source": "LoD/1.07",
      "method": "STR",
      "index": "STR:ce6d908e8553d0cf353c49fe22a3b675",
      "indexes": {
        "EXP": null,
        "STR": "ce6d908e8553d0cf353c49fe22a3b675",
        "API": null,
        "MNE": "bf8c322b1dd06995c54b40d971c644e5",
        "CFG": "9a79e3481750058eb22d5511b99ea9bf",
        "PRO": "c8f9dd487289ffa0ad7ffcd1b7feb746",
        "CAL": "8663fba99a43c444406e362e74136098",
        "CON": "318b296d2b8708a97227cf51294ab6b8",
        "APS": null
      },
      "display_name": "FUN_00401000",
      "callees": {
        "LoD/1.07": [
          "FUN_004013b0|0x4013B0",
          "GetExitCodeProcess|0x2",
          "GetLastError|0x6",
          "LoadStringA|0x2C",
          "GetCommandLineA|0x5",
          "FUN_0040146d|0x40146D",
          "CreateProcessA|0x4",
          "CreateEventA|0x7",
          "MessageBoxA|0x2B",
          "WaitForMultipleObjects|0x3",
          "CloseHandle|0x17"
        ],
        "LoD/1.08": [
          "GetCommandLineA|0x5",
          "CreateEventA|0x7",
          "MessageBoxA|0x2B",
          "FUN_0040146d|0x40146D",
          "FUN_004013b0|0x4013B0",
          "CreateProcessA|0x4",
          "GetLastError|0x6",
          "WaitForMultipleObjects|0x3",
          "CloseHandle|0x17",
          "GetExitCodeProcess|0x2",
          "LoadStringA|0x2C"
        ],
        "LoD/1.09": [
          "GetLastError|0x6",
          "CreateEventA|0x7",
          "CloseHandle|0x17",
          "FUN_004013b0|0x4013B0",
          "FUN_0040146d|0x40146D",
          "WaitForMultipleObjects|0x3",
          "MessageBoxA|0x2B",
          "GetExitCodeProcess|0x2",
          "LoadStringA|0x2C",
          "GetCommandLineA|0x5",
          "CreateProcessA|0x4"
        ],
        "LoD/1.09b": [
          "MessageBoxA|0x2B",
          "GetCommandLineA|0x5",
          "LoadStringA|0x2C",
          "FUN_004013b0|0x4013B0",
          "CreateProcessA|0x4",
          "WaitForMultipleObjects|0x3",
          "GetExitCodeProcess|0x2",
          "GetLastError|0x6",
          "CloseHandle|0x17",
          "CreateEventA|0x7",
          "FUN_0040146d|0x40146D"
        ],
        "LoD/1.09d": [
          "CreateProcessA|0x4",
          "WaitForMultipleObjects|0x3",
          "FUN_0040146d|0x40146D",
          "MessageBoxA|0x2B",
          "CloseHandle|0x17",
          "LoadStringA|0x2C",
          "GetExitCodeProcess|0x2",
          "FUN_004013b0|0x4013B0",
          "CreateEventA|0x7",
          "GetCommandLineA|0x5",
          "GetLastError|0x6"
        ],
        "LoD/1.10": [
          "CloseHandle|0x17",
          "GetLastError|0x6",
          "FUN_004013b0|0x4013B0",
          "MessageBoxA|0x2B",
          "CreateProcessA|0x4",
          "WaitForMultipleObjects|0x3",
          "GetExitCodeProcess|0x2",
          "FUN_0040146d|0x40146D",
          "CreateEventA|0x7",
          "LoadStringA|0x2C",
          "GetCommandLineA|0x5"
        ],
        "LoD/1.11": [
          "CreateProcessA|0x4",
          "LoadStringA|0x2C",
          "CreateEventA|0x7",
          "FUN_004013b0|0x4013B0",
          "GetCommandLineA|0x5",
          "WaitForMultipleObjects|0x3",
          "GetLastError|0x6",
          "GetExitCodeProcess|0x2",
          "MessageBoxA|0x2B",
          "CloseHandle|0x17",
          "FUN_0040146d|0x40146D"
        ],
        "LoD/1.11b": [
          "FUN_0040146d|0x40146D",
          "CreateProcessA|0x4",
          "WaitForMultipleObjects|0x3",
          "GetExitCodeProcess|0x2",
          "CloseHandle|0x17",
          "GetLastError|0x6",
          "LoadStringA|0x2C",
          "MessageBoxA|0x2B",
          "FUN_004013b0|0x4013B0",
          "CreateEventA|0x7",
          "GetCommandLineA|0x5"
        ],
        "LoD/1.12a": [
          "GetCommandLineA|0x5",
          "CreateProcessA|0x4",
          "GetLastError|0x6",
          "GetExitCodeProcess|0x2",
          "CreateEventA|0x7",
          "MessageBoxA|0x2B",
          "LoadStringA|0x2C",
          "FUN_0040146d|0x40146D",
          "CloseHandle|0x17",
          "WaitForMultipleObjects|0x3",
          "FUN_004013b0|0x4013B0"
        ],
        "LoD/1.13c": [
          "CreateEventA|0x7",
          "GetLastError|0x6",
          "LoadStringA|0x2C",
          "FUN_0040146d|0x40146D",
          "GetExitCodeProcess|0x2",
          "GetCommandLineA|0x5",
          "MessageBoxA|0x2B",
          "WaitForMultipleObjects|0x3",
          "CloseHandle|0x17",
          "CreateProcessA|0x4",
          "FUN_004013b0|0x4013B0"
        ],
        "LoD/1.13d": [
          "WaitForMultipleObjects|0x3",
          "FUN_004013b0|0x4013B0",
          "FUN_0040146d|0x40146D",
          "CreateProcessA|0x4",
          "MessageBoxA|0x2B",
          "CloseHandle|0x17",
          "CreateEventA|0x7",
          "GetCommandLineA|0x5",
          "GetLastError|0x6",
          "LoadStringA|0x2C",
          "GetExitCodeProcess|0x2"
        ],
        "LoD/1.14a": [
          "CreateProcessA|0x4",
          "WaitForMultipleObjects|0x3",
          "CreateEventA|0x7",
          "GetCommandLineA|0x5",
          "GetLastError|0x6",
          "LoadStringA|0x2C",
          "MessageBoxA|0x2B",
          "FUN_0040146d|0x40146D",
          "GetExitCodeProcess|0x2",
          "FUN_004013b0|0x4013B0",
          "CloseHandle|0x17"
        ],
        "LoD/1.14b": [
          "LoadStringA|0x2C",
          "WaitForMultipleObjects|0x3",
          "MessageBoxA|0x2B",
          "CreateProcessA|0x4",
          "GetExitCodeProcess|0x2",
          "CreateEventA|0x7",
          "FUN_004013b0|0x4013B0",
          "GetLastError|0x6",
          "CloseHandle|0x17",
          "FUN_0040146d|0x40146D",
          "GetCommandLineA|0x5"
        ],
        "LoD/1.14c": [
          "FUN_0040146d|0x40146D",
          "FUN_004013b0|0x4013B0",
          "GetExitCodeProcess|0x2",
          "GetCommandLineA|0x5",
          "GetLastError|0x6",
          "CloseHandle|0x17",
          "CreateProcessA|0x4",
          "WaitForMultipleObjects|0x3",
          "CreateEventA|0x7",
          "LoadStringA|0x2C",
          "MessageBoxA|0x2B"
        ],
        "LoD/1.14d": [
          "MessageBoxA|0x2B",
          "GetCommandLineA|0x5",
          "WaitForMultipleObjects|0x3",
          "CreateEventA|0x7",
          "FUN_0040146d|0x40146D",
          "FUN_004013b0|0x4013B0",
          "LoadStringA|0x2C",
          "GetLastError|0x6",
          "CloseHandle|0x17",
          "GetExitCodeProcess|0x2",
          "CreateProcessA|0x4"
        ]
      },
      "callers": {
        "LoD/1.07": [
          "entry|0x4014E3"
        ],
        "LoD/1.08": [
          "entry|0x4014E3"
        ],
        "LoD/1.09": [
          "entry|0x4014E3"
        ],
        "LoD/1.09b": [
          "entry|0x4014E3"
        ],
        "LoD/1.09d": [
          "entry|0x4014E3"
        ],
        "LoD/1.10": [
          "entry|0x4014E3"
        ],
        "LoD/1.11": [
          "entry|0x4014E3"
        ],
        "LoD/1.11b": [
          "entry|0x4014E3"
        ],
        "LoD/1.12a": [
          "entry|0x4014E3"
        ],
        "LoD/1.13c": [
          "entry|0x4014E3"
        ],
        "LoD/1.13d": [
          "entry|0x4014E3"
        ],
        "LoD/1.14a": [
          "entry|0x4014E3"
        ],
        "LoD/1.14b": [
          "entry|0x4014E3"
        ],
        "LoD/1.14c": [
          "entry|0x4014E3"
        ],
        "LoD/1.14d": [
          "entry|0x4014E3"
        ]
      },
      "strings": {
        "LoD/1.07": [
          "\"DIABLO_II_OK\"",
          "u\"Diablo II was unable to find Game.exe.\\nPlease make sure your application is correctly installed, and that your Expansion Disc is in your CD_ROM drive, and try again.\\n\"",
          "u\"Please make sure your Diablo II Expansion Disc is in your CD-ROM drive, then click on 'Retry'.\"",
          "u\"Game.exe\"",
          "u\"CD-ROM drive error.\"",
          "u\"Diablo II.exe\"",
          "u\"Diablo II was unable to locate your CD-ROM drive.\\nPlease make sure your Diablo II Expansion Disc is in your CD-ROM drive, then click on 'Retry'.\"",
          "u\"Please verify that your Diablo II Expansion Disc is in your CD-ROM drive, then click on 'Retry'.\"",
          "u\"Diablo II was unable to detect a Disc in your CD-ROM drive.\\nPlease make sure your Diablo II Expansion Disc is in your CD-ROM drive, then click on 'Retry'.\"",
          "u\"Diablo II failed to run.\\nPlease make sure your Diablo II Expansion Disc is in your CD-ROM drive, then click on 'Retry'.\""
        ],
        "LoD/1.08": [
          "\"DIABLO_II_OK\"",
          "u\"Diablo II was unable to find Game.exe.\\nPlease make sure your application is correctly installed, and that your Expansion Disc is in your CD_ROM drive, and try again.\\n\"",
          "u\"Please make sure your Diablo II Expansion Disc is in your CD-ROM drive, then click on 'Retry'.\"",
          "u\"Game.exe\"",
          "u\"CD-ROM drive error.\"",
          "u\"Diablo II.exe\"",
          "u\"Diablo II was unable to locate your CD-ROM drive.\\nPlease make sure your Diablo II Expansion Disc is in your CD-ROM drive, then click on 'Retry'.\"",
          "u\"Please verify that your Diablo II Expansion Disc is in your CD-ROM drive, then click on 'Retry'.\"",
          "u\"Diablo II was unable to detect a Disc in your CD-ROM drive.\\nPlease make sure your Diablo II Expansion Disc is in your CD-ROM drive, then click on 'Retry'.\"",
          "u\"Diablo II failed to run.\\nPlease make sure your Diablo II Expansion Disc is in your CD-ROM drive, then click on 'Retry'.\""
        ],
        "LoD/1.09": [
          "\"DIABLO_II_OK\"",
          "u\"Diablo II was unable to find Game.exe.\\nPlease make sure your application is correctly installed, and that your Expansion Disc is in your CD_ROM drive, and try again.\\n\"",
          "u\"Please make sure your Diablo II Expansion Disc is in your CD-ROM drive, then click on 'Retry'.\"",
          "u\"Game.exe\"",
          "u\"CD-ROM drive error.\"",
          "u\"Diablo II.exe\"",
          "u\"Diablo II was unable to locate your CD-ROM drive.\\nPlease make sure your Diablo II Expansion Disc is in your CD-ROM drive, then click on 'Retry'.\"",
          "u\"Please verify that your Diablo II Expansion Disc is in your CD-ROM drive, then click on 'Retry'.\"",
          "u\"Diablo II was unable to detect a Disc in your CD-ROM drive.\\nPlease make sure your Diablo II Expansion Disc is in your CD-ROM drive, then click on 'Retry'.\"",
          "u\"Diablo II failed to run.\\nPlease make sure your Diablo II Expansion Disc is in your CD-ROM drive, then click on 'Retry'.\""
        ],
        "LoD/1.09b": [
          "\"DIABLO_II_OK\"",
          "u\"Diablo II was unable to find Game.exe.\\nPlease make sure your application is correctly installed, and that your Expansion Disc is in your CD_ROM drive, and try again.\\n\"",
          "u\"Please make sure your Diablo II Expansion Disc is in your CD-ROM drive, then click on 'Retry'.\"",
          "u\"Game.exe\"",
          "u\"CD-ROM drive error.\"",
          "u\"Diablo II.exe\"",
          "u\"Diablo II was unable to locate your CD-ROM drive.\\nPlease make sure your Diablo II Expansion Disc is in your CD-ROM drive, then click on 'Retry'.\"",
          "u\"Please verify that your Diablo II Expansion Disc is in your CD-ROM drive, then click on 'Retry'.\"",
          "u\"Diablo II was unable to detect a Disc in your CD-ROM drive.\\nPlease make sure your Diablo II Expansion Disc is in your CD-ROM drive, then click on 'Retry'.\"",
          "u\"Diablo II failed to run.\\nPlease make sure your Diablo II Expansion Disc is in your CD-ROM drive, then click on 'Retry'.\""
        ],
        "LoD/1.09d": [
          "\"DIABLO_II_OK\"",
          "u\"Diablo II was unable to find Game.exe.\\nPlease make sure your application is correctly installed, and that your Expansion Disc is in your CD_ROM drive, and try again.\\n\"",
          "u\"Please make sure your Diablo II Expansion Disc is in your CD-ROM drive, then click on 'Retry'.\"",
          "u\"Game.exe\"",
          "u\"CD-ROM drive error.\"",
          "u\"Diablo II.exe\"",
          "u\"Diablo II was unable to locate your CD-ROM drive.\\nPlease make sure your Diablo II Expansion Disc is in your CD-ROM drive, then click on 'Retry'.\"",
          "u\"Please verify that your Diablo II Expansion Disc is in your CD-ROM drive, then click on 'Retry'.\"",
          "u\"Diablo II was unable to detect a Disc in your CD-ROM drive.\\nPlease make sure your Diablo II Expansion Disc is in your CD-ROM drive, then click on 'Retry'.\"",
          "u\"Diablo II failed to run.\\nPlease make sure your Diablo II Expansion Disc is in your CD-ROM drive, then click on 'Retry'.\""
        ],
        "LoD/1.10": [
          "\"DIABLO_II_OK\"",
          "u\"Diablo II was unable to find Game.exe.\\nPlease make sure your application is correctly installed, and that your Expansion Disc is in your CD_ROM drive, and try again.\\n\"",
          "u\"Please make sure your Diablo II Expansion Disc is in your CD-ROM drive, then click on 'Retry'.\"",
          "u\"Game.exe\"",
          "u\"CD-ROM drive error.\"",
          "u\"Diablo II.exe\"",
          "u\"Diablo II was unable to locate your CD-ROM drive.\\nPlease make sure your Diablo II Expansion Disc is in your CD-ROM drive, then click on 'Retry'.\"",
          "u\"Please verify that your Diablo II Expansion Disc is in your CD-ROM drive, then click on 'Retry'.\"",
          "u\"Diablo II was unable to detect a Disc in your CD-ROM drive.\\nPlease make sure your Diablo II Expansion Disc is in your CD-ROM drive, then click on 'Retry'.\"",
          "u\"Diablo II failed to run.\\nPlease make sure your Diablo II Expansion Disc is in your CD-ROM drive, then click on 'Retry'.\""
        ],
        "LoD/1.11": [
          "\"DIABLO_II_OK\"",
          "u\"Diablo II was unable to find Game.exe.\\nPlease make sure your application is correctly installed, and that your Expansion Disc is in your CD_ROM drive, and try again.\\n\"",
          "u\"Please make sure your Diablo II Expansion Disc is in your CD-ROM drive, then click on 'Retry'.\"",
          "u\"Game.exe\"",
          "u\"CD-ROM drive error.\"",
          "u\"Diablo II.exe\"",
          "u\"Diablo II was unable to locate your CD-ROM drive.\\nPlease make sure your Diablo II Expansion Disc is in your CD-ROM drive, then click on 'Retry'.\"",
          "u\"Please verify that your Diablo II Expansion Disc is in your CD-ROM drive, then click on 'Retry'.\"",
          "u\"Diablo II was unable to detect a Disc in your CD-ROM drive.\\nPlease make sure your Diablo II Expansion Disc is in your CD-ROM drive, then click on 'Retry'.\"",
          "u\"Diablo II failed to run.\\nPlease make sure your Diablo II Expansion Disc is in your CD-ROM drive, then click on 'Retry'.\""
        ],
        "LoD/1.11b": [
          "\"DIABLO_II_OK\"",
          "u\"Diablo II was unable to find Game.exe.\\nPlease make sure your application is correctly installed, and that your Expansion Disc is in your CD_ROM drive, and try again.\\n\"",
          "u\"Please make sure your Diablo II Expansion Disc is in your CD-ROM drive, then click on 'Retry'.\"",
          "u\"Game.exe\"",
          "u\"CD-ROM drive error.\"",
          "u\"Diablo II.exe\"",
          "u\"Diablo II was unable to locate your CD-ROM drive.\\nPlease make sure your Diablo II Expansion Disc is in your CD-ROM drive, then click on 'Retry'.\"",
          "u\"Please verify that your Diablo II Expansion Disc is in your CD-ROM drive, then click on 'Retry'.\"",
          "u\"Diablo II was unable to detect a Disc in your CD-ROM drive.\\nPlease make sure your Diablo II Expansion Disc is in your CD-ROM drive, then click on 'Retry'.\"",
          "u\"Diablo II failed to run.\\nPlease make sure your Diablo II Expansion Disc is in your CD-ROM drive, then click on 'Retry'.\""
        ],
        "LoD/1.12a": [
          "\"DIABLO_II_OK\"",
          "u\"Diablo II was unable to find Game.exe.\\nPlease make sure your application is correctly installed, and that your Expansion Disc is in your CD_ROM drive, and try again.\\n\"",
          "u\"Please make sure your Diablo II Expansion Disc is in your CD-ROM drive, then click on 'Retry'.\"",
          "u\"Game.exe\"",
          "u\"CD-ROM drive error.\"",
          "u\"Diablo II.exe\"",
          "u\"Diablo II was unable to locate your CD-ROM drive.\\nPlease make sure your Diablo II Expansion Disc is in your CD-ROM drive, then click on 'Retry'.\"",
          "u\"Please verify that your Diablo II Expansion Disc is in your CD-ROM drive, then click on 'Retry'.\"",
          "u\"Diablo II was unable to detect a Disc in your CD-ROM drive.\\nPlease make sure your Diablo II Expansion Disc is in your CD-ROM drive, then click on 'Retry'.\"",
          "u\"Diablo II failed to run.\\nPlease make sure your Diablo II Expansion Disc is in your CD-ROM drive, then click on 'Retry'.\""
        ],
        "LoD/1.13c": [
          "\"DIABLO_II_OK\"",
          "u\"Diablo II was unable to find Game.exe.\\nPlease make sure your application is correctly installed, and that your Expansion Disc is in your CD_ROM drive, and try again.\\n\"",
          "u\"Please make sure your Diablo II Expansion Disc is in your CD-ROM drive, then click on 'Retry'.\"",
          "u\"Game.exe\"",
          "u\"CD-ROM drive error.\"",
          "u\"Diablo II.exe\"",
          "u\"Diablo II was unable to locate your CD-ROM drive.\\nPlease make sure your Diablo II Expansion Disc is in your CD-ROM drive, then click on 'Retry'.\"",
          "u\"Please verify that your Diablo II Expansion Disc is in your CD-ROM drive, then click on 'Retry'.\"",
          "u\"Diablo II was unable to detect a Disc in your CD-ROM drive.\\nPlease make sure your Diablo II Expansion Disc is in your CD-ROM drive, then click on 'Retry'.\"",
          "u\"Diablo II failed to run.\\nPlease make sure your Diablo II Expansion Disc is in your CD-ROM drive, then click on 'Retry'.\""
        ],
        "LoD/1.13d": [
          "\"DIABLO_II_OK\"",
          "u\"Diablo II was unable to find Game.exe.\\nPlease make sure your application is correctly installed, and that your Expansion Disc is in your CD_ROM drive, and try again.\\n\"",
          "u\"Please make sure your Diablo II Expansion Disc is in your CD-ROM drive, then click on 'Retry'.\"",
          "u\"Game.exe\"",
          "u\"CD-ROM drive error.\"",
          "u\"Diablo II.exe\"",
          "u\"Diablo II was unable to locate your CD-ROM drive.\\nPlease make sure your Diablo II Expansion Disc is in your CD-ROM drive, then click on 'Retry'.\"",
          "u\"Please verify that your Diablo II Expansion Disc is in your CD-ROM drive, then click on 'Retry'.\"",
          "u\"Diablo II was unable to detect a Disc in your CD-ROM drive.\\nPlease make sure your Diablo II Expansion Disc is in your CD-ROM drive, then click on 'Retry'.\"",
          "u\"Diablo II failed to run.\\nPlease make sure your Diablo II Expansion Disc is in your CD-ROM drive, then click on 'Retry'.\""
        ],
        "LoD/1.14a": [
          "\"DIABLO_II_OK\"",
          "u\"Diablo II was unable to find Game.exe.\\nPlease make sure your application is correctly installed, and that your Expansion Disc is in your CD_ROM drive, and try again.\\n\"",
          "u\"Please make sure your Diablo II Expansion Disc is in your CD-ROM drive, then click on 'Retry'.\"",
          "u\"Game.exe\"",
          "u\"CD-ROM drive error.\"",
          "u\"Diablo II.exe\"",
          "u\"Diablo II was unable to locate your CD-ROM drive.\\nPlease make sure your Diablo II Expansion Disc is in your CD-ROM drive, then click on 'Retry'.\"",
          "u\"Please verify that your Diablo II Expansion Disc is in your CD-ROM drive, then click on 'Retry'.\"",
          "u\"Diablo II was unable to detect a Disc in your CD-ROM drive.\\nPlease make sure your Diablo II Expansion Disc is in your CD-ROM drive, then click on 'Retry'.\"",
          "u\"Diablo II failed to run.\\nPlease make sure your Diablo II Expansion Disc is in your CD-ROM drive, then click on 'Retry'.\""
        ],
        "LoD/1.14b": [
          "\"DIABLO_II_OK\"",
          "u\"Diablo II was unable to find Game.exe.\\nPlease make sure your application is correctly installed, and that your Expansion Disc is in your CD_ROM drive, and try again.\\n\"",
          "u\"Please make sure your Diablo II Expansion Disc is in your CD-ROM drive, then click on 'Retry'.\"",
          "u\"Game.exe\"",
          "u\"CD-ROM drive error.\"",
          "u\"Diablo II.exe\"",
          "u\"Diablo II was unable to locate your CD-ROM drive.\\nPlease make sure your Diablo II Expansion Disc is in your CD-ROM drive, then click on 'Retry'.\"",
          "u\"Please verify that your Diablo II Expansion Disc is in your CD-ROM drive, then click on 'Retry'.\"",
          "u\"Diablo II was unable to detect a Disc in your CD-ROM drive.\\nPlease make sure your Diablo II Expansion Disc is in your CD-ROM drive, then click on 'Retry'.\"",
          "u\"Diablo II failed to run.\\nPlease make sure your Diablo II Expansion Disc is in your CD-ROM drive, then click on 'Retry'.\""
        ],
        "LoD/1.14c": [
          "\"DIABLO_II_OK\"",
          "u\"Diablo II was unable to find Game.exe.\\nPlease make sure your application is correctly installed, and that your Expansion Disc is in your CD_ROM drive, and try again.\\n\"",
          "u\"Please make sure your Diablo II Expansion Disc is in your CD-ROM drive, then click on 'Retry'.\"",
          "u\"Game.exe\"",
          "u\"CD-ROM drive error.\"",
          "u\"Diablo II.exe\"",
          "u\"Diablo II was unable to locate your CD-ROM drive.\\nPlease make sure your Diablo II Expansion Disc is in your CD-ROM drive, then click on 'Retry'.\"",
          "u\"Please verify that your Diablo II Expansion Disc is in your CD-ROM drive, then click on 'Retry'.\"",
          "u\"Diablo II was unable to detect a Disc in your CD-ROM drive.\\nPlease make sure your Diablo II Expansion Disc is in your CD-ROM drive, then click on 'Retry'.\"",
          "u\"Diablo II failed to run.\\nPlease make sure your Diablo II Expansion Disc is in your CD-ROM drive, then click on 'Retry'.\""
        ],
        "LoD/1.14d": [
          "\"DIABLO_II_OK\"",
          "u\"Diablo II was unable to find Game.exe.\\nPlease make sure your application is correctly installed, and that your Expansion Disc is in your CD_ROM drive, and try again.\\n\"",
          "u\"Please make sure your Diablo II Expansion Disc is in your CD-ROM drive, then click on 'Retry'.\"",
          "u\"Game.exe\"",
          "u\"CD-ROM drive error.\"",
          "u\"Diablo II.exe\"",
          "u\"Diablo II was unable to locate your CD-ROM drive.\\nPlease make sure your Diablo II Expansion Disc is in your CD-ROM drive, then click on 'Retry'.\"",
          "u\"Please verify that your Diablo II Expansion Disc is in your CD-ROM drive, then click on 'Retry'.\"",
          "u\"Diablo II was unable to detect a Disc in your CD-ROM drive.\\nPlease make sure your Diablo II Expansion Disc is in your CD-ROM drive, then click on 'Retry'.\"",
          "u\"Diablo II failed to run.\\nPlease make sure your Diablo II Expansion Disc is in your CD-ROM drive, then click on 'Retry'.\""
        ]
      },
      "instruction_counts": {
        "LoD/1.07": 299,
        "LoD/1.08": 299,
        "LoD/1.09": 299,
        "LoD/1.09b": 299,
        "LoD/1.09d": 299,
        "LoD/1.10": 299,
        "LoD/1.11": 299,
        "LoD/1.11b": 299,
        "LoD/1.12a": 299,
        "LoD/1.13c": 299,
        "LoD/1.13d": 299,
        "LoD/1.14a": 299,
        "LoD/1.14b": 299,
        "LoD/1.14c": 299,
        "LoD/1.14d": 299
      },
      "stack_frame_sizes": {
        "LoD/1.07": 1680,
        "LoD/1.08": 1680,
        "LoD/1.09": 1680,
        "LoD/1.09b": 1680,
        "LoD/1.09d": 1680,
        "LoD/1.10": 1680,
        "LoD/1.11": 1680,
        "LoD/1.11b": 1680,
        "LoD/1.12a": 1680,
        "LoD/1.13c": 1680,
        "LoD/1.13d": 1680,
        "LoD/1.14a": 1680,
        "LoD/1.14b": 1680,
        "LoD/1.14c": 1680,
        "LoD/1.14d": 1680
      },
      "basic_block_counts": {
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
        "LoD/1.13d": 23,
        "LoD/1.14a": 23,
        "LoD/1.14b": 23,
        "LoD/1.14c": 23,
        "LoD/1.14d": 23
      },
      "loop_counts": {
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
        "LoD/1.13d": 3,
        "LoD/1.14a": 3,
        "LoD/1.14b": 3,
        "LoD/1.14c": 3,
        "LoD/1.14d": 3
      },
      "mnemonic_hashes": {
        "LoD/1.07": "bf8c322b1dd06995c54b40d971c644e5",
        "LoD/1.08": "bf8c322b1dd06995c54b40d971c644e5",
        "LoD/1.09": "bf8c322b1dd06995c54b40d971c644e5",
        "LoD/1.09b": "bf8c322b1dd06995c54b40d971c644e5",
        "LoD/1.09d": "bf8c322b1dd06995c54b40d971c644e5",
        "LoD/1.10": "bf8c322b1dd06995c54b40d971c644e5",
        "LoD/1.11": "bf8c322b1dd06995c54b40d971c644e5",
        "LoD/1.11b": "bf8c322b1dd06995c54b40d971c644e5",
        "LoD/1.12a": "bf8c322b1dd06995c54b40d971c644e5",
        "LoD/1.13c": "bf8c322b1dd06995c54b40d971c644e5",
        "LoD/1.13d": "bf8c322b1dd06995c54b40d971c644e5",
        "LoD/1.14a": "bf8c322b1dd06995c54b40d971c644e5",
        "LoD/1.14b": "bf8c322b1dd06995c54b40d971c644e5",
        "LoD/1.14c": "bf8c322b1dd06995c54b40d971c644e5",
        "LoD/1.14d": "bf8c322b1dd06995c54b40d971c644e5"
      },
      "constants": {
        "LoD/1.07": [
          260,
          312,
          316,
          380,
          388,
          640,
          644,
          652,
          900,
          1160
        ],
        "LoD/1.08": [
          260,
          312,
          316,
          380,
          388,
          640,
          644,
          652,
          900,
          1160
        ],
        "LoD/1.09": [
          260,
          312,
          316,
          380,
          388,
          640,
          644,
          652,
          900,
          1160
        ],
        "LoD/1.09b": [
          260,
          312,
          316,
          380,
          388,
          640,
          644,
          652,
          900,
          1160
        ],
        "LoD/1.09d": [
          260,
          312,
          316,
          380,
          388,
          640,
          644,
          652,
          900,
          1160
        ],
        "LoD/1.10": [
          260,
          312,
          316,
          380,
          388,
          640,
          644,
          652,
          900,
          1160
        ],
        "LoD/1.11": [
          260,
          312,
          316,
          380,
          388,
          640,
          644,
          652,
          900,
          1160
        ],
        "LoD/1.11b": [
          260,
          312,
          316,
          380,
          388,
          640,
          644,
          652,
          900,
          1160
        ],
        "LoD/1.12a": [
          260,
          312,
          316,
          380,
          388,
          640,
          644,
          652,
          900,
          1160
        ],
        "LoD/1.13c": [
          260,
          312,
          316,
          380,
          388,
          640,
          644,
          652,
          900,
          1160
        ],
        "LoD/1.13d": [
          260,
          312,
          316,
          380,
          388,
          640,
          644,
          652,
          900,
          1160
        ],
        "LoD/1.14a": [
          260,
          312,
          316,
          380,
          388,
          640,
          644,
          652,
          900,
          1160
        ],
        "LoD/1.14b": [
          260,
          312,
          316,
          380,
          388,
          640,
          644,
          652,
          900,
          1160
        ],
        "LoD/1.14c": [
          260,
          312,
          316,
          380,
          388,
          640,
          644,
          652,
          900,
          1160
        ],
        "LoD/1.14d": [
          260,
          312,
          316,
          380,
          388,
          640,
          644,
          652,
          900,
          1160
        ]
      },
      "globals": {
        "LoD/1.07": [
          "0x6038|s_DIABLO_II_OK_00406038",
          "0xFFFFFFFFFFBFF980|",
          "0x5018|PTR_CreateEventA_00405018",
          "0x5014|PTR_GetLastError_00405014",
          "0x50B0|PTR_LoadStringA_004050b0",
          "0x7EBA|pu_Game.exe_00407eba",
          "0x82CC|pu_Diablo_II.exe_004082cc",
          "0x5010|PTR_GetCommandLineA_00405010",
          "0x6034|DAT_00406034",
          "0x6035|DAT_00406035"
        ],
        "LoD/1.08": [
          "0x6038|s_DIABLO_II_OK_00406038",
          "0xFFFFFFFFFFBFF980|",
          "0x5018|PTR_CreateEventA_00405018",
          "0x5014|PTR_GetLastError_00405014",
          "0x50B0|PTR_LoadStringA_004050b0",
          "0x7EBA|pu_Game.exe_00407eba",
          "0x82CC|pu_Diablo_II.exe_004082cc",
          "0x5010|PTR_GetCommandLineA_00405010",
          "0x6034|DAT_00406034",
          "0x6035|DAT_00406035"
        ],
        "LoD/1.09": [
          "0x6038|s_DIABLO_II_OK_00406038",
          "0xFFFFFFFFFFBFF980|",
          "0x5018|PTR_CreateEventA_00405018",
          "0x5014|PTR_GetLastError_00405014",
          "0x50B0|PTR_LoadStringA_004050b0",
          "0x7EBA|pu_Game.exe_00407eba",
          "0x82CC|pu_Diablo_II.exe_004082cc",
          "0x5010|PTR_GetCommandLineA_00405010",
          "0x6034|DAT_00406034",
          "0x6035|DAT_00406035"
        ],
        "LoD/1.09b": [
          "0x6038|s_DIABLO_II_OK_00406038",
          "0xFFFFFFFFFFBFF980|",
          "0x5018|PTR_CreateEventA_00405018",
          "0x5014|PTR_GetLastError_00405014",
          "0x50B0|PTR_LoadStringA_004050b0",
          "0x7EBA|pu_Game.exe_00407eba",
          "0x82CC|pu_Diablo_II.exe_004082cc",
          "0x5010|PTR_GetCommandLineA_00405010",
          "0x6034|DAT_00406034",
          "0x6035|DAT_00406035"
        ],
        "LoD/1.09d": [
          "0x6038|s_DIABLO_II_OK_00406038",
          "0xFFFFFFFFFFBFF980|",
          "0x5018|PTR_CreateEventA_00405018",
          "0x5014|PTR_GetLastError_00405014",
          "0x50B0|PTR_LoadStringA_004050b0",
          "0x7EBA|pu_Game.exe_00407eba",
          "0x82CC|pu_Diablo_II.exe_004082cc",
          "0x5010|PTR_GetCommandLineA_00405010",
          "0x6034|DAT_00406034",
          "0x6035|DAT_00406035"
        ],
        "LoD/1.10": [
          "0x6038|s_DIABLO_II_OK_00406038",
          "0xFFFFFFFFFFBFF980|",
          "0x5018|PTR_CreateEventA_00405018",
          "0x5014|PTR_GetLastError_00405014",
          "0x50B0|PTR_LoadStringA_004050b0",
          "0x7EBA|pu_Game.exe_00407eba",
          "0x82CC|pu_Diablo_II.exe_004082cc",
          "0x5010|PTR_GetCommandLineA_00405010",
          "0x6034|DAT_00406034",
          "0x6035|DAT_00406035"
        ],
        "LoD/1.11": [
          "0x6038|s_DIABLO_II_OK_00406038",
          "0xFFFFFFFFFFBFF980|",
          "0x5018|PTR_CreateEventA_00405018",
          "0x5014|PTR_GetLastError_00405014",
          "0x50B0|PTR_LoadStringA_004050b0",
          "0x7EBA|pu_Game.exe_00407eba",
          "0x82CC|pu_Diablo_II.exe_004082cc",
          "0x5010|PTR_GetCommandLineA_00405010",
          "0x6034|DAT_00406034",
          "0x6035|DAT_00406035"
        ],
        "LoD/1.11b": [
          "0x6038|s_DIABLO_II_OK_00406038",
          "0xFFFFFFFFFFBFF980|",
          "0x5018|PTR_CreateEventA_00405018",
          "0x5014|PTR_GetLastError_00405014",
          "0x50B0|PTR_LoadStringA_004050b0",
          "0x7EBA|pu_Game.exe_00407eba",
          "0x82CC|pu_Diablo_II.exe_004082cc",
          "0x5010|PTR_GetCommandLineA_00405010",
          "0x6034|DAT_00406034",
          "0x6035|DAT_00406035"
        ],
        "LoD/1.12a": [
          "0x6038|s_DIABLO_II_OK_00406038",
          "0xFFFFFFFFFFBFF980|",
          "0x5018|PTR_CreateEventA_00405018",
          "0x5014|PTR_GetLastError_00405014",
          "0x50B0|PTR_LoadStringA_004050b0",
          "0x7EBA|pu_Game.exe_00407eba",
          "0x82CC|pu_Diablo_II.exe_004082cc",
          "0x5010|PTR_GetCommandLineA_00405010",
          "0x6034|DAT_00406034",
          "0x6035|DAT_00406035"
        ],
        "LoD/1.13c": [
          "0x6038|s_DIABLO_II_OK_00406038",
          "0xFFFFFFFFFFBFF980|",
          "0x5018|PTR_CreateEventA_00405018",
          "0x5014|PTR_GetLastError_00405014",
          "0x50B0|PTR_LoadStringA_004050b0",
          "0x7EBA|pu_Game.exe_00407eba",
          "0x82CC|pu_Diablo_II.exe_004082cc",
          "0x5010|PTR_GetCommandLineA_00405010",
          "0x6034|DAT_00406034",
          "0x6035|DAT_00406035"
        ],
        "LoD/1.13d": [
          "0x6038|s_DIABLO_II_OK_00406038",
          "0xFFFFFFFFFFBFF980|",
          "0x5018|PTR_CreateEventA_00405018",
          "0x5014|PTR_GetLastError_00405014",
          "0x50B0|PTR_LoadStringA_004050b0",
          "0x7EBA|pu_Game.exe_00407eba",
          "0x82CC|pu_Diablo_II.exe_004082cc",
          "0x5010|PTR_GetCommandLineA_00405010",
          "0x6034|DAT_00406034",
          "0x6035|DAT_00406035"
        ],
        "LoD/1.14a": [
          "0x6038|s_DIABLO_II_OK_00406038",
          "0xFFFFFFFFFFBFF980|",
          "0x5018|PTR_CreateEventA_00405018",
          "0x5014|PTR_GetLastError_00405014",
          "0x50B0|PTR_LoadStringA_004050b0",
          "0x7EBA|pu_Game.exe_00407eba",
          "0x82CC|pu_Diablo_II.exe_004082cc",
          "0x5010|PTR_GetCommandLineA_00405010",
          "0x6034|DAT_00406034",
          "0x6035|DAT_00406035"
        ],
        "LoD/1.14b": [
          "0x6038|s_DIABLO_II_OK_00406038",
          "0xFFFFFFFFFFBFF980|",
          "0x5018|PTR_CreateEventA_00405018",
          "0x5014|PTR_GetLastError_00405014",
          "0x50B0|PTR_LoadStringA_004050b0",
          "0x7EBA|pu_Game.exe_00407eba",
          "0x82CC|pu_Diablo_II.exe_004082cc",
          "0x5010|PTR_GetCommandLineA_00405010",
          "0x6034|DAT_00406034",
          "0x6035|DAT_00406035"
        ],
        "LoD/1.14c": [
          "0x6038|s_DIABLO_II_OK_00406038",
          "0xFFFFFFFFFFBFF980|",
          "0x5018|PTR_CreateEventA_00405018",
          "0x5014|PTR_GetLastError_00405014",
          "0x50B0|PTR_LoadStringA_004050b0",
          "0x7EBA|pu_Game.exe_00407eba",
          "0x82CC|pu_Diablo_II.exe_004082cc",
          "0x5010|PTR_GetCommandLineA_00405010",
          "0x6034|DAT_00406034",
          "0x6035|DAT_00406035"
        ],
        "LoD/1.14d": [
          "0x6038|s_DIABLO_II_OK_00406038",
          "0xFFFFFFFFFFBFF980|",
          "0x5018|PTR_CreateEventA_00405018",
          "0x5014|PTR_GetLastError_00405014",
          "0x50B0|PTR_LoadStringA_004050b0",
          "0x7EBA|pu_Game.exe_00407eba",
          "0x82CC|pu_Diablo_II.exe_004082cc",
          "0x5010|PTR_GetCommandLineA_00405010",
          "0x6034|DAT_00406034",
          "0x6035|DAT_00406035"
        ]
      }
    },
    "diablo ii.exe_MNE_0ae7612051bc": {
      "addresses": {
        "LoD/1.07": "0x004013B0",
        "LoD/1.08": "0x004013B0",
        "LoD/1.09": "0x004013B0",
        "LoD/1.09b": "0x004013B0",
        "LoD/1.09d": "0x004013B0",
        "LoD/1.10": "0x004013B0",
        "LoD/1.11": "0x004013B0",
        "LoD/1.11b": "0x004013B0",
        "LoD/1.12a": "0x004013B0",
        "LoD/1.13c": "0x004013B0",
        "LoD/1.13d": "0x004013B0",
        "LoD/1.14a": "0x004013B0",
        "LoD/1.14b": "0x004013B0",
        "LoD/1.14c": "0x004013B0",
        "LoD/1.14d": "0x004013B0"
      },
      "rvas": {
        "LoD/1.07": "0x13B0",
        "LoD/1.08": "0x13B0",
        "LoD/1.09": "0x13B0",
        "LoD/1.09b": "0x13B0",
        "LoD/1.09d": "0x13B0",
        "LoD/1.10": "0x13B0",
        "LoD/1.11": "0x13B0",
        "LoD/1.11b": "0x13B0",
        "LoD/1.12a": "0x13B0",
        "LoD/1.13c": "0x13B0",
        "LoD/1.13d": "0x13B0",
        "LoD/1.14a": "0x13B0",
        "LoD/1.14b": "0x13B0",
        "LoD/1.14c": "0x13B0",
        "LoD/1.14d": "0x13B0"
      },
      "sizes": {
        "LoD/1.07": 189,
        "LoD/1.08": 189,
        "LoD/1.09": 189,
        "LoD/1.09b": 189,
        "LoD/1.09d": 189,
        "LoD/1.10": 189,
        "LoD/1.11": 189,
        "LoD/1.11b": 189,
        "LoD/1.12a": 189,
        "LoD/1.13c": 189,
        "LoD/1.13d": 189,
        "LoD/1.14a": 189,
        "LoD/1.14b": 189,
        "LoD/1.14c": 189,
        "LoD/1.14d": 189
      },
      "return_type": "byte *",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:0ae7612051bc2c351ff4baa78f16b259",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "0ae7612051bc2c351ff4baa78f16b259",
        "CFG": "8677e4ae8cbf70d01424b1301aab8351",
        "PRO": "b7f126c199604b0f1fe6e9b462063d20",
        "CAL": null,
        "CON": null,
        "APS": null
      },
      "display_name": "FUN_004013b0",
      "callees": {
        "LoD/1.07": [
          "FUN_00401a02|0x401A02",
          "_strncat|0x401A40"
        ],
        "LoD/1.08": [
          "FUN_00401a02|0x401A02",
          "_strncat|0x401A40"
        ],
        "LoD/1.09": [
          "_strncat|0x401A40",
          "FUN_00401a02|0x401A02"
        ],
        "LoD/1.09b": [
          "FUN_00401a02|0x401A02",
          "_strncat|0x401A40"
        ],
        "LoD/1.09d": [
          "_strncat|0x401A40",
          "FUN_00401a02|0x401A02"
        ],
        "LoD/1.10": [
          "_strncat|0x401A40",
          "FUN_00401a02|0x401A02"
        ],
        "LoD/1.11": [
          "_strncat|0x401A40",
          "FUN_00401a02|0x401A02"
        ],
        "LoD/1.11b": [
          "FUN_00401a02|0x401A02",
          "_strncat|0x401A40"
        ],
        "LoD/1.12a": [
          "_strncat|0x401A40",
          "FUN_00401a02|0x401A02"
        ],
        "LoD/1.13c": [
          "_strncat|0x401A40",
          "FUN_00401a02|0x401A02"
        ],
        "LoD/1.13d": [
          "_strncat|0x401A40",
          "FUN_00401a02|0x401A02"
        ],
        "LoD/1.14a": [
          "FUN_00401a02|0x401A02",
          "_strncat|0x401A40"
        ],
        "LoD/1.14b": [
          "FUN_00401a02|0x401A02",
          "_strncat|0x401A40"
        ],
        "LoD/1.14c": [
          "_strncat|0x401A40",
          "FUN_00401a02|0x401A02"
        ],
        "LoD/1.14d": [
          "_strncat|0x401A40",
          "FUN_00401a02|0x401A02"
        ]
      },
      "callers": {
        "LoD/1.07": [
          "FUN_00401000|0x401000"
        ],
        "LoD/1.08": [
          "FUN_00401000|0x401000"
        ],
        "LoD/1.09": [
          "FUN_00401000|0x401000"
        ],
        "LoD/1.09b": [
          "FUN_00401000|0x401000"
        ],
        "LoD/1.09d": [
          "FUN_00401000|0x401000"
        ],
        "LoD/1.10": [
          "FUN_00401000|0x401000"
        ],
        "LoD/1.11": [
          "FUN_00401000|0x401000"
        ],
        "LoD/1.11b": [
          "FUN_00401000|0x401000"
        ],
        "LoD/1.12a": [
          "FUN_00401000|0x401000"
        ],
        "LoD/1.13c": [
          "FUN_00401000|0x401000"
        ],
        "LoD/1.13d": [
          "FUN_00401000|0x401000"
        ],
        "LoD/1.14a": [
          "FUN_00401000|0x401000"
        ],
        "LoD/1.14b": [
          "FUN_00401000|0x401000"
        ],
        "LoD/1.14c": [
          "FUN_00401000|0x401000"
        ],
        "LoD/1.14d": [
          "FUN_00401000|0x401000"
        ]
      },
      "instruction_counts": {
        "LoD/1.07": 88,
        "LoD/1.08": 88,
        "LoD/1.09": 88,
        "LoD/1.09b": 88,
        "LoD/1.09d": 88,
        "LoD/1.10": 88,
        "LoD/1.11": 88,
        "LoD/1.11b": 88,
        "LoD/1.12a": 88,
        "LoD/1.13c": 88,
        "LoD/1.13d": 88,
        "LoD/1.14a": 88,
        "LoD/1.14b": 88,
        "LoD/1.14c": 88,
        "LoD/1.14d": 88
      },
      "stack_frame_sizes": {
        "LoD/1.07": 16,
        "LoD/1.08": 16,
        "LoD/1.09": 16,
        "LoD/1.09b": 16,
        "LoD/1.09d": 16,
        "LoD/1.10": 16,
        "LoD/1.11": 16,
        "LoD/1.11b": 16,
        "LoD/1.12a": 16,
        "LoD/1.13c": 16,
        "LoD/1.13d": 16,
        "LoD/1.14a": 16,
        "LoD/1.14b": 16,
        "LoD/1.14c": 16,
        "LoD/1.14d": 16
      },
      "basic_block_counts": {
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
        "LoD/1.13d": 23,
        "LoD/1.14a": 23,
        "LoD/1.14b": 23,
        "LoD/1.14c": 23,
        "LoD/1.14d": 23
      },
      "loop_counts": {
        "LoD/1.07": 2,
        "LoD/1.08": 2,
        "LoD/1.09": 2,
        "LoD/1.09b": 2,
        "LoD/1.09d": 2,
        "LoD/1.10": 2,
        "LoD/1.11": 2,
        "LoD/1.11b": 2,
        "LoD/1.12a": 2,
        "LoD/1.13c": 2,
        "LoD/1.13d": 2,
        "LoD/1.14a": 2,
        "LoD/1.14b": 2,
        "LoD/1.14c": 2,
        "LoD/1.14d": 2
      },
      "mnemonic_hashes": {
        "LoD/1.07": "0ae7612051bc2c351ff4baa78f16b259",
        "LoD/1.08": "0ae7612051bc2c351ff4baa78f16b259",
        "LoD/1.09": "0ae7612051bc2c351ff4baa78f16b259",
        "LoD/1.09b": "0ae7612051bc2c351ff4baa78f16b259",
        "LoD/1.09d": "0ae7612051bc2c351ff4baa78f16b259",
        "LoD/1.10": "0ae7612051bc2c351ff4baa78f16b259",
        "LoD/1.11": "0ae7612051bc2c351ff4baa78f16b259",
        "LoD/1.11b": "0ae7612051bc2c351ff4baa78f16b259",
        "LoD/1.12a": "0ae7612051bc2c351ff4baa78f16b259",
        "LoD/1.13c": "0ae7612051bc2c351ff4baa78f16b259",
        "LoD/1.13d": "0ae7612051bc2c351ff4baa78f16b259",
        "LoD/1.14a": "0ae7612051bc2c351ff4baa78f16b259",
        "LoD/1.14b": "0ae7612051bc2c351ff4baa78f16b259",
        "LoD/1.14c": "0ae7612051bc2c351ff4baa78f16b259",
        "LoD/1.14d": "0ae7612051bc2c351ff4baa78f16b259"
      },
      "constants": {
        "LoD/1.07": [
          4221121
        ],
        "LoD/1.08": [
          4221121
        ],
        "LoD/1.09": [
          4221121
        ],
        "LoD/1.09b": [
          4221121
        ],
        "LoD/1.09d": [
          4221121
        ],
        "LoD/1.10": [
          4221121
        ],
        "LoD/1.11": [
          4221121
        ],
        "LoD/1.11b": [
          4221121
        ],
        "LoD/1.12a": [
          4221121
        ],
        "LoD/1.13c": [
          4221121
        ],
        "LoD/1.13d": [
          4221121
        ],
        "LoD/1.14a": [
          4221121
        ],
        "LoD/1.14b": [
          4221121
        ],
        "LoD/1.14c": [
          4221121
        ],
        "LoD/1.14d": [
          4221121
        ]
      },
      "globals": {
        "LoD/1.07": [
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00004|",
          "0x67AC|g_fIsMultiByteCodePage",
          "0xFFFFFFFFFFC00008|",
          "0x68C1|DAT_004068c0+1"
        ],
        "LoD/1.08": [
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00004|",
          "0x67AC|g_fIsMultiByteCodePage",
          "0xFFFFFFFFFFC00008|",
          "0x68C1|DAT_004068c0+1"
        ],
        "LoD/1.09": [
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00004|",
          "0x67AC|g_fIsMultiByteCodePage",
          "0xFFFFFFFFFFC00008|",
          "0x68C1|DAT_004068c0+1"
        ],
        "LoD/1.09b": [
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00004|",
          "0x67AC|g_fIsMultiByteCodePage",
          "0xFFFFFFFFFFC00008|",
          "0x68C1|DAT_004068c0+1"
        ],
        "LoD/1.09d": [
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00004|",
          "0x67AC|g_fIsMultiByteCodePage",
          "0xFFFFFFFFFFC00008|",
          "0x68C1|DAT_004068c0+1"
        ],
        "LoD/1.10": [
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00004|",
          "0x67AC|g_fIsMultiByteCodePage",
          "0xFFFFFFFFFFC00008|",
          "0x68C1|DAT_004068c0+1"
        ],
        "LoD/1.11": [
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00004|",
          "0x67AC|g_fIsMultiByteCodePage",
          "0xFFFFFFFFFFC00008|",
          "0x68C1|DAT_004068c0+1"
        ],
        "LoD/1.11b": [
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00004|",
          "0x67AC|g_fIsMultiByteCodePage",
          "0xFFFFFFFFFFC00008|",
          "0x68C1|DAT_004068c0+1"
        ],
        "LoD/1.12a": [
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00004|",
          "0x67AC|g_fIsMultiByteCodePage",
          "0xFFFFFFFFFFC00008|",
          "0x68C1|DAT_004068c0+1"
        ],
        "LoD/1.13c": [
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00004|",
          "0x67AC|g_fIsMultiByteCodePage",
          "0xFFFFFFFFFFC00008|",
          "0x68C1|DAT_004068c0+1"
        ],
        "LoD/1.13d": [
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00004|",
          "0x67AC|g_fIsMultiByteCodePage",
          "0xFFFFFFFFFFC00008|",
          "0x68C1|DAT_004068c0+1"
        ],
        "LoD/1.14a": [
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00004|",
          "0x67AC|g_fIsMultiByteCodePage",
          "0xFFFFFFFFFFC00008|",
          "0x68C1|DAT_004068c0+1"
        ],
        "LoD/1.14b": [
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00004|",
          "0x67AC|g_fIsMultiByteCodePage",
          "0xFFFFFFFFFFC00008|",
          "0x68C1|DAT_004068c0+1"
        ],
        "LoD/1.14c": [
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00004|",
          "0x67AC|g_fIsMultiByteCodePage",
          "0xFFFFFFFFFFC00008|",
          "0x68C1|DAT_004068c0+1"
        ],
        "LoD/1.14d": [
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00004|",
          "0x67AC|g_fIsMultiByteCodePage",
          "0xFFFFFFFFFFC00008|",
          "0x68C1|DAT_004068c0+1"
        ]
      }
    },
    "diablo ii.exe_MNE_e63ed098730a": {
      "addresses": {
        "LoD/1.07": "0x0040146D",
        "LoD/1.08": "0x0040146D",
        "LoD/1.09": "0x0040146D",
        "LoD/1.09b": "0x0040146D",
        "LoD/1.09d": "0x0040146D",
        "LoD/1.10": "0x0040146D",
        "LoD/1.11": "0x0040146D",
        "LoD/1.11b": "0x0040146D",
        "LoD/1.12a": "0x0040146D",
        "LoD/1.13c": "0x0040146D",
        "LoD/1.13d": "0x0040146D",
        "LoD/1.14a": "0x0040146D",
        "LoD/1.14b": "0x0040146D",
        "LoD/1.14c": "0x0040146D",
        "LoD/1.14d": "0x0040146D"
      },
      "rvas": {
        "LoD/1.07": "0x146D",
        "LoD/1.08": "0x146D",
        "LoD/1.09": "0x146D",
        "LoD/1.09b": "0x146D",
        "LoD/1.09d": "0x146D",
        "LoD/1.10": "0x146D",
        "LoD/1.11": "0x146D",
        "LoD/1.11b": "0x146D",
        "LoD/1.12a": "0x146D",
        "LoD/1.13c": "0x146D",
        "LoD/1.13d": "0x146D",
        "LoD/1.14a": "0x146D",
        "LoD/1.14b": "0x146D",
        "LoD/1.14c": "0x146D",
        "LoD/1.14d": "0x146D"
      },
      "sizes": {
        "LoD/1.07": 118,
        "LoD/1.08": 118,
        "LoD/1.09": 118,
        "LoD/1.09b": 118,
        "LoD/1.09d": 118,
        "LoD/1.10": 118,
        "LoD/1.11": 118,
        "LoD/1.11b": 118,
        "LoD/1.12a": 118,
        "LoD/1.13c": 118,
        "LoD/1.13d": 118,
        "LoD/1.14a": 118,
        "LoD/1.14b": 118,
        "LoD/1.14c": 118,
        "LoD/1.14d": 118
      },
      "return_type": "uint *",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:e63ed098730a213950e38bf7d491270b",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "e63ed098730a213950e38bf7d491270b",
        "CFG": "5f05e3e4b6b85141bd532cebeaa4c0e1",
        "PRO": "c28c57488c736ef8416365a079852ca1",
        "CAL": null,
        "CON": null,
        "APS": null
      },
      "display_name": "FUN_0040146d",
      "callees": {
        "LoD/1.07": [
          "FUN_00401b63|0x401B63",
          "FUN_00401c00|0x401C00",
          "_strlen|0x401B80"
        ],
        "LoD/1.08": [
          "FUN_00401b63|0x401B63",
          "_strlen|0x401B80",
          "_strstr|0x401C00"
        ],
        "LoD/1.09": [
          "_strlen|0x401B80",
          "FUN_00401b63|0x401B63",
          "_strstr|0x401C00"
        ],
        "LoD/1.09b": [
          "FUN_00401b63|0x401B63",
          "_strstr|0x401C00",
          "_strlen|0x401B80"
        ],
        "LoD/1.09d": [
          "_strlen|0x401B80",
          "FUN_00401b63|0x401B63",
          "_strstr|0x401C00"
        ],
        "LoD/1.10": [
          "_strstr|0x401C00",
          "FUN_00401b63|0x401B63",
          "_strlen|0x401B80"
        ],
        "LoD/1.11": [
          "FUN_00401b63|0x401B63",
          "_strstr|0x401C00",
          "_strlen|0x401B80"
        ],
        "LoD/1.11b": [
          "_strlen|0x401B80",
          "_strstr|0x401C00",
          "FUN_00401b63|0x401B63"
        ],
        "LoD/1.12a": [
          "_strstr|0x401C00",
          "_strlen|0x401B80",
          "FUN_00401b63|0x401B63"
        ],
        "LoD/1.13c": [
          "_strlen|0x401B80",
          "FUN_00401b63|0x401B63",
          "_strstr|0x401C00"
        ],
        "LoD/1.13d": [
          "_strlen|0x401B80",
          "FUN_00401b63|0x401B63",
          "_strstr|0x401C00"
        ],
        "LoD/1.14a": [
          "FUN_00401b63|0x401B63",
          "_strstr|0x401C00",
          "_strlen|0x401B80"
        ],
        "LoD/1.14b": [
          "_strstr|0x401C00",
          "FUN_00401b63|0x401B63",
          "_strlen|0x401B80"
        ],
        "LoD/1.14c": [
          "_strlen|0x401B80",
          "FUN_00401b63|0x401B63",
          "_strstr|0x401C00"
        ],
        "LoD/1.14d": [
          "FUN_00401b63|0x401B63",
          "_strstr|0x401C00",
          "_strlen|0x401B80"
        ]
      },
      "callers": {
        "LoD/1.07": [
          "FUN_00401000|0x401000"
        ],
        "LoD/1.08": [
          "FUN_00401000|0x401000"
        ],
        "LoD/1.09": [
          "FUN_00401000|0x401000"
        ],
        "LoD/1.09b": [
          "FUN_00401000|0x401000"
        ],
        "LoD/1.09d": [
          "FUN_00401000|0x401000"
        ],
        "LoD/1.10": [
          "FUN_00401000|0x401000"
        ],
        "LoD/1.11": [
          "FUN_00401000|0x401000"
        ],
        "LoD/1.11b": [
          "FUN_00401000|0x401000"
        ],
        "LoD/1.12a": [
          "FUN_00401000|0x401000"
        ],
        "LoD/1.13c": [
          "FUN_00401000|0x401000"
        ],
        "LoD/1.13d": [
          "FUN_00401000|0x401000"
        ],
        "LoD/1.14a": [
          "FUN_00401000|0x401000"
        ],
        "LoD/1.14b": [
          "FUN_00401000|0x401000"
        ],
        "LoD/1.14c": [
          "FUN_00401000|0x401000"
        ],
        "LoD/1.14d": [
          "FUN_00401000|0x401000"
        ]
      },
      "instruction_counts": {
        "LoD/1.07": 56,
        "LoD/1.08": 56,
        "LoD/1.09": 56,
        "LoD/1.09b": 56,
        "LoD/1.09d": 56,
        "LoD/1.10": 56,
        "LoD/1.11": 56,
        "LoD/1.11b": 56,
        "LoD/1.12a": 56,
        "LoD/1.13c": 56,
        "LoD/1.13d": 56,
        "LoD/1.14a": 56,
        "LoD/1.14b": 56,
        "LoD/1.14c": 56,
        "LoD/1.14d": 56
      },
      "stack_frame_sizes": {
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
        "LoD/1.13d": 12,
        "LoD/1.14a": 12,
        "LoD/1.14b": 12,
        "LoD/1.14c": 12,
        "LoD/1.14d": 12
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
        "LoD/1.13d": 15,
        "LoD/1.14a": 15,
        "LoD/1.14b": 15,
        "LoD/1.14c": 15,
        "LoD/1.14d": 15
      },
      "loop_counts": {
        "LoD/1.07": 2,
        "LoD/1.08": 2,
        "LoD/1.09": 2,
        "LoD/1.09b": 2,
        "LoD/1.09d": 2,
        "LoD/1.10": 2,
        "LoD/1.11": 2,
        "LoD/1.11b": 2,
        "LoD/1.12a": 2,
        "LoD/1.13c": 2,
        "LoD/1.13d": 2,
        "LoD/1.14a": 2,
        "LoD/1.14b": 2,
        "LoD/1.14c": 2,
        "LoD/1.14d": 2
      },
      "mnemonic_hashes": {
        "LoD/1.07": "e63ed098730a213950e38bf7d491270b",
        "LoD/1.08": "e63ed098730a213950e38bf7d491270b",
        "LoD/1.09": "e63ed098730a213950e38bf7d491270b",
        "LoD/1.09b": "e63ed098730a213950e38bf7d491270b",
        "LoD/1.09d": "e63ed098730a213950e38bf7d491270b",
        "LoD/1.10": "e63ed098730a213950e38bf7d491270b",
        "LoD/1.11": "e63ed098730a213950e38bf7d491270b",
        "LoD/1.11b": "e63ed098730a213950e38bf7d491270b",
        "LoD/1.12a": "e63ed098730a213950e38bf7d491270b",
        "LoD/1.13c": "e63ed098730a213950e38bf7d491270b",
        "LoD/1.13d": "e63ed098730a213950e38bf7d491270b",
        "LoD/1.14a": "e63ed098730a213950e38bf7d491270b",
        "LoD/1.14b": "e63ed098730a213950e38bf7d491270b",
        "LoD/1.14c": "e63ed098730a213950e38bf7d491270b",
        "LoD/1.14d": "e63ed098730a213950e38bf7d491270b"
      },
      "globals": {
        "LoD/1.07": [
          "0x67AC|g_fIsMultiByteCodePage",
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.08": [
          "0x67AC|g_fIsMultiByteCodePage",
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.09": [
          "0x67AC|g_fIsMultiByteCodePage",
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.09b": [
          "0x67AC|g_fIsMultiByteCodePage",
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.09d": [
          "0x67AC|g_fIsMultiByteCodePage",
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.10": [
          "0x67AC|g_fIsMultiByteCodePage",
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.11": [
          "0x67AC|g_fIsMultiByteCodePage",
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.11b": [
          "0x67AC|g_fIsMultiByteCodePage",
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.12a": [
          "0x67AC|g_fIsMultiByteCodePage",
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.13c": [
          "0x67AC|g_fIsMultiByteCodePage",
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.13d": [
          "0x67AC|g_fIsMultiByteCodePage",
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.14a": [
          "0x67AC|g_fIsMultiByteCodePage",
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.14b": [
          "0x67AC|g_fIsMultiByteCodePage",
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.14c": [
          "0x67AC|g_fIsMultiByteCodePage",
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.14d": [
          "0x67AC|g_fIsMultiByteCodePage",
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|"
        ]
      }
    },
    "diablo ii.exe_CAL_69d6a3f35ed0": {
      "addresses": {
        "LoD/1.07": "0x004014E3",
        "LoD/1.08": "0x004014E3",
        "LoD/1.09": "0x004014E3",
        "LoD/1.09b": "0x004014E3",
        "LoD/1.09d": "0x004014E3",
        "LoD/1.10": "0x004014E3",
        "LoD/1.11": "0x004014E3",
        "LoD/1.11b": "0x004014E3",
        "LoD/1.12a": "0x004014E3",
        "LoD/1.13c": "0x004014E3",
        "LoD/1.13d": "0x004014E3",
        "LoD/1.14a": "0x004014E3",
        "LoD/1.14b": "0x004014E3",
        "LoD/1.14c": "0x004014E3",
        "LoD/1.14d": "0x004014E3"
      },
      "rvas": {
        "LoD/1.07": "0x14E3",
        "LoD/1.08": "0x14E3",
        "LoD/1.09": "0x14E3",
        "LoD/1.09b": "0x14E3",
        "LoD/1.09d": "0x14E3",
        "LoD/1.10": "0x14E3",
        "LoD/1.11": "0x14E3",
        "LoD/1.11b": "0x14E3",
        "LoD/1.12a": "0x14E3",
        "LoD/1.13c": "0x14E3",
        "LoD/1.13d": "0x14E3",
        "LoD/1.14a": "0x14E3",
        "LoD/1.14b": "0x14E3",
        "LoD/1.14c": "0x14E3",
        "LoD/1.14d": "0x14E3"
      },
      "sizes": {
        "LoD/1.07": 235,
        "LoD/1.08": 235,
        "LoD/1.09": 235,
        "LoD/1.09b": 235,
        "LoD/1.09d": 235,
        "LoD/1.10": 235,
        "LoD/1.11": 235,
        "LoD/1.11b": 235,
        "LoD/1.12a": 235,
        "LoD/1.13c": 235,
        "LoD/1.13d": 235,
        "LoD/1.14a": 235,
        "LoD/1.14b": 235,
        "LoD/1.14c": 235,
        "LoD/1.14d": 235
      },
      "name": "entry",
      "return_type": "undefined",
      "name_source": "LoD/1.07",
      "method": "CAL",
      "index": "CAL:69d6a3f35ed0660493dbdad2d18d4a70",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "c37fa64bd2f36382e92794cbb2949299",
        "CFG": "e29ac4f91ecc5ba7006bc331cebfe296",
        "PRO": "00979d284d2930909980b74bf77787ef",
        "CAL": "69d6a3f35ed0660493dbdad2d18d4a70",
        "CON": "d2b975d8da09fa950f7398460f34b227",
        "APS": null
      },
      "callees": {
        "LoD/1.07": [
          "InitializeGlobalConstructors|0x401C80",
          "FUN_00401d82|0x401D82",
          "GetCommandLineA|0x5",
          "GetVersion|0xD",
          "GetModuleHandleA|0xB",
          "InitializeEnvironmentVariables|0x401F5E",
          "FUN_00401000|0x401000",
          "FUN_004015fe|0x4015FE",
          "InitializeModuleData|0x402017",
          "FUN_00401f06|0x401F06",
          "ReportError|0x401CAD",
          "InitializeFileDescriptors|0x402396",
          "GetEnvironmentStringsConverted|0x402264",
          "GetStartupInfoA|0xC",
          "InitializeDllHeapAndResources|0x402541"
        ],
        "LoD/1.08": [
          "InitializeDllHeapAndResources|0x402541",
          "InitializeGlobalConstructors|0x401C80",
          "GetStartupInfoA|0xC",
          "FUN_00401f06|0x401F06",
          "GetVersion|0xD",
          "InitializeFileDescriptors|0x402396",
          "ReportError|0x401CAD",
          "GetCommandLineA|0x5",
          "InitializeEnvironmentVariables|0x401F5E",
          "GetModuleHandleA|0xB",
          "FUN_00401d82|0x401D82",
          "InitializeModuleData|0x402017",
          "GetEnvironmentStringsConverted|0x402264",
          "FUN_00401000|0x401000",
          "FUN_004015fe|0x4015FE"
        ],
        "LoD/1.09": [
          "InitializeEnvironmentVariables|0x401F5E",
          "FUN_00401f06|0x401F06",
          "FUN_00401d82|0x401D82",
          "InitializeDllHeapAndResources|0x402541",
          "InitializeModuleData|0x402017",
          "ReportError|0x401CAD",
          "GetStartupInfoA|0xC",
          "GetEnvironmentStringsConverted|0x402264",
          "InitializeFileDescriptors|0x402396",
          "FUN_004015fe|0x4015FE",
          "GetVersion|0xD",
          "InitializeGlobalConstructors|0x401C80",
          "GetModuleHandleA|0xB",
          "FUN_00401000|0x401000",
          "GetCommandLineA|0x5"
        ],
        "LoD/1.09b": [
          "InitializeDllHeapAndResources|0x402541",
          "FUN_004015fe|0x4015FE",
          "GetCommandLineA|0x5",
          "FUN_00401d82|0x401D82",
          "ReportError|0x401CAD",
          "GetStartupInfoA|0xC",
          "InitializeFileDescriptors|0x402396",
          "GetEnvironmentStringsConverted|0x402264",
          "InitializeEnvironmentVariables|0x401F5E",
          "FUN_00401f06|0x401F06",
          "GetModuleHandleA|0xB",
          "InitializeGlobalConstructors|0x401C80",
          "FUN_00401000|0x401000",
          "GetVersion|0xD",
          "InitializeModuleData|0x402017"
        ],
        "LoD/1.09d": [
          "InitializeEnvironmentVariables|0x401F5E",
          "InitializeModuleData|0x402017",
          "InitializeGlobalConstructors|0x401C80",
          "InitializeFileDescriptors|0x402396",
          "GetModuleHandleA|0xB",
          "FUN_00401000|0x401000",
          "FUN_00401f06|0x401F06",
          "GetEnvironmentStringsConverted|0x402264",
          "FUN_00401d82|0x401D82",
          "InitializeDllHeapAndResources|0x402541",
          "FUN_004015fe|0x4015FE",
          "ReportError|0x401CAD",
          "GetStartupInfoA|0xC",
          "GetVersion|0xD",
          "GetCommandLineA|0x5"
        ],
        "LoD/1.10": [
          "InitializeFileDescriptors|0x402396",
          "InitializeGlobalConstructors|0x401C80",
          "InitializeEnvironmentVariables|0x401F5E",
          "GetEnvironmentStringsConverted|0x402264",
          "FUN_00401d82|0x401D82",
          "ReportError|0x401CAD",
          "FUN_00401000|0x401000",
          "FUN_00401f06|0x401F06",
          "InitializeDllHeapAndResources|0x402541",
          "GetVersion|0xD",
          "FUN_004015fe|0x4015FE",
          "InitializeModuleData|0x402017",
          "GetStartupInfoA|0xC",
          "GetCommandLineA|0x5",
          "GetModuleHandleA|0xB"
        ],
        "LoD/1.11": [
          "FUN_004015fe|0x4015FE",
          "InitializeEnvironmentVariables|0x401F5E",
          "GetVersion|0xD",
          "InitializeGlobalConstructors|0x401C80",
          "GetCommandLineA|0x5",
          "GetModuleHandleA|0xB",
          "InitializeFileDescriptors|0x402396",
          "GetEnvironmentStringsConverted|0x402264",
          "InitializeModuleData|0x402017",
          "InitializeDllHeapAndResources|0x402541",
          "FUN_00401f06|0x401F06",
          "FUN_00401000|0x401000",
          "FUN_00401d82|0x401D82",
          "ReportError|0x401CAD",
          "GetStartupInfoA|0xC"
        ],
        "LoD/1.11b": [
          "FUN_00401f06|0x401F06",
          "GetStartupInfoA|0xC",
          "InitializeModuleData|0x402017",
          "GetVersion|0xD",
          "InitializeDllHeapAndResources|0x402541",
          "ReportError|0x401CAD",
          "FUN_004015fe|0x4015FE",
          "FUN_00401000|0x401000",
          "GetCommandLineA|0x5",
          "GetEnvironmentStringsConverted|0x402264",
          "GetModuleHandleA|0xB",
          "InitializeGlobalConstructors|0x401C80",
          "InitializeEnvironmentVariables|0x401F5E",
          "FUN_00401d82|0x401D82",
          "InitializeFileDescriptors|0x402396"
        ],
        "LoD/1.12a": [
          "InitializeFileDescriptors|0x402396",
          "InitializeGlobalConstructors|0x401C80",
          "GetModuleHandleA|0xB",
          "GetVersion|0xD",
          "FUN_00401f06|0x401F06",
          "GetCommandLineA|0x5",
          "ReportError|0x401CAD",
          "GetStartupInfoA|0xC",
          "FUN_00401d82|0x401D82",
          "InitializeModuleData|0x402017",
          "InitializeEnvironmentVariables|0x401F5E",
          "GetEnvironmentStringsConverted|0x402264",
          "FUN_00401000|0x401000",
          "InitializeDllHeapAndResources|0x402541",
          "FUN_004015fe|0x4015FE"
        ],
        "LoD/1.13c": [
          "InitializeFileDescriptors|0x402396",
          "FUN_00401000|0x401000",
          "FUN_004015fe|0x4015FE",
          "FUN_00401d82|0x401D82",
          "ReportError|0x401CAD",
          "GetVersion|0xD",
          "InitializeGlobalConstructors|0x401C80",
          "FUN_00401f06|0x401F06",
          "InitializeDllHeapAndResources|0x402541",
          "GetEnvironmentStringsConverted|0x402264",
          "GetStartupInfoA|0xC",
          "InitializeModuleData|0x402017",
          "GetCommandLineA|0x5",
          "InitializeEnvironmentVariables|0x401F5E",
          "GetModuleHandleA|0xB"
        ],
        "LoD/1.13d": [
          "FUN_00401000|0x401000",
          "InitializeDllHeapAndResources|0x402541",
          "InitializeGlobalConstructors|0x401C80",
          "GetCommandLineA|0x5",
          "InitializeFileDescriptors|0x402396",
          "FUN_004015fe|0x4015FE",
          "InitializeModuleData|0x402017",
          "GetStartupInfoA|0xC",
          "GetModuleHandleA|0xB",
          "FUN_00401d82|0x401D82",
          "InitializeEnvironmentVariables|0x401F5E",
          "ReportError|0x401CAD",
          "GetVersion|0xD",
          "GetEnvironmentStringsConverted|0x402264",
          "FUN_00401f06|0x401F06"
        ],
        "LoD/1.14a": [
          "GetModuleHandleA|0xB",
          "GetCommandLineA|0x5",
          "InitializeGlobalConstructors|0x401C80",
          "FUN_004015fe|0x4015FE",
          "FUN_00401d82|0x401D82",
          "ReportError|0x401CAD",
          "InitializeFileDescriptors|0x402396",
          "InitializeEnvironmentVariables|0x401F5E",
          "InitializeModuleData|0x402017",
          "FUN_00401f06|0x401F06",
          "GetVersion|0xD",
          "InitializeDllHeapAndResources|0x402541",
          "FUN_00401000|0x401000",
          "GetEnvironmentStringsConverted|0x402264",
          "GetStartupInfoA|0xC"
        ],
        "LoD/1.14b": [
          "GetStartupInfoA|0xC",
          "GetModuleHandleA|0xB",
          "FUN_00401f06|0x401F06",
          "InitializeDllHeapAndResources|0x402541",
          "InitializeModuleData|0x402017",
          "InitializeGlobalConstructors|0x401C80",
          "InitializeEnvironmentVariables|0x401F5E",
          "FUN_00401d82|0x401D82",
          "InitializeFileDescriptors|0x402396",
          "GetEnvironmentStringsConverted|0x402264",
          "GetVersion|0xD",
          "ReportError|0x401CAD",
          "FUN_004015fe|0x4015FE",
          "FUN_00401000|0x401000",
          "GetCommandLineA|0x5"
        ],
        "LoD/1.14c": [
          "GetEnvironmentStringsConverted|0x402264",
          "GetModuleHandleA|0xB",
          "InitializeGlobalConstructors|0x401C80",
          "GetStartupInfoA|0xC",
          "FUN_00401d82|0x401D82",
          "GetCommandLineA|0x5",
          "InitializeFileDescriptors|0x402396",
          "InitializeEnvironmentVariables|0x401F5E",
          "FUN_00401000|0x401000",
          "ReportError|0x401CAD",
          "InitializeDllHeapAndResources|0x402541",
          "FUN_004015fe|0x4015FE",
          "InitializeModuleData|0x402017",
          "GetVersion|0xD",
          "FUN_00401f06|0x401F06"
        ],
        "LoD/1.14d": [
          "ReportError|0x401CAD",
          "FUN_00401d82|0x401D82",
          "GetEnvironmentStringsConverted|0x402264",
          "InitializeGlobalConstructors|0x401C80",
          "InitializeFileDescriptors|0x402396",
          "GetVersion|0xD",
          "InitializeEnvironmentVariables|0x401F5E",
          "InitializeDllHeapAndResources|0x402541",
          "GetCommandLineA|0x5",
          "InitializeModuleData|0x402017",
          "GetModuleHandleA|0xB",
          "GetStartupInfoA|0xC",
          "FUN_00401000|0x401000",
          "FUN_004015fe|0x4015FE",
          "FUN_00401f06|0x401F06"
        ]
      },
      "instruction_counts": {
        "LoD/1.07": 75,
        "LoD/1.08": 75,
        "LoD/1.09": 75,
        "LoD/1.09b": 75,
        "LoD/1.09d": 75,
        "LoD/1.10": 75,
        "LoD/1.11": 75,
        "LoD/1.11b": 75,
        "LoD/1.12a": 75,
        "LoD/1.13c": 75,
        "LoD/1.13d": 75,
        "LoD/1.14a": 75,
        "LoD/1.14b": 75,
        "LoD/1.14c": 75,
        "LoD/1.14d": 75
      },
      "stack_frame_sizes": {
        "LoD/1.07": 112,
        "LoD/1.08": 112,
        "LoD/1.09": 112,
        "LoD/1.09b": 112,
        "LoD/1.09d": 112,
        "LoD/1.10": 112,
        "LoD/1.11": 112,
        "LoD/1.11b": 112,
        "LoD/1.12a": 112,
        "LoD/1.13c": 112,
        "LoD/1.13d": 112,
        "LoD/1.14a": 112,
        "LoD/1.14b": 112,
        "LoD/1.14c": 112,
        "LoD/1.14d": 112
      },
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
        "LoD/1.13d": 6,
        "LoD/1.14a": 6,
        "LoD/1.14b": 6,
        "LoD/1.14c": 6,
        "LoD/1.14d": 6
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
        "LoD/1.13d": 0,
        "LoD/1.14a": 0,
        "LoD/1.14b": 0,
        "LoD/1.14c": 0,
        "LoD/1.14d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "c37fa64bd2f36382e92794cbb2949299",
        "LoD/1.08": "c37fa64bd2f36382e92794cbb2949299",
        "LoD/1.09": "c37fa64bd2f36382e92794cbb2949299",
        "LoD/1.09b": "c37fa64bd2f36382e92794cbb2949299",
        "LoD/1.09d": "c37fa64bd2f36382e92794cbb2949299",
        "LoD/1.10": "c37fa64bd2f36382e92794cbb2949299",
        "LoD/1.11": "c37fa64bd2f36382e92794cbb2949299",
        "LoD/1.11b": "c37fa64bd2f36382e92794cbb2949299",
        "LoD/1.12a": "c37fa64bd2f36382e92794cbb2949299",
        "LoD/1.13c": "c37fa64bd2f36382e92794cbb2949299",
        "LoD/1.13d": "c37fa64bd2f36382e92794cbb2949299",
        "LoD/1.14a": "c37fa64bd2f36382e92794cbb2949299",
        "LoD/1.14b": "c37fa64bd2f36382e92794cbb2949299",
        "LoD/1.14c": "c37fa64bd2f36382e92794cbb2949299",
        "LoD/1.14d": "c37fa64bd2f36382e92794cbb2949299"
      },
      "constants": {
        "LoD/1.07": [
          4204152,
          4214968
        ],
        "LoD/1.08": [
          4204152,
          4214968
        ],
        "LoD/1.09": [
          4204152,
          4214968
        ],
        "LoD/1.09b": [
          4204152,
          4214968
        ],
        "LoD/1.09d": [
          4204152,
          4214968
        ],
        "LoD/1.10": [
          4204152,
          4214968
        ],
        "LoD/1.11": [
          4204152,
          4214968
        ],
        "LoD/1.11b": [
          4204152,
          4214968
        ],
        "LoD/1.12a": [
          4204152,
          4214968
        ],
        "LoD/1.13c": [
          4204152,
          4214968
        ],
        "LoD/1.13d": [
          4204152,
          4214968
        ],
        "LoD/1.14a": [
          4204152,
          4214968
        ],
        "LoD/1.14b": [
          4204152,
          4214968
        ],
        "LoD/1.14c": [
          4204152,
          4214968
        ],
        "LoD/1.14d": [
          4204152,
          4214968
        ]
      },
      "globals": {
        "LoD/1.07": [
          "0x50B8|DAT_004050b8",
          "0x2678|LAB_00402678",
          "0xFF9FF000|ExceptionList",
          "0xFFFFFFFFFFBFFFE4|",
          "0x5030|PTR_GetVersion_00405030",
          "0x64DC|DAT_004064dc",
          "0x64D8|DAT_004064d8",
          "0x64D4|DAT_004064d4",
          "0x64D0|DAT_004064d0",
          "0xFFFFFFFFFFBFFFF8|"
        ],
        "LoD/1.08": [
          "0x50B8|DAT_004050b8",
          "0x2678|LAB_00402678",
          "0xFF9FF000|ExceptionList",
          "0xFFFFFFFFFFBFFFE4|",
          "0x5030|PTR_GetVersion_00405030",
          "0x64DC|DAT_004064dc",
          "0x64D8|DAT_004064d8",
          "0x64D4|DAT_004064d4",
          "0x64D0|DAT_004064d0",
          "0xFFFFFFFFFFBFFFF8|"
        ],
        "LoD/1.09": [
          "0x50B8|DAT_004050b8",
          "0x2678|LAB_00402678",
          "0xFF9FF000|ExceptionList",
          "0xFFFFFFFFFFBFFFE4|",
          "0x5030|PTR_GetVersion_00405030",
          "0x64DC|DAT_004064dc",
          "0x64D8|DAT_004064d8",
          "0x64D4|DAT_004064d4",
          "0x64D0|DAT_004064d0",
          "0xFFFFFFFFFFBFFFF8|"
        ],
        "LoD/1.09b": [
          "0x50B8|DAT_004050b8",
          "0x2678|LAB_00402678",
          "0xFF9FF000|ExceptionList",
          "0xFFFFFFFFFFBFFFE4|",
          "0x5030|PTR_GetVersion_00405030",
          "0x64DC|DAT_004064dc",
          "0x64D8|DAT_004064d8",
          "0x64D4|DAT_004064d4",
          "0x64D0|DAT_004064d0",
          "0xFFFFFFFFFFBFFFF8|"
        ],
        "LoD/1.09d": [
          "0x50B8|DAT_004050b8",
          "0x2678|LAB_00402678",
          "0xFF9FF000|ExceptionList",
          "0xFFFFFFFFFFBFFFE4|",
          "0x5030|PTR_GetVersion_00405030",
          "0x64DC|DAT_004064dc",
          "0x64D8|DAT_004064d8",
          "0x64D4|DAT_004064d4",
          "0x64D0|DAT_004064d0",
          "0xFFFFFFFFFFBFFFF8|"
        ],
        "LoD/1.10": [
          "0x50B8|DAT_004050b8",
          "0x2678|LAB_00402678",
          "0xFF9FF000|ExceptionList",
          "0xFFFFFFFFFFBFFFE4|",
          "0x5030|PTR_GetVersion_00405030",
          "0x64DC|DAT_004064dc",
          "0x64D8|DAT_004064d8",
          "0x64D4|DAT_004064d4",
          "0x64D0|DAT_004064d0",
          "0xFFFFFFFFFFBFFFF8|"
        ],
        "LoD/1.11": [
          "0x50B8|DAT_004050b8",
          "0x2678|LAB_00402678",
          "0xFF9FF000|ExceptionList",
          "0xFFFFFFFFFFBFFFE4|",
          "0x5030|PTR_GetVersion_00405030",
          "0x64DC|DAT_004064dc",
          "0x64D8|DAT_004064d8",
          "0x64D4|DAT_004064d4",
          "0x64D0|DAT_004064d0",
          "0xFFFFFFFFFFBFFFF8|"
        ],
        "LoD/1.11b": [
          "0x50B8|DAT_004050b8",
          "0x2678|LAB_00402678",
          "0xFF9FF000|ExceptionList",
          "0xFFFFFFFFFFBFFFE4|",
          "0x5030|PTR_GetVersion_00405030",
          "0x64DC|DAT_004064dc",
          "0x64D8|DAT_004064d8",
          "0x64D4|DAT_004064d4",
          "0x64D0|DAT_004064d0",
          "0xFFFFFFFFFFBFFFF8|"
        ],
        "LoD/1.12a": [
          "0x50B8|DAT_004050b8",
          "0x2678|LAB_00402678",
          "0xFF9FF000|ExceptionList",
          "0xFFFFFFFFFFBFFFE4|",
          "0x5030|PTR_GetVersion_00405030",
          "0x64DC|DAT_004064dc",
          "0x64D8|DAT_004064d8",
          "0x64D4|DAT_004064d4",
          "0x64D0|DAT_004064d0",
          "0xFFFFFFFFFFBFFFF8|"
        ],
        "LoD/1.13c": [
          "0x50B8|DAT_004050b8",
          "0x2678|LAB_00402678",
          "0xFF9FF000|ExceptionList",
          "0xFFFFFFFFFFBFFFE4|",
          "0x5030|PTR_GetVersion_00405030",
          "0x64DC|DAT_004064dc",
          "0x64D8|DAT_004064d8",
          "0x64D4|DAT_004064d4",
          "0x64D0|DAT_004064d0",
          "0xFFFFFFFFFFBFFFF8|"
        ],
        "LoD/1.13d": [
          "0x50B8|DAT_004050b8",
          "0x2678|LAB_00402678",
          "0xFF9FF000|ExceptionList",
          "0xFFFFFFFFFFBFFFE4|",
          "0x5030|PTR_GetVersion_00405030",
          "0x64DC|DAT_004064dc",
          "0x64D8|DAT_004064d8",
          "0x64D4|DAT_004064d4",
          "0x64D0|DAT_004064d0",
          "0xFFFFFFFFFFBFFFF8|"
        ],
        "LoD/1.14a": [
          "0x50B8|DAT_004050b8",
          "0x2678|LAB_00402678",
          "0xFF9FF000|ExceptionList",
          "0xFFFFFFFFFFBFFFE4|",
          "0x5030|PTR_GetVersion_00405030",
          "0x64DC|DAT_004064dc",
          "0x64D8|DAT_004064d8",
          "0x64D4|DAT_004064d4",
          "0x64D0|DAT_004064d0",
          "0xFFFFFFFFFFBFFFF8|"
        ],
        "LoD/1.14b": [
          "0x50B8|DAT_004050b8",
          "0x2678|LAB_00402678",
          "0xFF9FF000|ExceptionList",
          "0xFFFFFFFFFFBFFFE4|",
          "0x5030|PTR_GetVersion_00405030",
          "0x64DC|DAT_004064dc",
          "0x64D8|DAT_004064d8",
          "0x64D4|DAT_004064d4",
          "0x64D0|DAT_004064d0",
          "0xFFFFFFFFFFBFFFF8|"
        ],
        "LoD/1.14c": [
          "0x50B8|DAT_004050b8",
          "0x2678|LAB_00402678",
          "0xFF9FF000|ExceptionList",
          "0xFFFFFFFFFFBFFFE4|",
          "0x5030|PTR_GetVersion_00405030",
          "0x64DC|DAT_004064dc",
          "0x64D8|DAT_004064d8",
          "0x64D4|DAT_004064d4",
          "0x64D0|DAT_004064d0",
          "0xFFFFFFFFFFBFFFF8|"
        ],
        "LoD/1.14d": [
          "0x50B8|DAT_004050b8",
          "0x2678|LAB_00402678",
          "0xFF9FF000|ExceptionList",
          "0xFFFFFFFFFFBFFFE4|",
          "0x5030|PTR_GetVersion_00405030",
          "0x64DC|DAT_004064dc",
          "0x64D8|DAT_004064d8",
          "0x64D4|DAT_004064d4",
          "0x64D0|DAT_004064d0",
          "0xFFFFFFFFFFBFFFF8|"
        ]
      }
    },
    "diablo ii.exe_AmsgExit": {
      "addresses": {
        "LoD/1.07": "0x004015D9",
        "LoD/1.08": "0x004015D9",
        "LoD/1.09": "0x004015D9",
        "LoD/1.09b": "0x004015D9",
        "LoD/1.09d": "0x004015D9",
        "LoD/1.10": "0x004015D9",
        "LoD/1.11": "0x004015D9",
        "LoD/1.11b": "0x004015D9",
        "LoD/1.12a": "0x004015D9",
        "LoD/1.13c": "0x004015D9",
        "LoD/1.13d": "0x004015D9",
        "LoD/1.14a": "0x004015D9",
        "LoD/1.14b": "0x004015D9",
        "LoD/1.14c": "0x004015D9",
        "LoD/1.14d": "0x004015D9"
      },
      "rvas": {
        "LoD/1.07": "0x15D9",
        "LoD/1.08": "0x15D9",
        "LoD/1.09": "0x15D9",
        "LoD/1.09b": "0x15D9",
        "LoD/1.09d": "0x15D9",
        "LoD/1.10": "0x15D9",
        "LoD/1.11": "0x15D9",
        "LoD/1.11b": "0x15D9",
        "LoD/1.12a": "0x15D9",
        "LoD/1.13c": "0x15D9",
        "LoD/1.13d": "0x15D9",
        "LoD/1.14a": "0x15D9",
        "LoD/1.14b": "0x15D9",
        "LoD/1.14c": "0x15D9",
        "LoD/1.14d": "0x15D9"
      },
      "sizes": {
        "LoD/1.07": 34,
        "LoD/1.08": 34,
        "LoD/1.09": 34,
        "LoD/1.09b": 34,
        "LoD/1.09d": 34,
        "LoD/1.10": 34,
        "LoD/1.11": 34,
        "LoD/1.11b": 34,
        "LoD/1.12a": 34,
        "LoD/1.13c": 34,
        "LoD/1.13d": 34,
        "LoD/1.14a": 34,
        "LoD/1.14b": 34,
        "LoD/1.14c": 34,
        "LoD/1.14d": 34
      },
      "name": "AmsgExit",
      "signature": "void AmsgExit(int param_1)",
      "calling_convention": "__cdecl",
      "return_type": "void",
      "comment": "Library Function - Single Match\n __amsg_exit\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.07",
      "method": "CAL",
      "index": "CAL:ec95479fbc9d5a35228cd8819b6daa86",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "23111e3d86e48fe171246fbcab7ae60b",
        "CFG": "d8a9d89b63cefe7947e17dc7192e86b4",
        "PRO": "d50b0d0648e43516997f810ba73a3fa5",
        "CAL": "ec95479fbc9d5a35228cd8819b6daa86",
        "CON": null,
        "APS": null
      },
      "callees": {
        "LoD/1.07": [
          "DisplayRuntimeError|0x402789",
          "CleanupConsoleOutput|0x402750",
          "__exit|0x401CBE"
        ],
        "LoD/1.08": [
          "DisplayRuntimeError|0x402789",
          "CleanupConsoleOutput|0x402750",
          "__exit|0x401CBE"
        ],
        "LoD/1.09": [
          "__exit|0x401CBE",
          "CleanupConsoleOutput|0x402750",
          "DisplayRuntimeError|0x402789"
        ],
        "LoD/1.09b": [
          "DisplayRuntimeError|0x402789",
          "__exit|0x401CBE",
          "CleanupConsoleOutput|0x402750"
        ],
        "LoD/1.09d": [
          "__exit|0x401CBE",
          "DisplayRuntimeError|0x402789",
          "CleanupConsoleOutput|0x402750"
        ],
        "LoD/1.10": [
          "__exit|0x401CBE",
          "DisplayRuntimeError|0x402789",
          "CleanupConsoleOutput|0x402750"
        ],
        "LoD/1.11": [
          "CleanupConsoleOutput|0x402750",
          "__exit|0x401CBE",
          "DisplayRuntimeError|0x402789"
        ],
        "LoD/1.11b": [
          "CleanupConsoleOutput|0x402750",
          "__exit|0x401CBE",
          "DisplayRuntimeError|0x402789"
        ],
        "LoD/1.12a": [
          "CleanupConsoleOutput|0x402750",
          "DisplayRuntimeError|0x402789",
          "__exit|0x401CBE"
        ],
        "LoD/1.13c": [
          "CleanupConsoleOutput|0x402750",
          "DisplayRuntimeError|0x402789",
          "__exit|0x401CBE"
        ],
        "LoD/1.13d": [
          "__exit|0x401CBE",
          "CleanupConsoleOutput|0x402750",
          "DisplayRuntimeError|0x402789"
        ],
        "LoD/1.14a": [
          "CleanupConsoleOutput|0x402750",
          "DisplayRuntimeError|0x402789",
          "__exit|0x401CBE"
        ],
        "LoD/1.14b": [
          "CleanupConsoleOutput|0x402750",
          "DisplayRuntimeError|0x402789",
          "__exit|0x401CBE"
        ],
        "LoD/1.14c": [
          "__exit|0x401CBE",
          "DisplayRuntimeError|0x402789",
          "CleanupConsoleOutput|0x402750"
        ],
        "LoD/1.14d": [
          "CleanupConsoleOutput|0x402750",
          "__exit|0x401CBE",
          "DisplayRuntimeError|0x402789"
        ]
      },
      "callers": {
        "LoD/1.07": [
          "InitializeModuleData|0x402017",
          "InitializeEnvironmentVariables|0x401F5E",
          "InitializeFileDescriptors|0x402396"
        ],
        "LoD/1.08": [
          "InitializeEnvironmentVariables|0x401F5E",
          "InitializeModuleData|0x402017",
          "InitializeFileDescriptors|0x402396"
        ],
        "LoD/1.09": [
          "InitializeEnvironmentVariables|0x401F5E",
          "InitializeModuleData|0x402017",
          "InitializeFileDescriptors|0x402396"
        ],
        "LoD/1.09b": [
          "InitializeFileDescriptors|0x402396",
          "InitializeEnvironmentVariables|0x401F5E",
          "InitializeModuleData|0x402017"
        ],
        "LoD/1.09d": [
          "InitializeEnvironmentVariables|0x401F5E",
          "InitializeModuleData|0x402017",
          "InitializeFileDescriptors|0x402396"
        ],
        "LoD/1.10": [
          "InitializeFileDescriptors|0x402396",
          "InitializeEnvironmentVariables|0x401F5E",
          "InitializeModuleData|0x402017"
        ],
        "LoD/1.11": [
          "InitializeModuleData|0x402017",
          "InitializeEnvironmentVariables|0x401F5E",
          "InitializeFileDescriptors|0x402396"
        ],
        "LoD/1.11b": [
          "InitializeModuleData|0x402017",
          "InitializeEnvironmentVariables|0x401F5E",
          "InitializeFileDescriptors|0x402396"
        ],
        "LoD/1.12a": [
          "InitializeFileDescriptors|0x402396",
          "InitializeEnvironmentVariables|0x401F5E",
          "InitializeModuleData|0x402017"
        ],
        "LoD/1.13c": [
          "InitializeFileDescriptors|0x402396",
          "InitializeModuleData|0x402017",
          "InitializeEnvironmentVariables|0x401F5E"
        ],
        "LoD/1.13d": [
          "InitializeModuleData|0x402017",
          "InitializeEnvironmentVariables|0x401F5E",
          "InitializeFileDescriptors|0x402396"
        ],
        "LoD/1.14a": [
          "InitializeFileDescriptors|0x402396",
          "InitializeEnvironmentVariables|0x401F5E",
          "InitializeModuleData|0x402017"
        ],
        "LoD/1.14b": [
          "InitializeModuleData|0x402017",
          "InitializeEnvironmentVariables|0x401F5E",
          "InitializeFileDescriptors|0x402396"
        ],
        "LoD/1.14c": [
          "InitializeFileDescriptors|0x402396",
          "InitializeModuleData|0x402017",
          "InitializeEnvironmentVariables|0x401F5E"
        ],
        "LoD/1.14d": [
          "InitializeModuleData|0x402017",
          "InitializeFileDescriptors|0x402396",
          "InitializeEnvironmentVariables|0x401F5E"
        ]
      },
      "instruction_counts": {
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
        "LoD/1.13d": 7,
        "LoD/1.14a": 7,
        "LoD/1.14b": 7,
        "LoD/1.14c": 7,
        "LoD/1.14d": 7
      },
      "stack_frame_sizes": {
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
        "LoD/1.13d": 8,
        "LoD/1.14a": 8,
        "LoD/1.14b": 8,
        "LoD/1.14c": 8,
        "LoD/1.14d": 8
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
        "LoD/1.13d": 3,
        "LoD/1.14a": 3,
        "LoD/1.14b": 3,
        "LoD/1.14c": 3,
        "LoD/1.14d": 3
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
        "LoD/1.13d": 0,
        "LoD/1.14a": 0,
        "LoD/1.14b": 0,
        "LoD/1.14c": 0,
        "LoD/1.14d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "23111e3d86e48fe171246fbcab7ae60b",
        "LoD/1.08": "23111e3d86e48fe171246fbcab7ae60b",
        "LoD/1.09": "23111e3d86e48fe171246fbcab7ae60b",
        "LoD/1.09b": "23111e3d86e48fe171246fbcab7ae60b",
        "LoD/1.09d": "23111e3d86e48fe171246fbcab7ae60b",
        "LoD/1.10": "23111e3d86e48fe171246fbcab7ae60b",
        "LoD/1.11": "23111e3d86e48fe171246fbcab7ae60b",
        "LoD/1.11b": "23111e3d86e48fe171246fbcab7ae60b",
        "LoD/1.12a": "23111e3d86e48fe171246fbcab7ae60b",
        "LoD/1.13c": "23111e3d86e48fe171246fbcab7ae60b",
        "LoD/1.13d": "23111e3d86e48fe171246fbcab7ae60b",
        "LoD/1.14a": "23111e3d86e48fe171246fbcab7ae60b",
        "LoD/1.14b": "23111e3d86e48fe171246fbcab7ae60b",
        "LoD/1.14c": "23111e3d86e48fe171246fbcab7ae60b",
        "LoD/1.14d": "23111e3d86e48fe171246fbcab7ae60b"
      },
      "globals": {
        "LoD/1.07": [
          "0x64BC|g_dwConsoleDisplayFlag",
          "0xFFFFFFFFFFC00004|",
          "0x6048|PTR___exit_00406048"
        ],
        "LoD/1.08": [
          "0x64BC|g_dwConsoleDisplayFlag",
          "0xFFFFFFFFFFC00004|",
          "0x6048|PTR___exit_00406048"
        ],
        "LoD/1.09": [
          "0x64BC|g_dwConsoleDisplayFlag",
          "0xFFFFFFFFFFC00004|",
          "0x6048|PTR___exit_00406048"
        ],
        "LoD/1.09b": [
          "0x64BC|g_dwConsoleDisplayFlag",
          "0xFFFFFFFFFFC00004|",
          "0x6048|PTR___exit_00406048"
        ],
        "LoD/1.09d": [
          "0x64BC|g_dwConsoleDisplayFlag",
          "0xFFFFFFFFFFC00004|",
          "0x6048|PTR___exit_00406048"
        ],
        "LoD/1.10": [
          "0x64BC|g_dwConsoleDisplayFlag",
          "0xFFFFFFFFFFC00004|",
          "0x6048|PTR___exit_00406048"
        ],
        "LoD/1.11": [
          "0x64BC|g_dwConsoleDisplayFlag",
          "0xFFFFFFFFFFC00004|",
          "0x6048|PTR___exit_00406048"
        ],
        "LoD/1.11b": [
          "0x64BC|g_dwConsoleDisplayFlag",
          "0xFFFFFFFFFFC00004|",
          "0x6048|PTR___exit_00406048"
        ],
        "LoD/1.12a": [
          "0x64BC|g_dwConsoleDisplayFlag",
          "0xFFFFFFFFFFC00004|",
          "0x6048|PTR___exit_00406048"
        ],
        "LoD/1.13c": [
          "0x64BC|g_dwConsoleDisplayFlag",
          "0xFFFFFFFFFFC00004|",
          "0x6048|PTR___exit_00406048"
        ],
        "LoD/1.13d": [
          "0x64BC|g_dwConsoleDisplayFlag",
          "0xFFFFFFFFFFC00004|",
          "0x6048|PTR___exit_00406048"
        ],
        "LoD/1.14a": [
          "0x64BC|g_dwConsoleDisplayFlag",
          "0xFFFFFFFFFFC00004|",
          "0x6048|PTR___exit_00406048"
        ],
        "LoD/1.14b": [
          "0x64BC|g_dwConsoleDisplayFlag",
          "0xFFFFFFFFFFC00004|",
          "0x6048|PTR___exit_00406048"
        ],
        "LoD/1.14c": [
          "0x64BC|g_dwConsoleDisplayFlag",
          "0xFFFFFFFFFFC00004|",
          "0x6048|PTR___exit_00406048"
        ],
        "LoD/1.14d": [
          "0x64BC|g_dwConsoleDisplayFlag",
          "0xFFFFFFFFFFC00004|",
          "0x6048|PTR___exit_00406048"
        ]
      }
    },
    "diablo ii.exe_CAL_751ccb169902": {
      "addresses": {
        "LoD/1.07": "0x004015FE",
        "LoD/1.08": "0x004015FE",
        "LoD/1.09": "0x004015FE",
        "LoD/1.09b": "0x004015FE",
        "LoD/1.09d": "0x004015FE",
        "LoD/1.10": "0x004015FE",
        "LoD/1.11": "0x004015FE",
        "LoD/1.11b": "0x004015FE",
        "LoD/1.12a": "0x004015FE",
        "LoD/1.13c": "0x004015FE",
        "LoD/1.13d": "0x004015FE",
        "LoD/1.14a": "0x004015FE",
        "LoD/1.14b": "0x004015FE",
        "LoD/1.14c": "0x004015FE",
        "LoD/1.14d": "0x004015FE"
      },
      "rvas": {
        "LoD/1.07": "0x15FE",
        "LoD/1.08": "0x15FE",
        "LoD/1.09": "0x15FE",
        "LoD/1.09b": "0x15FE",
        "LoD/1.09d": "0x15FE",
        "LoD/1.10": "0x15FE",
        "LoD/1.11": "0x15FE",
        "LoD/1.11b": "0x15FE",
        "LoD/1.12a": "0x15FE",
        "LoD/1.13c": "0x15FE",
        "LoD/1.13d": "0x15FE",
        "LoD/1.14a": "0x15FE",
        "LoD/1.14b": "0x15FE",
        "LoD/1.14c": "0x15FE",
        "LoD/1.14d": "0x15FE"
      },
      "sizes": {
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
        "LoD/1.13d": 35,
        "LoD/1.14a": 35,
        "LoD/1.14b": 35,
        "LoD/1.14c": 35,
        "LoD/1.14d": 35
      },
      "return_type": "undefined",
      "name_source": "LoD/1.07",
      "method": "CAL",
      "index": "CAL:751ccb169902422404a503b9cbd72d96",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "fa40def9a627b3e96c51f0f9c6833564",
        "CFG": "e6ff6ad0743b58874820ceb7f4492737",
        "PRO": "2e59db3ab77f3da70f210b2bdbad55ff",
        "CAL": "751ccb169902422404a503b9cbd72d96",
        "CON": null,
        "APS": null
      },
      "display_name": "FUN_004015fe",
      "callees": {
        "LoD/1.07": [
          "ExitProcess|0xE",
          "DisplayRuntimeError|0x402789",
          "CleanupConsoleOutput|0x402750"
        ],
        "LoD/1.08": [
          "DisplayRuntimeError|0x402789",
          "CleanupConsoleOutput|0x402750",
          "ExitProcess|0xE"
        ],
        "LoD/1.09": [
          "ExitProcess|0xE",
          "CleanupConsoleOutput|0x402750",
          "DisplayRuntimeError|0x402789"
        ],
        "LoD/1.09b": [
          "DisplayRuntimeError|0x402789",
          "ExitProcess|0xE",
          "CleanupConsoleOutput|0x402750"
        ],
        "LoD/1.09d": [
          "ExitProcess|0xE",
          "DisplayRuntimeError|0x402789",
          "CleanupConsoleOutput|0x402750"
        ],
        "LoD/1.10": [
          "ExitProcess|0xE",
          "DisplayRuntimeError|0x402789",
          "CleanupConsoleOutput|0x402750"
        ],
        "LoD/1.11": [
          "CleanupConsoleOutput|0x402750",
          "DisplayRuntimeError|0x402789",
          "ExitProcess|0xE"
        ],
        "LoD/1.11b": [
          "ExitProcess|0xE",
          "CleanupConsoleOutput|0x402750",
          "DisplayRuntimeError|0x402789"
        ],
        "LoD/1.12a": [
          "CleanupConsoleOutput|0x402750",
          "ExitProcess|0xE",
          "DisplayRuntimeError|0x402789"
        ],
        "LoD/1.13c": [
          "CleanupConsoleOutput|0x402750",
          "ExitProcess|0xE",
          "DisplayRuntimeError|0x402789"
        ],
        "LoD/1.13d": [
          "CleanupConsoleOutput|0x402750",
          "DisplayRuntimeError|0x402789",
          "ExitProcess|0xE"
        ],
        "LoD/1.14a": [
          "CleanupConsoleOutput|0x402750",
          "ExitProcess|0xE",
          "DisplayRuntimeError|0x402789"
        ],
        "LoD/1.14b": [
          "CleanupConsoleOutput|0x402750",
          "DisplayRuntimeError|0x402789",
          "ExitProcess|0xE"
        ],
        "LoD/1.14c": [
          "DisplayRuntimeError|0x402789",
          "ExitProcess|0xE",
          "CleanupConsoleOutput|0x402750"
        ],
        "LoD/1.14d": [
          "CleanupConsoleOutput|0x402750",
          "DisplayRuntimeError|0x402789",
          "ExitProcess|0xE"
        ]
      },
      "callers": {
        "LoD/1.07": [
          "entry|0x4014E3"
        ],
        "LoD/1.08": [
          "entry|0x4014E3"
        ],
        "LoD/1.09": [
          "entry|0x4014E3"
        ],
        "LoD/1.09b": [
          "entry|0x4014E3"
        ],
        "LoD/1.09d": [
          "entry|0x4014E3"
        ],
        "LoD/1.10": [
          "entry|0x4014E3"
        ],
        "LoD/1.11": [
          "entry|0x4014E3"
        ],
        "LoD/1.11b": [
          "entry|0x4014E3"
        ],
        "LoD/1.12a": [
          "entry|0x4014E3"
        ],
        "LoD/1.13c": [
          "entry|0x4014E3"
        ],
        "LoD/1.13d": [
          "entry|0x4014E3"
        ],
        "LoD/1.14a": [
          "entry|0x4014E3"
        ],
        "LoD/1.14b": [
          "entry|0x4014E3"
        ],
        "LoD/1.14c": [
          "entry|0x4014E3"
        ],
        "LoD/1.14d": [
          "entry|0x4014E3"
        ]
      },
      "instruction_counts": {
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
        "LoD/1.13d": 8,
        "LoD/1.14a": 8,
        "LoD/1.14b": 8,
        "LoD/1.14c": 8,
        "LoD/1.14d": 8
      },
      "stack_frame_sizes": {
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
        "LoD/1.13d": 8,
        "LoD/1.14a": 8,
        "LoD/1.14b": 8,
        "LoD/1.14c": 8,
        "LoD/1.14d": 8
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
        "LoD/1.13d": 3,
        "LoD/1.14a": 3,
        "LoD/1.14b": 3,
        "LoD/1.14c": 3,
        "LoD/1.14d": 3
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
        "LoD/1.13d": 0,
        "LoD/1.14a": 0,
        "LoD/1.14b": 0,
        "LoD/1.14c": 0,
        "LoD/1.14d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "fa40def9a627b3e96c51f0f9c6833564",
        "LoD/1.08": "fa40def9a627b3e96c51f0f9c6833564",
        "LoD/1.09": "fa40def9a627b3e96c51f0f9c6833564",
        "LoD/1.09b": "fa40def9a627b3e96c51f0f9c6833564",
        "LoD/1.09d": "fa40def9a627b3e96c51f0f9c6833564",
        "LoD/1.10": "fa40def9a627b3e96c51f0f9c6833564",
        "LoD/1.11": "fa40def9a627b3e96c51f0f9c6833564",
        "LoD/1.11b": "fa40def9a627b3e96c51f0f9c6833564",
        "LoD/1.12a": "fa40def9a627b3e96c51f0f9c6833564",
        "LoD/1.13c": "fa40def9a627b3e96c51f0f9c6833564",
        "LoD/1.13d": "fa40def9a627b3e96c51f0f9c6833564",
        "LoD/1.14a": "fa40def9a627b3e96c51f0f9c6833564",
        "LoD/1.14b": "fa40def9a627b3e96c51f0f9c6833564",
        "LoD/1.14c": "fa40def9a627b3e96c51f0f9c6833564",
        "LoD/1.14d": "fa40def9a627b3e96c51f0f9c6833564"
      },
      "globals": {
        "LoD/1.07": [
          "0x64BC|g_dwConsoleDisplayFlag",
          "0xFFFFFFFFFFC00004|",
          "0x5034|PTR_ExitProcess_00405034"
        ],
        "LoD/1.08": [
          "0x64BC|g_dwConsoleDisplayFlag",
          "0xFFFFFFFFFFC00004|",
          "0x5034|PTR_ExitProcess_00405034"
        ],
        "LoD/1.09": [
          "0x64BC|g_dwConsoleDisplayFlag",
          "0xFFFFFFFFFFC00004|",
          "0x5034|PTR_ExitProcess_00405034"
        ],
        "LoD/1.09b": [
          "0x64BC|g_dwConsoleDisplayFlag",
          "0xFFFFFFFFFFC00004|",
          "0x5034|PTR_ExitProcess_00405034"
        ],
        "LoD/1.09d": [
          "0x64BC|g_dwConsoleDisplayFlag",
          "0xFFFFFFFFFFC00004|",
          "0x5034|PTR_ExitProcess_00405034"
        ],
        "LoD/1.10": [
          "0x64BC|g_dwConsoleDisplayFlag",
          "0xFFFFFFFFFFC00004|",
          "0x5034|PTR_ExitProcess_00405034"
        ],
        "LoD/1.11": [
          "0x64BC|g_dwConsoleDisplayFlag",
          "0xFFFFFFFFFFC00004|",
          "0x5034|PTR_ExitProcess_00405034"
        ],
        "LoD/1.11b": [
          "0x64BC|g_dwConsoleDisplayFlag",
          "0xFFFFFFFFFFC00004|",
          "0x5034|PTR_ExitProcess_00405034"
        ],
        "LoD/1.12a": [
          "0x64BC|g_dwConsoleDisplayFlag",
          "0xFFFFFFFFFFC00004|",
          "0x5034|PTR_ExitProcess_00405034"
        ],
        "LoD/1.13c": [
          "0x64BC|g_dwConsoleDisplayFlag",
          "0xFFFFFFFFFFC00004|",
          "0x5034|PTR_ExitProcess_00405034"
        ],
        "LoD/1.13d": [
          "0x64BC|g_dwConsoleDisplayFlag",
          "0xFFFFFFFFFFC00004|",
          "0x5034|PTR_ExitProcess_00405034"
        ],
        "LoD/1.14a": [
          "0x64BC|g_dwConsoleDisplayFlag",
          "0xFFFFFFFFFFC00004|",
          "0x5034|PTR_ExitProcess_00405034"
        ],
        "LoD/1.14b": [
          "0x64BC|g_dwConsoleDisplayFlag",
          "0xFFFFFFFFFFC00004|",
          "0x5034|PTR_ExitProcess_00405034"
        ],
        "LoD/1.14c": [
          "0x64BC|g_dwConsoleDisplayFlag",
          "0xFFFFFFFFFFC00004|",
          "0x5034|PTR_ExitProcess_00405034"
        ],
        "LoD/1.14d": [
          "0x64BC|g_dwConsoleDisplayFlag",
          "0xFFFFFFFFFFC00004|",
          "0x5034|PTR_ExitProcess_00405034"
        ]
      }
    },
    "diablo ii.exe_InitializeCodePageLocale": {
      "addresses": {
        "LoD/1.07": "0x00401622",
        "LoD/1.08": "0x00401622",
        "LoD/1.09": "0x00401622",
        "LoD/1.09b": "0x00401622",
        "LoD/1.09d": "0x00401622",
        "LoD/1.10": "0x00401622",
        "LoD/1.11": "0x00401622",
        "LoD/1.11b": "0x00401622",
        "LoD/1.12a": "0x00401622",
        "LoD/1.13c": "0x00401622",
        "LoD/1.13d": "0x00401622",
        "LoD/1.14a": "0x00401622",
        "LoD/1.14b": "0x00401622",
        "LoD/1.14c": "0x00401622",
        "LoD/1.14d": "0x00401622"
      },
      "rvas": {
        "LoD/1.07": "0x1622",
        "LoD/1.08": "0x1622",
        "LoD/1.09": "0x1622",
        "LoD/1.09b": "0x1622",
        "LoD/1.09d": "0x1622",
        "LoD/1.10": "0x1622",
        "LoD/1.11": "0x1622",
        "LoD/1.11b": "0x1622",
        "LoD/1.12a": "0x1622",
        "LoD/1.13c": "0x1622",
        "LoD/1.13d": "0x1622",
        "LoD/1.14a": "0x1622",
        "LoD/1.14b": "0x1622",
        "LoD/1.14c": "0x1622",
        "LoD/1.14d": "0x1622"
      },
      "sizes": {
        "LoD/1.07": 409,
        "LoD/1.08": 409,
        "LoD/1.09": 409,
        "LoD/1.09b": 409,
        "LoD/1.09d": 409,
        "LoD/1.10": 409,
        "LoD/1.11": 409,
        "LoD/1.11b": 409,
        "LoD/1.12a": 409,
        "LoD/1.13c": 409,
        "LoD/1.13d": 409,
        "LoD/1.14a": 409,
        "LoD/1.14b": 409,
        "LoD/1.14c": 409,
        "LoD/1.14d": 409
      },
      "name": "InitializeCodePageLocale",
      "signature": "int InitializeCodePageLocale(uint dwCodePage)",
      "calling_convention": "__cdecl",
      "return_type": "int",
      "comment": "Initializes system code page locale settings and character classification tables\n\nAlgorithm:\n1. Validate and retrieve code page ID through FUN_10021596()\n2. Check if requested code page is already active (early return if same)\n3. Search predefined code page table (0x1002eac8) for supported code pages\n4. If found in table: Initialize from hardcoded character classification data\n   a. Clear 256-byte character table at 0x1003cbc0\n   b. Load character range data from table offset (iVar11 * 0x30 + 0x1002ead8)\n   c. Process 4 character type classification loops\n   d. Set character flags using OR operations with type-specific bit masks\n   e. Copy locale data from table (0x1002eacc + offset) to globals 0x1003cab0-cab8\n5. If not in table: Query Windows API via GetCPInfo() for system code page\n   a. Call GetCPInfo() to populate _cpinfo structure\n   b. Clear character classification table at 0x1003cbc0\n   c. Process multi-byte character lead byte ranges from _cpinfo.LeadByte[]\n   d. Set lead byte flag (0x04) for DBCS ranges\n   e. Set trail byte flag (0x08) for bytes 0x01-0xFE\n6. Update global state: current code page ID, locale flags, character table\n7. Call cleanup functions FUN_10021613() and FUN_1002163c()\n\nParameters:\nnCodePage - Windows code page identifier (e.g., 932 for Shift-JIS, 1252 for Latin-1)\n\nReturns:\n0 - Success, code page initialized\n-1 - Failure, invalid code page or system error\n\nSpecial Cases:\n- Returns 0 immediately if requested code page already active\n- Handles both predefined code pages (faster lookup) and system code pages (API call)\n- DBCS code pages process lead/trail byte ranges for multi-byte character support\n- Single-byte code pages skip lead byte processing\n\nMagic Numbers Reference:\n0x30 (48) - Size of each code page table entry\n0x40 (64) - Size of character classification table in DWORDs (256 bytes total)\n0x04 - Lead byte flag for DBCS characters\n0x08 - Trail byte flag for DBCS characters  \n0xFF (255) - Maximum single-byte character value\n0x1002eac8 - Base address of predefined code page table\n0x1002ead8 - Base address of character classification data\n0x1002eacc - Base address of locale information data\n0x1003caa4 - Global: Current active code page ID\n0x1003cabc - Global: Locale initialization flag\n0x1003cbc0 - Global: 256-byte character classification table\n0x1003cab0 - Global: Locale data copied from table\n0x1003ccc4 - Global: Result from FUN_100215e0() locale processing\n\nStructure Layout:\n_cpinfo (20 bytes):\nOffset  Size  Field Name     Type    Description\n0x00    4     MaxCharSize    UINT    Maximum character size in bytes\n0x04    12    DefaultChar    BYTE[2] Default character for unmappable chars  \n0x06    12    LeadByte       BYTE[12] Lead byte ranges for DBCS (pairs of start/end)",
      "name_source": "LoD/1.07",
      "method": "CAL",
      "index": "CAL:889d2a491df398fed4786992eeb9ca1f",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "4a5a68bf41640182f32d03a3c91e5fdc",
        "CFG": "788180c544e7082c69e40531981aa350",
        "PRO": "fccb21a6a871c7122e2713f7dcd5a6af",
        "CAL": "889d2a491df398fed4786992eeb9ca1f",
        "CON": "325f4c35c36b7f42d8d730381f0d5463",
        "APS": null
      },
      "callees": {
        "LoD/1.07": [
          "ResolveCodePageIdentifier|0x4017BB",
          "InitializeCharacterTables|0x401861",
          "InitializeLocaleDataBuffers|0x401838",
          "GetCPInfo|0xF",
          "MapCodePageIdentifier|0x401805"
        ],
        "LoD/1.08": [
          "GetCPInfo|0xF",
          "ResolveCodePageIdentifier|0x4017BB",
          "InitializeLocaleDataBuffers|0x401838",
          "MapCodePageIdentifier|0x401805",
          "InitializeCharacterTables|0x401861"
        ],
        "LoD/1.09": [
          "InitializeCharacterTables|0x401861",
          "GetCPInfo|0xF",
          "ResolveCodePageIdentifier|0x4017BB",
          "InitializeLocaleDataBuffers|0x401838",
          "MapCodePageIdentifier|0x401805"
        ],
        "LoD/1.09b": [
          "GetCPInfo|0xF",
          "MapCodePageIdentifier|0x401805",
          "InitializeLocaleDataBuffers|0x401838",
          "InitializeCharacterTables|0x401861",
          "ResolveCodePageIdentifier|0x4017BB"
        ],
        "LoD/1.09d": [
          "MapCodePageIdentifier|0x401805",
          "ResolveCodePageIdentifier|0x4017BB",
          "InitializeLocaleDataBuffers|0x401838",
          "GetCPInfo|0xF",
          "InitializeCharacterTables|0x401861"
        ],
        "LoD/1.10": [
          "ResolveCodePageIdentifier|0x4017BB",
          "GetCPInfo|0xF",
          "MapCodePageIdentifier|0x401805",
          "InitializeCharacterTables|0x401861",
          "InitializeLocaleDataBuffers|0x401838"
        ],
        "LoD/1.11": [
          "ResolveCodePageIdentifier|0x4017BB",
          "MapCodePageIdentifier|0x401805",
          "InitializeLocaleDataBuffers|0x401838",
          "InitializeCharacterTables|0x401861",
          "GetCPInfo|0xF"
        ],
        "LoD/1.11b": [
          "GetCPInfo|0xF",
          "ResolveCodePageIdentifier|0x4017BB",
          "InitializeLocaleDataBuffers|0x401838",
          "InitializeCharacterTables|0x401861",
          "MapCodePageIdentifier|0x401805"
        ],
        "LoD/1.12a": [
          "InitializeLocaleDataBuffers|0x401838",
          "MapCodePageIdentifier|0x401805",
          "GetCPInfo|0xF",
          "ResolveCodePageIdentifier|0x4017BB",
          "InitializeCharacterTables|0x401861"
        ],
        "LoD/1.13c": [
          "InitializeLocaleDataBuffers|0x401838",
          "InitializeCharacterTables|0x401861",
          "ResolveCodePageIdentifier|0x4017BB",
          "GetCPInfo|0xF",
          "MapCodePageIdentifier|0x401805"
        ],
        "LoD/1.13d": [
          "InitializeCharacterTables|0x401861",
          "ResolveCodePageIdentifier|0x4017BB",
          "GetCPInfo|0xF",
          "MapCodePageIdentifier|0x401805",
          "InitializeLocaleDataBuffers|0x401838"
        ],
        "LoD/1.14a": [
          "GetCPInfo|0xF",
          "MapCodePageIdentifier|0x401805",
          "ResolveCodePageIdentifier|0x4017BB",
          "InitializeLocaleDataBuffers|0x401838",
          "InitializeCharacterTables|0x401861"
        ],
        "LoD/1.14b": [
          "MapCodePageIdentifier|0x401805",
          "InitializeCharacterTables|0x401861",
          "ResolveCodePageIdentifier|0x4017BB",
          "GetCPInfo|0xF",
          "InitializeLocaleDataBuffers|0x401838"
        ],
        "LoD/1.14c": [
          "InitializeCharacterTables|0x401861",
          "ResolveCodePageIdentifier|0x4017BB",
          "MapCodePageIdentifier|0x401805",
          "GetCPInfo|0xF",
          "InitializeLocaleDataBuffers|0x401838"
        ],
        "LoD/1.14d": [
          "MapCodePageIdentifier|0x401805",
          "ResolveCodePageIdentifier|0x4017BB",
          "GetCPInfo|0xF",
          "InitializeCharacterTables|0x401861",
          "InitializeLocaleDataBuffers|0x401838"
        ]
      },
      "callers": {
        "LoD/1.07": [
          "InitializeCodePageOnce|0x4019E6"
        ],
        "LoD/1.08": [
          "InitializeCodePageOnce|0x4019E6"
        ],
        "LoD/1.09": [
          "InitializeCodePageOnce|0x4019E6"
        ],
        "LoD/1.09b": [
          "InitializeCodePageOnce|0x4019E6"
        ],
        "LoD/1.09d": [
          "InitializeCodePageOnce|0x4019E6"
        ],
        "LoD/1.10": [
          "InitializeCodePageOnce|0x4019E6"
        ],
        "LoD/1.11": [
          "InitializeCodePageOnce|0x4019E6"
        ],
        "LoD/1.11b": [
          "InitializeCodePageOnce|0x4019E6"
        ],
        "LoD/1.12a": [
          "InitializeCodePageOnce|0x4019E6"
        ],
        "LoD/1.13c": [
          "InitializeCodePageOnce|0x4019E6"
        ],
        "LoD/1.13d": [
          "InitializeCodePageOnce|0x4019E6"
        ],
        "LoD/1.14a": [
          "InitializeCodePageOnce|0x4019E6"
        ],
        "LoD/1.14b": [
          "InitializeCodePageOnce|0x4019E6"
        ],
        "LoD/1.14c": [
          "InitializeCodePageOnce|0x4019E6"
        ],
        "LoD/1.14d": [
          "InitializeCodePageOnce|0x4019E6"
        ]
      },
      "instruction_counts": {
        "LoD/1.07": 135,
        "LoD/1.08": 135,
        "LoD/1.09": 135,
        "LoD/1.09b": 135,
        "LoD/1.09d": 135,
        "LoD/1.10": 135,
        "LoD/1.11": 135,
        "LoD/1.11b": 135,
        "LoD/1.12a": 135,
        "LoD/1.13c": 135,
        "LoD/1.13d": 135,
        "LoD/1.14a": 135,
        "LoD/1.14b": 135,
        "LoD/1.14c": 135,
        "LoD/1.14d": 135
      },
      "stack_frame_sizes": {
        "LoD/1.07": 36,
        "LoD/1.08": 36,
        "LoD/1.09": 36,
        "LoD/1.09b": 36,
        "LoD/1.09d": 36,
        "LoD/1.10": 36,
        "LoD/1.11": 36,
        "LoD/1.11b": 36,
        "LoD/1.12a": 36,
        "LoD/1.13c": 36,
        "LoD/1.13d": 36,
        "LoD/1.14a": 36,
        "LoD/1.14b": 36,
        "LoD/1.14c": 36,
        "LoD/1.14d": 36
      },
      "basic_block_counts": {
        "LoD/1.07": 34,
        "LoD/1.08": 34,
        "LoD/1.09": 34,
        "LoD/1.09b": 34,
        "LoD/1.09d": 34,
        "LoD/1.10": 34,
        "LoD/1.11": 34,
        "LoD/1.11b": 34,
        "LoD/1.12a": 34,
        "LoD/1.13c": 34,
        "LoD/1.13d": 34,
        "LoD/1.14a": 34,
        "LoD/1.14b": 34,
        "LoD/1.14c": 34,
        "LoD/1.14d": 34
      },
      "loop_counts": {
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
        "LoD/1.13d": 7,
        "LoD/1.14a": 7,
        "LoD/1.14b": 7,
        "LoD/1.14c": 7,
        "LoD/1.14d": 7
      },
      "mnemonic_hashes": {
        "LoD/1.07": "4a5a68bf41640182f32d03a3c91e5fdc",
        "LoD/1.08": "4a5a68bf41640182f32d03a3c91e5fdc",
        "LoD/1.09": "4a5a68bf41640182f32d03a3c91e5fdc",
        "LoD/1.09b": "4a5a68bf41640182f32d03a3c91e5fdc",
        "LoD/1.09d": "4a5a68bf41640182f32d03a3c91e5fdc",
        "LoD/1.10": "4a5a68bf41640182f32d03a3c91e5fdc",
        "LoD/1.11": "4a5a68bf41640182f32d03a3c91e5fdc",
        "LoD/1.11b": "4a5a68bf41640182f32d03a3c91e5fdc",
        "LoD/1.12a": "4a5a68bf41640182f32d03a3c91e5fdc",
        "LoD/1.13c": "4a5a68bf41640182f32d03a3c91e5fdc",
        "LoD/1.13d": "4a5a68bf41640182f32d03a3c91e5fdc",
        "LoD/1.14a": "4a5a68bf41640182f32d03a3c91e5fdc",
        "LoD/1.14b": "4a5a68bf41640182f32d03a3c91e5fdc",
        "LoD/1.14c": "4a5a68bf41640182f32d03a3c91e5fdc",
        "LoD/1.14d": "4a5a68bf41640182f32d03a3c91e5fdc"
      },
      "constants": {
        "LoD/1.07": [
          4218960,
          4218968,
          4218972,
          4218984,
          4219208,
          4220832,
          4221120,
          4221121
        ],
        "LoD/1.08": [
          4218960,
          4218968,
          4218972,
          4218984,
          4219208,
          4220832,
          4221120,
          4221121
        ],
        "LoD/1.09": [
          4218960,
          4218968,
          4218972,
          4218984,
          4219208,
          4220832,
          4221120,
          4221121
        ],
        "LoD/1.09b": [
          4218960,
          4218968,
          4218972,
          4218984,
          4219208,
          4220832,
          4221120,
          4221121
        ],
        "LoD/1.09d": [
          4218960,
          4218968,
          4218972,
          4218984,
          4219208,
          4220832,
          4221120,
          4221121
        ],
        "LoD/1.10": [
          4218960,
          4218968,
          4218972,
          4218984,
          4219208,
          4220832,
          4221120,
          4221121
        ],
        "LoD/1.11": [
          4218960,
          4218968,
          4218972,
          4218984,
          4219208,
          4220832,
          4221120,
          4221121
        ],
        "LoD/1.11b": [
          4218960,
          4218968,
          4218972,
          4218984,
          4219208,
          4220832,
          4221120,
          4221121
        ],
        "LoD/1.12a": [
          4218960,
          4218968,
          4218972,
          4218984,
          4219208,
          4220832,
          4221120,
          4221121
        ],
        "LoD/1.13c": [
          4218960,
          4218968,
          4218972,
          4218984,
          4219208,
          4220832,
          4221120,
          4221121
        ],
        "LoD/1.13d": [
          4218960,
          4218968,
          4218972,
          4218984,
          4219208,
          4220832,
          4221120,
          4221121
        ],
        "LoD/1.14a": [
          4218960,
          4218968,
          4218972,
          4218984,
          4219208,
          4220832,
          4221120,
          4221121
        ],
        "LoD/1.14b": [
          4218960,
          4218968,
          4218972,
          4218984,
          4219208,
          4220832,
          4221120,
          4221121
        ],
        "LoD/1.14c": [
          4218960,
          4218968,
          4218972,
          4218984,
          4219208,
          4220832,
          4221120,
          4221121
        ],
        "LoD/1.14d": [
          4218960,
          4218968,
          4218972,
          4218984,
          4219208,
          4220832,
          4221120,
          4221121
        ]
      },
      "globals": {
        "LoD/1.07": [
          "0xFFFFFFFFFFC00004|",
          "0x6798|g_dwCurrentCodePage",
          "0x6058|DAT_00406058",
          "0x6088|DAT_00406088",
          "0x6148|DAT_00406148",
          "0xFFFFFFFFFFBFFFE4|",
          "0x5038|PTR_GetCPInfo_00405038",
          "0x68C0|DAT_004068c0",
          "0x68C4|DAT_004068c4",
          "0x69C4|g_dwCodePageProperties"
        ],
        "LoD/1.08": [
          "0xFFFFFFFFFFC00004|",
          "0x6798|g_dwCurrentCodePage",
          "0x6058|DAT_00406058",
          "0x6088|DAT_00406088",
          "0x6148|DAT_00406148",
          "0xFFFFFFFFFFBFFFE4|",
          "0x5038|PTR_GetCPInfo_00405038",
          "0x68C0|DAT_004068c0",
          "0x68C4|DAT_004068c4",
          "0x69C4|g_dwCodePageProperties"
        ],
        "LoD/1.09": [
          "0xFFFFFFFFFFC00004|",
          "0x6798|g_dwCurrentCodePage",
          "0x6058|DAT_00406058",
          "0x6088|DAT_00406088",
          "0x6148|DAT_00406148",
          "0xFFFFFFFFFFBFFFE4|",
          "0x5038|PTR_GetCPInfo_00405038",
          "0x68C0|DAT_004068c0",
          "0x68C4|DAT_004068c4",
          "0x69C4|g_dwCodePageProperties"
        ],
        "LoD/1.09b": [
          "0xFFFFFFFFFFC00004|",
          "0x6798|g_dwCurrentCodePage",
          "0x6058|DAT_00406058",
          "0x6088|DAT_00406088",
          "0x6148|DAT_00406148",
          "0xFFFFFFFFFFBFFFE4|",
          "0x5038|PTR_GetCPInfo_00405038",
          "0x68C0|DAT_004068c0",
          "0x68C4|DAT_004068c4",
          "0x69C4|g_dwCodePageProperties"
        ],
        "LoD/1.09d": [
          "0xFFFFFFFFFFC00004|",
          "0x6798|g_dwCurrentCodePage",
          "0x6058|DAT_00406058",
          "0x6088|DAT_00406088",
          "0x6148|DAT_00406148",
          "0xFFFFFFFFFFBFFFE4|",
          "0x5038|PTR_GetCPInfo_00405038",
          "0x68C0|DAT_004068c0",
          "0x68C4|DAT_004068c4",
          "0x69C4|g_dwCodePageProperties"
        ],
        "LoD/1.10": [
          "0xFFFFFFFFFFC00004|",
          "0x6798|g_dwCurrentCodePage",
          "0x6058|DAT_00406058",
          "0x6088|DAT_00406088",
          "0x6148|DAT_00406148",
          "0xFFFFFFFFFFBFFFE4|",
          "0x5038|PTR_GetCPInfo_00405038",
          "0x68C0|DAT_004068c0",
          "0x68C4|DAT_004068c4",
          "0x69C4|g_dwCodePageProperties"
        ],
        "LoD/1.11": [
          "0xFFFFFFFFFFC00004|",
          "0x6798|g_dwCurrentCodePage",
          "0x6058|DAT_00406058",
          "0x6088|DAT_00406088",
          "0x6148|DAT_00406148",
          "0xFFFFFFFFFFBFFFE4|",
          "0x5038|PTR_GetCPInfo_00405038",
          "0x68C0|DAT_004068c0",
          "0x68C4|DAT_004068c4",
          "0x69C4|g_dwCodePageProperties"
        ],
        "LoD/1.11b": [
          "0xFFFFFFFFFFC00004|",
          "0x6798|g_dwCurrentCodePage",
          "0x6058|DAT_00406058",
          "0x6088|DAT_00406088",
          "0x6148|DAT_00406148",
          "0xFFFFFFFFFFBFFFE4|",
          "0x5038|PTR_GetCPInfo_00405038",
          "0x68C0|DAT_004068c0",
          "0x68C4|DAT_004068c4",
          "0x69C4|g_dwCodePageProperties"
        ],
        "LoD/1.12a": [
          "0xFFFFFFFFFFC00004|",
          "0x6798|g_dwCurrentCodePage",
          "0x6058|DAT_00406058",
          "0x6088|DAT_00406088",
          "0x6148|DAT_00406148",
          "0xFFFFFFFFFFBFFFE4|",
          "0x5038|PTR_GetCPInfo_00405038",
          "0x68C0|DAT_004068c0",
          "0x68C4|DAT_004068c4",
          "0x69C4|g_dwCodePageProperties"
        ],
        "LoD/1.13c": [
          "0xFFFFFFFFFFC00004|",
          "0x6798|g_dwCurrentCodePage",
          "0x6058|DAT_00406058",
          "0x6088|DAT_00406088",
          "0x6148|DAT_00406148",
          "0xFFFFFFFFFFBFFFE4|",
          "0x5038|PTR_GetCPInfo_00405038",
          "0x68C0|DAT_004068c0",
          "0x68C4|DAT_004068c4",
          "0x69C4|g_dwCodePageProperties"
        ],
        "LoD/1.13d": [
          "0xFFFFFFFFFFC00004|",
          "0x6798|g_dwCurrentCodePage",
          "0x6058|DAT_00406058",
          "0x6088|DAT_00406088",
          "0x6148|DAT_00406148",
          "0xFFFFFFFFFFBFFFE4|",
          "0x5038|PTR_GetCPInfo_00405038",
          "0x68C0|DAT_004068c0",
          "0x68C4|DAT_004068c4",
          "0x69C4|g_dwCodePageProperties"
        ],
        "LoD/1.14a": [
          "0xFFFFFFFFFFC00004|",
          "0x6798|g_dwCurrentCodePage",
          "0x6058|DAT_00406058",
          "0x6088|DAT_00406088",
          "0x6148|DAT_00406148",
          "0xFFFFFFFFFFBFFFE4|",
          "0x5038|PTR_GetCPInfo_00405038",
          "0x68C0|DAT_004068c0",
          "0x68C4|DAT_004068c4",
          "0x69C4|g_dwCodePageProperties"
        ],
        "LoD/1.14b": [
          "0xFFFFFFFFFFC00004|",
          "0x6798|g_dwCurrentCodePage",
          "0x6058|DAT_00406058",
          "0x6088|DAT_00406088",
          "0x6148|DAT_00406148",
          "0xFFFFFFFFFFBFFFE4|",
          "0x5038|PTR_GetCPInfo_00405038",
          "0x68C0|DAT_004068c0",
          "0x68C4|DAT_004068c4",
          "0x69C4|g_dwCodePageProperties"
        ],
        "LoD/1.14c": [
          "0xFFFFFFFFFFC00004|",
          "0x6798|g_dwCurrentCodePage",
          "0x6058|DAT_00406058",
          "0x6088|DAT_00406088",
          "0x6148|DAT_00406148",
          "0xFFFFFFFFFFBFFFE4|",
          "0x5038|PTR_GetCPInfo_00405038",
          "0x68C0|DAT_004068c0",
          "0x68C4|DAT_004068c4",
          "0x69C4|g_dwCodePageProperties"
        ],
        "LoD/1.14d": [
          "0xFFFFFFFFFFC00004|",
          "0x6798|g_dwCurrentCodePage",
          "0x6058|DAT_00406058",
          "0x6088|DAT_00406088",
          "0x6148|DAT_00406148",
          "0xFFFFFFFFFFBFFFE4|",
          "0x5038|PTR_GetCPInfo_00405038",
          "0x68C0|DAT_004068c0",
          "0x68C4|DAT_004068c4",
          "0x69C4|g_dwCodePageProperties"
        ]
      }
    },
    "diablo ii.exe_ResolveCodePageIdentifier": {
      "addresses": {
        "LoD/1.07": "0x004017BB",
        "LoD/1.08": "0x004017BB",
        "LoD/1.09": "0x004017BB",
        "LoD/1.09b": "0x004017BB",
        "LoD/1.09d": "0x004017BB",
        "LoD/1.10": "0x004017BB",
        "LoD/1.11": "0x004017BB",
        "LoD/1.11b": "0x004017BB",
        "LoD/1.12a": "0x004017BB",
        "LoD/1.13c": "0x004017BB",
        "LoD/1.13d": "0x004017BB",
        "LoD/1.14a": "0x004017BB",
        "LoD/1.14b": "0x004017BB",
        "LoD/1.14c": "0x004017BB",
        "LoD/1.14d": "0x004017BB"
      },
      "rvas": {
        "LoD/1.07": "0x17BB",
        "LoD/1.08": "0x17BB",
        "LoD/1.09": "0x17BB",
        "LoD/1.09b": "0x17BB",
        "LoD/1.09d": "0x17BB",
        "LoD/1.10": "0x17BB",
        "LoD/1.11": "0x17BB",
        "LoD/1.11b": "0x17BB",
        "LoD/1.12a": "0x17BB",
        "LoD/1.13c": "0x17BB",
        "LoD/1.13d": "0x17BB",
        "LoD/1.14a": "0x17BB",
        "LoD/1.14b": "0x17BB",
        "LoD/1.14c": "0x17BB",
        "LoD/1.14d": "0x17BB"
      },
      "sizes": {
        "LoD/1.07": 74,
        "LoD/1.08": 74,
        "LoD/1.09": 74,
        "LoD/1.09b": 74,
        "LoD/1.09d": 74,
        "LoD/1.10": 74,
        "LoD/1.11": 74,
        "LoD/1.11b": 74,
        "LoD/1.12a": 74,
        "LoD/1.13c": 74,
        "LoD/1.13d": 74,
        "LoD/1.14a": 74,
        "LoD/1.14b": 74,
        "LoD/1.14c": 74,
        "LoD/1.14d": 74
      },
      "name": "ResolveCodePageIdentifier",
      "signature": "uint ResolveCodePageIdentifier(int nCodePageSelector)",
      "calling_convention": "__cdecl",
      "return_type": "uint",
      "comment": "Resolves code page identifiers to actual Windows code page numbers.\n\nAlgorithm:\n1. Clear initialization flag g_dwCodePageInitialized to 0\n2. Check if nCodePageSelector equals -2 (CP_OEMCP constant)\n   - Set g_dwCodePageInitialized = 1 to mark operation performed\n   - Call GetOEMCP() API to retrieve OEM code page\n   - Return OEM code page number\n3. Check if nCodePageSelector equals -3 (CP_ACP constant)  \n   - Set g_dwCodePageInitialized = 1 to mark operation performed\n   - Call GetACP() API to retrieve ANSI code page\n   - Return ANSI code page number\n4. Check if nCodePageSelector equals -4 (CP_THREAD_ACP constant)\n   - Retrieve stored thread locale code page from g_dwThreadLocaleCodePage\n   - Set g_dwCodePageInitialized = 1 to mark operation performed\n   - Return thread locale code page value\n5. For any other value (explicit code page number)\n   - Keep g_dwCodePageInitialized = 0 (no API call needed)\n   - Return nCodePageSelector unchanged\n\nParameters:\nnCodePageSelector (int): Code page selector constant or explicit code page number\n  -2 (CP_OEMCP): Request OEM code page via GetOEMCP()\n  -3 (CP_ACP): Request ANSI code page via GetACP()  \n  -4 (CP_THREAD_ACP): Request thread locale code page from global storage\n  Other: Explicit Windows code page number (1252, 65001, etc.)\n\nReturns:\nuint: Resolved Windows code page number\n  Success: Valid code page number (437, 1252, 65001, etc.)\n  Error: Original nCodePageSelector value if no resolution needed\n\nSpecial Cases:\n- Indirect jumps at 0x100215b0 and 0x100215c5 call GetOEMCP/GetACP via function pointers\n- Thread locale code page (-4) uses pre-stored value, not live API call\n- Global flag g_dwCodePageInitialized tracks whether API resolution was performed\n- Function handles both symbolic constants and explicit numeric code page values\n\nMagic Numbers Reference:\n-2 (0xFFFFFFFE): CP_OEMCP - OEM code page constant\n-3 (0xFFFFFFFD): CP_ACP - ANSI code page constant  \n-4 (0xFFFFFFFC): CP_THREAD_ACP - Thread locale code page constant\n0x1003ca88: Address of g_dwCodePageInitialized flag\n0x1003c8e4: Address of g_dwThreadLocaleCodePage storage\n0x100230b0: Function pointer to GetOEMCP API\n0x100230ac: Function pointer to GetACP API",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:8f2a733057dd5a290f0e17d077c53986",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "8f2a733057dd5a290f0e17d077c53986",
        "CFG": "3fff12cee20d7217020e61babff50752",
        "PRO": "932b89934961eeda54cd9a9e50ce4be1",
        "CAL": null,
        "CON": null,
        "APS": null
      },
      "callers": {
        "LoD/1.07": [
          "InitializeCodePageLocale|0x401622"
        ],
        "LoD/1.08": [
          "InitializeCodePageLocale|0x401622"
        ],
        "LoD/1.09": [
          "InitializeCodePageLocale|0x401622"
        ],
        "LoD/1.09b": [
          "InitializeCodePageLocale|0x401622"
        ],
        "LoD/1.09d": [
          "InitializeCodePageLocale|0x401622"
        ],
        "LoD/1.10": [
          "InitializeCodePageLocale|0x401622"
        ],
        "LoD/1.11": [
          "InitializeCodePageLocale|0x401622"
        ],
        "LoD/1.11b": [
          "InitializeCodePageLocale|0x401622"
        ],
        "LoD/1.12a": [
          "InitializeCodePageLocale|0x401622"
        ],
        "LoD/1.13c": [
          "InitializeCodePageLocale|0x401622"
        ],
        "LoD/1.13d": [
          "InitializeCodePageLocale|0x401622"
        ],
        "LoD/1.14a": [
          "InitializeCodePageLocale|0x401622"
        ],
        "LoD/1.14b": [
          "InitializeCodePageLocale|0x401622"
        ],
        "LoD/1.14c": [
          "InitializeCodePageLocale|0x401622"
        ],
        "LoD/1.14d": [
          "InitializeCodePageLocale|0x401622"
        ]
      },
      "instruction_counts": {
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
        "LoD/1.13d": 15,
        "LoD/1.14a": 15,
        "LoD/1.14b": 15,
        "LoD/1.14c": 15,
        "LoD/1.14d": 15
      },
      "stack_frame_sizes": {
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
        "LoD/1.13d": 8,
        "LoD/1.14a": 8,
        "LoD/1.14b": 8,
        "LoD/1.14c": 8,
        "LoD/1.14d": 8
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
        "LoD/1.13d": 7,
        "LoD/1.14a": 7,
        "LoD/1.14b": 7,
        "LoD/1.14c": 7,
        "LoD/1.14d": 7
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
        "LoD/1.13d": 0,
        "LoD/1.14a": 0,
        "LoD/1.14b": 0,
        "LoD/1.14c": 0,
        "LoD/1.14d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "8f2a733057dd5a290f0e17d077c53986",
        "LoD/1.08": "8f2a733057dd5a290f0e17d077c53986",
        "LoD/1.09": "8f2a733057dd5a290f0e17d077c53986",
        "LoD/1.09b": "8f2a733057dd5a290f0e17d077c53986",
        "LoD/1.09d": "8f2a733057dd5a290f0e17d077c53986",
        "LoD/1.10": "8f2a733057dd5a290f0e17d077c53986",
        "LoD/1.11": "8f2a733057dd5a290f0e17d077c53986",
        "LoD/1.11b": "8f2a733057dd5a290f0e17d077c53986",
        "LoD/1.12a": "8f2a733057dd5a290f0e17d077c53986",
        "LoD/1.13c": "8f2a733057dd5a290f0e17d077c53986",
        "LoD/1.13d": "8f2a733057dd5a290f0e17d077c53986",
        "LoD/1.14a": "8f2a733057dd5a290f0e17d077c53986",
        "LoD/1.14b": "8f2a733057dd5a290f0e17d077c53986",
        "LoD/1.14c": "8f2a733057dd5a290f0e17d077c53986",
        "LoD/1.14d": "8f2a733057dd5a290f0e17d077c53986"
      },
      "globals": {
        "LoD/1.07": [
          "0xFFFFFFFFFFC00004|",
          "0x64C0|g_dwCodePageInitialized",
          "0x6638|g_dwThreadLocaleCodePage"
        ],
        "LoD/1.08": [
          "0xFFFFFFFFFFC00004|",
          "0x64C0|g_dwCodePageInitialized",
          "0x6638|g_dwThreadLocaleCodePage"
        ],
        "LoD/1.09": [
          "0xFFFFFFFFFFC00004|",
          "0x64C0|g_dwCodePageInitialized",
          "0x6638|g_dwThreadLocaleCodePage"
        ],
        "LoD/1.09b": [
          "0xFFFFFFFFFFC00004|",
          "0x64C0|g_dwCodePageInitialized",
          "0x6638|g_dwThreadLocaleCodePage"
        ],
        "LoD/1.09d": [
          "0xFFFFFFFFFFC00004|",
          "0x64C0|g_dwCodePageInitialized",
          "0x6638|g_dwThreadLocaleCodePage"
        ],
        "LoD/1.10": [
          "0xFFFFFFFFFFC00004|",
          "0x64C0|g_dwCodePageInitialized",
          "0x6638|g_dwThreadLocaleCodePage"
        ],
        "LoD/1.11": [
          "0xFFFFFFFFFFC00004|",
          "0x64C0|g_dwCodePageInitialized",
          "0x6638|g_dwThreadLocaleCodePage"
        ],
        "LoD/1.11b": [
          "0xFFFFFFFFFFC00004|",
          "0x64C0|g_dwCodePageInitialized",
          "0x6638|g_dwThreadLocaleCodePage"
        ],
        "LoD/1.12a": [
          "0xFFFFFFFFFFC00004|",
          "0x64C0|g_dwCodePageInitialized",
          "0x6638|g_dwThreadLocaleCodePage"
        ],
        "LoD/1.13c": [
          "0xFFFFFFFFFFC00004|",
          "0x64C0|g_dwCodePageInitialized",
          "0x6638|g_dwThreadLocaleCodePage"
        ],
        "LoD/1.13d": [
          "0xFFFFFFFFFFC00004|",
          "0x64C0|g_dwCodePageInitialized",
          "0x6638|g_dwThreadLocaleCodePage"
        ],
        "LoD/1.14a": [
          "0xFFFFFFFFFFC00004|",
          "0x64C0|g_dwCodePageInitialized",
          "0x6638|g_dwThreadLocaleCodePage"
        ],
        "LoD/1.14b": [
          "0xFFFFFFFFFFC00004|",
          "0x64C0|g_dwCodePageInitialized",
          "0x6638|g_dwThreadLocaleCodePage"
        ],
        "LoD/1.14c": [
          "0xFFFFFFFFFFC00004|",
          "0x64C0|g_dwCodePageInitialized",
          "0x6638|g_dwThreadLocaleCodePage"
        ],
        "LoD/1.14d": [
          "0xFFFFFFFFFFC00004|",
          "0x64C0|g_dwCodePageInitialized",
          "0x6638|g_dwThreadLocaleCodePage"
        ]
      }
    },
    "diablo ii.exe_MapCodePageIdentifier": {
      "addresses": {
        "LoD/1.07": "0x00401805",
        "LoD/1.08": "0x00401805",
        "LoD/1.09": "0x00401805",
        "LoD/1.09b": "0x00401805",
        "LoD/1.09d": "0x00401805",
        "LoD/1.10": "0x00401805",
        "LoD/1.11": "0x00401805",
        "LoD/1.11b": "0x00401805",
        "LoD/1.12a": "0x00401805",
        "LoD/1.13c": "0x00401805",
        "LoD/1.13d": "0x00401805",
        "LoD/1.14a": "0x00401805",
        "LoD/1.14b": "0x00401805",
        "LoD/1.14c": "0x00401805",
        "LoD/1.14d": "0x00401805"
      },
      "rvas": {
        "LoD/1.07": "0x1805",
        "LoD/1.08": "0x1805",
        "LoD/1.09": "0x1805",
        "LoD/1.09b": "0x1805",
        "LoD/1.09d": "0x1805",
        "LoD/1.10": "0x1805",
        "LoD/1.11": "0x1805",
        "LoD/1.11b": "0x1805",
        "LoD/1.12a": "0x1805",
        "LoD/1.13c": "0x1805",
        "LoD/1.13d": "0x1805",
        "LoD/1.14a": "0x1805",
        "LoD/1.14b": "0x1805",
        "LoD/1.14c": "0x1805",
        "LoD/1.14d": "0x1805"
      },
      "sizes": {
        "LoD/1.07": 51,
        "LoD/1.08": 51,
        "LoD/1.09": 51,
        "LoD/1.09b": 51,
        "LoD/1.09d": 51,
        "LoD/1.10": 51,
        "LoD/1.11": 51,
        "LoD/1.11b": 51,
        "LoD/1.12a": 51,
        "LoD/1.13c": 51,
        "LoD/1.13d": 51,
        "LoD/1.14a": 51,
        "LoD/1.14b": 51,
        "LoD/1.14c": 51,
        "LoD/1.14d": 51
      },
      "name": "MapCodePageIdentifier",
      "signature": "uint MapCodePageIdentifier(uint dwInputCodePage)",
      "calling_convention": "__cdecl",
      "return_type": "uint",
      "comment": "Maps input code page identifiers to corresponding output code page identifiers for locale initialization.\n\nAlgorithm:\n1. Check if input code page matches 0x3a4 (932 - Japanese Shift_JIS)\n2. If match, return 0x411 (1041 - Japanese Japan)\n3. Check if input code page matches 0x3a8 (936 - Chinese Simplified GBK) \n4. If match, return 0x804 (2052 - Chinese People's Republic)\n5. Check if input code page matches 0x3b5 (949 - Korean)\n6. If match, return 0x412 (1042 - Korean)\n7. Check if input code page matches 0x3b6 (950 - Chinese Traditional Big5)\n8. If match, return 0x404 (1028 - Chinese Taiwan)\n9. If no matches found, return 0 (invalid/unsupported code page)\n\nParameters:\n  dwInputCodePage (uint): Input code page identifier to map\n\nReturns:\n  uint: Corresponding locale identifier (LCID) if supported, 0 if unsupported\n\nMagic Numbers Reference:\n  0x3a4 (932): Japanese Shift_JIS code page\n  0x3a8 (936): Chinese Simplified GBK code page\n  0x3b5 (949): Korean code page  \n  0x3b6 (950): Chinese Traditional Big5 code page\n  0x411 (1041): Japanese Japan LCID\n  0x804 (2052): Chinese People's Republic LCID\n  0x412 (1042): Korean LCID\n  0x404 (1028): Chinese Taiwan LCID",
      "name_source": "LoD/1.07",
      "method": "CON",
      "index": "CON:f710c320ffeaad35efd664e99e7b58dd",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "f31c6439952ca9c3e10694cce3d833df",
        "CFG": "5cd7ae11dfc37525b1fbae6f1a834a1b",
        "PRO": "252bd71e2f7f97e91ef40be3ccbd06e8",
        "CAL": null,
        "CON": "f710c320ffeaad35efd664e99e7b58dd",
        "APS": null
      },
      "callers": {
        "LoD/1.07": [
          "InitializeCodePageLocale|0x401622"
        ],
        "LoD/1.08": [
          "InitializeCodePageLocale|0x401622"
        ],
        "LoD/1.09": [
          "InitializeCodePageLocale|0x401622"
        ],
        "LoD/1.09b": [
          "InitializeCodePageLocale|0x401622"
        ],
        "LoD/1.09d": [
          "InitializeCodePageLocale|0x401622"
        ],
        "LoD/1.10": [
          "InitializeCodePageLocale|0x401622"
        ],
        "LoD/1.11": [
          "InitializeCodePageLocale|0x401622"
        ],
        "LoD/1.11b": [
          "InitializeCodePageLocale|0x401622"
        ],
        "LoD/1.12a": [
          "InitializeCodePageLocale|0x401622"
        ],
        "LoD/1.13c": [
          "InitializeCodePageLocale|0x401622"
        ],
        "LoD/1.13d": [
          "InitializeCodePageLocale|0x401622"
        ],
        "LoD/1.14a": [
          "InitializeCodePageLocale|0x401622"
        ],
        "LoD/1.14b": [
          "InitializeCodePageLocale|0x401622"
        ],
        "LoD/1.14c": [
          "InitializeCodePageLocale|0x401622"
        ],
        "LoD/1.14d": [
          "InitializeCodePageLocale|0x401622"
        ]
      },
      "instruction_counts": {
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
        "LoD/1.13d": 19,
        "LoD/1.14a": 19,
        "LoD/1.14b": 19,
        "LoD/1.14c": 19,
        "LoD/1.14d": 19
      },
      "stack_frame_sizes": {
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
        "LoD/1.13d": 8,
        "LoD/1.14a": 8,
        "LoD/1.14b": 8,
        "LoD/1.14c": 8,
        "LoD/1.14d": 8
      },
      "basic_block_counts": {
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
        "LoD/1.13d": 9,
        "LoD/1.14a": 9,
        "LoD/1.14b": 9,
        "LoD/1.14c": 9,
        "LoD/1.14d": 9
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
        "LoD/1.13d": 0,
        "LoD/1.14a": 0,
        "LoD/1.14b": 0,
        "LoD/1.14c": 0,
        "LoD/1.14d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "f31c6439952ca9c3e10694cce3d833df",
        "LoD/1.08": "f31c6439952ca9c3e10694cce3d833df",
        "LoD/1.09": "f31c6439952ca9c3e10694cce3d833df",
        "LoD/1.09b": "f31c6439952ca9c3e10694cce3d833df",
        "LoD/1.09d": "f31c6439952ca9c3e10694cce3d833df",
        "LoD/1.10": "f31c6439952ca9c3e10694cce3d833df",
        "LoD/1.11": "f31c6439952ca9c3e10694cce3d833df",
        "LoD/1.11b": "f31c6439952ca9c3e10694cce3d833df",
        "LoD/1.12a": "f31c6439952ca9c3e10694cce3d833df",
        "LoD/1.13c": "f31c6439952ca9c3e10694cce3d833df",
        "LoD/1.13d": "f31c6439952ca9c3e10694cce3d833df",
        "LoD/1.14a": "f31c6439952ca9c3e10694cce3d833df",
        "LoD/1.14b": "f31c6439952ca9c3e10694cce3d833df",
        "LoD/1.14c": "f31c6439952ca9c3e10694cce3d833df",
        "LoD/1.14d": "f31c6439952ca9c3e10694cce3d833df"
      },
      "constants": {
        "LoD/1.07": [
          932,
          1028,
          1041,
          1042,
          2052
        ],
        "LoD/1.08": [
          932,
          1028,
          1041,
          1042,
          2052
        ],
        "LoD/1.09": [
          932,
          1028,
          1041,
          1042,
          2052
        ],
        "LoD/1.09b": [
          932,
          1028,
          1041,
          1042,
          2052
        ],
        "LoD/1.09d": [
          932,
          1028,
          1041,
          1042,
          2052
        ],
        "LoD/1.10": [
          932,
          1028,
          1041,
          1042,
          2052
        ],
        "LoD/1.11": [
          932,
          1028,
          1041,
          1042,
          2052
        ],
        "LoD/1.11b": [
          932,
          1028,
          1041,
          1042,
          2052
        ],
        "LoD/1.12a": [
          932,
          1028,
          1041,
          1042,
          2052
        ],
        "LoD/1.13c": [
          932,
          1028,
          1041,
          1042,
          2052
        ],
        "LoD/1.13d": [
          932,
          1028,
          1041,
          1042,
          2052
        ],
        "LoD/1.14a": [
          932,
          1028,
          1041,
          1042,
          2052
        ],
        "LoD/1.14b": [
          932,
          1028,
          1041,
          1042,
          2052
        ],
        "LoD/1.14c": [
          932,
          1028,
          1041,
          1042,
          2052
        ],
        "LoD/1.14d": [
          932,
          1028,
          1041,
          1042,
          2052
        ]
      },
      "globals": {
        "LoD/1.07": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.08": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.09": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.09b": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.09d": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.10": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.11": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.11b": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.12a": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.13c": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.13d": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.14a": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.14b": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.14c": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.14d": [
          "0xFFFFFFFFFFC00004|"
        ]
      }
    },
    "diablo ii.exe_InitializeLocaleDataBuffers": {
      "addresses": {
        "LoD/1.07": "0x00401838",
        "LoD/1.08": "0x00401838",
        "LoD/1.09": "0x00401838",
        "LoD/1.09b": "0x00401838",
        "LoD/1.09d": "0x00401838",
        "LoD/1.10": "0x00401838",
        "LoD/1.11": "0x00401838",
        "LoD/1.11b": "0x00401838",
        "LoD/1.12a": "0x00401838",
        "LoD/1.13c": "0x00401838",
        "LoD/1.13d": "0x00401838",
        "LoD/1.14a": "0x00401838",
        "LoD/1.14b": "0x00401838",
        "LoD/1.14c": "0x00401838",
        "LoD/1.14d": "0x00401838"
      },
      "rvas": {
        "LoD/1.07": "0x1838",
        "LoD/1.08": "0x1838",
        "LoD/1.09": "0x1838",
        "LoD/1.09b": "0x1838",
        "LoD/1.09d": "0x1838",
        "LoD/1.10": "0x1838",
        "LoD/1.11": "0x1838",
        "LoD/1.11b": "0x1838",
        "LoD/1.12a": "0x1838",
        "LoD/1.13c": "0x1838",
        "LoD/1.13d": "0x1838",
        "LoD/1.14a": "0x1838",
        "LoD/1.14b": "0x1838",
        "LoD/1.14c": "0x1838",
        "LoD/1.14d": "0x1838"
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
        "LoD/1.13d": 41,
        "LoD/1.14a": 41,
        "LoD/1.14b": 41,
        "LoD/1.14c": 41,
        "LoD/1.14d": 41
      },
      "name": "InitializeLocaleDataBuffers",
      "signature": "void InitializeLocaleDataBuffers(void)",
      "calling_convention": "__stdcall",
      "return_type": "void",
      "comment": "Initializes locale-related data buffers by zeroing memory regions and global variables.\n\nAlgorithm:\n1. Initialize pointer to start of buffer at 0x1003cbc0\n2. Set loop counter to 0x40 (64 iterations)\n3. For each iteration, store zero at current pointer location and increment pointer\n4. After loop, store additional zero byte at final pointer location\n5. Zero individual global variables at specific addresses\n\nParameters:\nNone\n\nReturns:\nvoid\n\nMagic Numbers Reference:\n0x40 (64 decimal) - Number of DWORDs to zero in main buffer\n0x1003cbc0 - Start address of main buffer to be zeroed\n0x1003caa4 - Global variable address\n0x1003cabc - Global variable address  \n0x1003ccc4 - Global variable address\n0x1003cab0 - Global variable address\n0x1003cab4 - Global variable address\n0x1003cab8 - Global variable address\n\nSpecial Cases:\nEnsures complete buffer initialization by storing extra zero byte after REP STOSD\nClears 256 bytes total (64 DWORDs * 4 bytes + 1 additional byte)",
      "name_source": "LoD/1.07",
      "method": "CON",
      "index": "CON:b7470f7199862f97617d4c4d6f7150e3",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "05d3556ba26e52c51954a1255d97c525",
        "CFG": "e44c2ff58c3054cb39205525061d1e17",
        "PRO": "705230914eb290d5ec2051144eb14d62",
        "CAL": null,
        "CON": "b7470f7199862f97617d4c4d6f7150e3",
        "APS": null
      },
      "callers": {
        "LoD/1.07": [
          "InitializeCodePageLocale|0x401622"
        ],
        "LoD/1.08": [
          "InitializeCodePageLocale|0x401622"
        ],
        "LoD/1.09": [
          "InitializeCodePageLocale|0x401622"
        ],
        "LoD/1.09b": [
          "InitializeCodePageLocale|0x401622"
        ],
        "LoD/1.09d": [
          "InitializeCodePageLocale|0x401622"
        ],
        "LoD/1.10": [
          "InitializeCodePageLocale|0x401622"
        ],
        "LoD/1.11": [
          "InitializeCodePageLocale|0x401622"
        ],
        "LoD/1.11b": [
          "InitializeCodePageLocale|0x401622"
        ],
        "LoD/1.12a": [
          "InitializeCodePageLocale|0x401622"
        ],
        "LoD/1.13c": [
          "InitializeCodePageLocale|0x401622"
        ],
        "LoD/1.13d": [
          "InitializeCodePageLocale|0x401622"
        ],
        "LoD/1.14a": [
          "InitializeCodePageLocale|0x401622"
        ],
        "LoD/1.14b": [
          "InitializeCodePageLocale|0x401622"
        ],
        "LoD/1.14c": [
          "InitializeCodePageLocale|0x401622"
        ],
        "LoD/1.14d": [
          "InitializeCodePageLocale|0x401622"
        ]
      },
      "instruction_counts": {
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
        "LoD/1.13d": 17,
        "LoD/1.14a": 17,
        "LoD/1.14b": 17,
        "LoD/1.14c": 17,
        "LoD/1.14d": 17
      },
      "stack_frame_sizes": {
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
        "LoD/1.13d": 4,
        "LoD/1.14a": 4,
        "LoD/1.14b": 4,
        "LoD/1.14c": 4,
        "LoD/1.14d": 4
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
        "LoD/1.13d": 1,
        "LoD/1.14a": 1,
        "LoD/1.14b": 1,
        "LoD/1.14c": 1,
        "LoD/1.14d": 1
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
        "LoD/1.13d": 0,
        "LoD/1.14a": 0,
        "LoD/1.14b": 0,
        "LoD/1.14c": 0,
        "LoD/1.14d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "05d3556ba26e52c51954a1255d97c525",
        "LoD/1.08": "05d3556ba26e52c51954a1255d97c525",
        "LoD/1.09": "05d3556ba26e52c51954a1255d97c525",
        "LoD/1.09b": "05d3556ba26e52c51954a1255d97c525",
        "LoD/1.09d": "05d3556ba26e52c51954a1255d97c525",
        "LoD/1.10": "05d3556ba26e52c51954a1255d97c525",
        "LoD/1.11": "05d3556ba26e52c51954a1255d97c525",
        "LoD/1.11b": "05d3556ba26e52c51954a1255d97c525",
        "LoD/1.12a": "05d3556ba26e52c51954a1255d97c525",
        "LoD/1.13c": "05d3556ba26e52c51954a1255d97c525",
        "LoD/1.13d": "05d3556ba26e52c51954a1255d97c525",
        "LoD/1.14a": "05d3556ba26e52c51954a1255d97c525",
        "LoD/1.14b": "05d3556ba26e52c51954a1255d97c525",
        "LoD/1.14c": "05d3556ba26e52c51954a1255d97c525",
        "LoD/1.14d": "05d3556ba26e52c51954a1255d97c525"
      },
      "constants": {
        "LoD/1.07": [
          4220832,
          4221120
        ],
        "LoD/1.08": [
          4220832,
          4221120
        ],
        "LoD/1.09": [
          4220832,
          4221120
        ],
        "LoD/1.09b": [
          4220832,
          4221120
        ],
        "LoD/1.09d": [
          4220832,
          4221120
        ],
        "LoD/1.10": [
          4220832,
          4221120
        ],
        "LoD/1.11": [
          4220832,
          4221120
        ],
        "LoD/1.11b": [
          4220832,
          4221120
        ],
        "LoD/1.12a": [
          4220832,
          4221120
        ],
        "LoD/1.13c": [
          4220832,
          4221120
        ],
        "LoD/1.13d": [
          4220832,
          4221120
        ],
        "LoD/1.14a": [
          4220832,
          4221120
        ],
        "LoD/1.14b": [
          4220832,
          4221120
        ],
        "LoD/1.14c": [
          4220832,
          4221120
        ],
        "LoD/1.14d": [
          4220832,
          4221120
        ]
      },
      "globals": {
        "LoD/1.07": [
          "0x68C0|DAT_004068c0",
          "0x68C4|DAT_004068c4",
          "0x67A0|DAT_004067a0",
          "0x6798|g_dwCurrentCodePage",
          "0x67AC|g_fIsMultiByteCodePage",
          "0x69C4|g_dwCodePageProperties",
          "0x67A4|DAT_004067a4",
          "0x67A8|DAT_004067a8"
        ],
        "LoD/1.08": [
          "0x68C0|DAT_004068c0",
          "0x68C4|DAT_004068c4",
          "0x67A0|DAT_004067a0",
          "0x6798|g_dwCurrentCodePage",
          "0x67AC|g_fIsMultiByteCodePage",
          "0x69C4|g_dwCodePageProperties",
          "0x67A4|DAT_004067a4",
          "0x67A8|DAT_004067a8"
        ],
        "LoD/1.09": [
          "0x68C0|DAT_004068c0",
          "0x68C4|DAT_004068c4",
          "0x67A0|DAT_004067a0",
          "0x6798|g_dwCurrentCodePage",
          "0x67AC|g_fIsMultiByteCodePage",
          "0x69C4|g_dwCodePageProperties",
          "0x67A4|DAT_004067a4",
          "0x67A8|DAT_004067a8"
        ],
        "LoD/1.09b": [
          "0x68C0|DAT_004068c0",
          "0x68C4|DAT_004068c4",
          "0x67A0|DAT_004067a0",
          "0x6798|g_dwCurrentCodePage",
          "0x67AC|g_fIsMultiByteCodePage",
          "0x69C4|g_dwCodePageProperties",
          "0x67A4|DAT_004067a4",
          "0x67A8|DAT_004067a8"
        ],
        "LoD/1.09d": [
          "0x68C0|DAT_004068c0",
          "0x68C4|DAT_004068c4",
          "0x67A0|DAT_004067a0",
          "0x6798|g_dwCurrentCodePage",
          "0x67AC|g_fIsMultiByteCodePage",
          "0x69C4|g_dwCodePageProperties",
          "0x67A4|DAT_004067a4",
          "0x67A8|DAT_004067a8"
        ],
        "LoD/1.10": [
          "0x68C0|DAT_004068c0",
          "0x68C4|DAT_004068c4",
          "0x67A0|DAT_004067a0",
          "0x6798|g_dwCurrentCodePage",
          "0x67AC|g_fIsMultiByteCodePage",
          "0x69C4|g_dwCodePageProperties",
          "0x67A4|DAT_004067a4",
          "0x67A8|DAT_004067a8"
        ],
        "LoD/1.11": [
          "0x68C0|DAT_004068c0",
          "0x68C4|DAT_004068c4",
          "0x67A0|DAT_004067a0",
          "0x6798|g_dwCurrentCodePage",
          "0x67AC|g_fIsMultiByteCodePage",
          "0x69C4|g_dwCodePageProperties",
          "0x67A4|DAT_004067a4",
          "0x67A8|DAT_004067a8"
        ],
        "LoD/1.11b": [
          "0x68C0|DAT_004068c0",
          "0x68C4|DAT_004068c4",
          "0x67A0|DAT_004067a0",
          "0x6798|g_dwCurrentCodePage",
          "0x67AC|g_fIsMultiByteCodePage",
          "0x69C4|g_dwCodePageProperties",
          "0x67A4|DAT_004067a4",
          "0x67A8|DAT_004067a8"
        ],
        "LoD/1.12a": [
          "0x68C0|DAT_004068c0",
          "0x68C4|DAT_004068c4",
          "0x67A0|DAT_004067a0",
          "0x6798|g_dwCurrentCodePage",
          "0x67AC|g_fIsMultiByteCodePage",
          "0x69C4|g_dwCodePageProperties",
          "0x67A4|DAT_004067a4",
          "0x67A8|DAT_004067a8"
        ],
        "LoD/1.13c": [
          "0x68C0|DAT_004068c0",
          "0x68C4|DAT_004068c4",
          "0x67A0|DAT_004067a0",
          "0x6798|g_dwCurrentCodePage",
          "0x67AC|g_fIsMultiByteCodePage",
          "0x69C4|g_dwCodePageProperties",
          "0x67A4|DAT_004067a4",
          "0x67A8|DAT_004067a8"
        ],
        "LoD/1.13d": [
          "0x68C0|DAT_004068c0",
          "0x68C4|DAT_004068c4",
          "0x67A0|DAT_004067a0",
          "0x6798|g_dwCurrentCodePage",
          "0x67AC|g_fIsMultiByteCodePage",
          "0x69C4|g_dwCodePageProperties",
          "0x67A4|DAT_004067a4",
          "0x67A8|DAT_004067a8"
        ],
        "LoD/1.14a": [
          "0x68C0|DAT_004068c0",
          "0x68C4|DAT_004068c4",
          "0x67A0|DAT_004067a0",
          "0x6798|g_dwCurrentCodePage",
          "0x67AC|g_fIsMultiByteCodePage",
          "0x69C4|g_dwCodePageProperties",
          "0x67A4|DAT_004067a4",
          "0x67A8|DAT_004067a8"
        ],
        "LoD/1.14b": [
          "0x68C0|DAT_004068c0",
          "0x68C4|DAT_004068c4",
          "0x67A0|DAT_004067a0",
          "0x6798|g_dwCurrentCodePage",
          "0x67AC|g_fIsMultiByteCodePage",
          "0x69C4|g_dwCodePageProperties",
          "0x67A4|DAT_004067a4",
          "0x67A8|DAT_004067a8"
        ],
        "LoD/1.14c": [
          "0x68C0|DAT_004068c0",
          "0x68C4|DAT_004068c4",
          "0x67A0|DAT_004067a0",
          "0x6798|g_dwCurrentCodePage",
          "0x67AC|g_fIsMultiByteCodePage",
          "0x69C4|g_dwCodePageProperties",
          "0x67A4|DAT_004067a4",
          "0x67A8|DAT_004067a8"
        ],
        "LoD/1.14d": [
          "0x68C0|DAT_004068c0",
          "0x68C4|DAT_004068c4",
          "0x67A0|DAT_004067a0",
          "0x6798|g_dwCurrentCodePage",
          "0x67AC|g_fIsMultiByteCodePage",
          "0x69C4|g_dwCodePageProperties",
          "0x67A4|DAT_004067a4",
          "0x67A8|DAT_004067a8"
        ]
      }
    },
    "diablo ii.exe_InitializeCharacterTables": {
      "addresses": {
        "LoD/1.07": "0x00401861",
        "LoD/1.08": "0x00401861",
        "LoD/1.09": "0x00401861",
        "LoD/1.09b": "0x00401861",
        "LoD/1.09d": "0x00401861",
        "LoD/1.10": "0x00401861",
        "LoD/1.11": "0x00401861",
        "LoD/1.11b": "0x00401861",
        "LoD/1.12a": "0x00401861",
        "LoD/1.13c": "0x00401861",
        "LoD/1.13d": "0x00401861",
        "LoD/1.14a": "0x00401861",
        "LoD/1.14b": "0x00401861",
        "LoD/1.14c": "0x00401861",
        "LoD/1.14d": "0x00401861"
      },
      "rvas": {
        "LoD/1.07": "0x1861",
        "LoD/1.08": "0x1861",
        "LoD/1.09": "0x1861",
        "LoD/1.09b": "0x1861",
        "LoD/1.09d": "0x1861",
        "LoD/1.10": "0x1861",
        "LoD/1.11": "0x1861",
        "LoD/1.11b": "0x1861",
        "LoD/1.12a": "0x1861",
        "LoD/1.13c": "0x1861",
        "LoD/1.13d": "0x1861",
        "LoD/1.14a": "0x1861",
        "LoD/1.14b": "0x1861",
        "LoD/1.14c": "0x1861",
        "LoD/1.14d": "0x1861"
      },
      "sizes": {
        "LoD/1.07": 389,
        "LoD/1.08": 389,
        "LoD/1.09": 389,
        "LoD/1.09b": 389,
        "LoD/1.09d": 389,
        "LoD/1.10": 389,
        "LoD/1.11": 389,
        "LoD/1.11b": 389,
        "LoD/1.12a": 389,
        "LoD/1.13c": 389,
        "LoD/1.13d": 389,
        "LoD/1.14a": 389,
        "LoD/1.14b": 389,
        "LoD/1.14c": 389,
        "LoD/1.14d": 389
      },
      "name": "InitializeCharacterTables",
      "signature": "void InitializeCharacterTables(void)",
      "calling_convention": "__stdcall",
      "return_type": "void",
      "comment": "Initializes character lookup tables and locale-specific character mappings for the current code page.\n\nAlgorithm:\n1. Retrieve code page information using GetCPInfo() with the global code page identifier\n2. If code page info valid, initialize base character table with identity mapping (0-255)\n3. Set character at index 0 to space character for proper handling\n4. Process multi-byte character lead byte ranges to mark them as spaces in character table\n5. Call FUN_10021c9e to generate character type flags for the character set\n6. Generate uppercase mappings using LocaleMapStringWithConversion with flag 0x100\n7. Generate lowercase mappings using LocaleMapStringWithConversion with flag 0x200\n8. Iterate through all 256 characters and populate global character tables:\n   - If character type flag & 0x1 (uppercase): set flag 0x10, use lowercase mapping\n   - If character type flag & 0x2 (lowercase): set flag 0x20, use uppercase mapping\n   - Otherwise: clear character mapping entry\n9. If code page info invalid, fall back to ASCII-only mappings:\n   - For A-Z (0x41-0x5A): set flag 0x10, add 0x20 for lowercase\n   - For a-z (0x61-0x7A): set flag 0x20, subtract 0x20 for uppercase\n   - For all other characters: clear mapping entry\n\nParameters:\nNone\n\nReturns:\nvoid - Function operates on global character tables DAT_1003cac0 and DAT_1003cbc0\n\nSpecial Cases:\n- Character 0 is always mapped to space (0x20) for proper null character handling\n- Lead bytes in multi-byte character sets are marked as spaces to prevent misinterpretation\n- Falls back to basic ASCII case mapping if code page information unavailable\n\nMagic Numbers:\n0x100 - LCMAP_UPPERCASE flag for LocaleMapStringWithConversion\n0x200 - LCMAP_LOWERCASE flag for LocaleMapStringWithConversion  \n0x10 - Character flag indicating uppercase letter\n0x20 - Character flag indicating lowercase letter\n0x1 - Character type flag for uppercase character\n0x2 - Character type flag for lowercase character\n0x41-0x5A - ASCII range for uppercase letters A-Z\n0x61-0x7A - ASCII range for lowercase letters a-z\n\nError Handling:\n- GetCPInfo failure triggers fallback to ASCII-only character mappings\n- Lead byte processing handles ranges safely with bounds checking\n- Character table initialization ensures all 256 entries are properly set\n\nStructure Layout:\n_cpinfo structure (18 bytes):\nOffset  Size  Field Name    Type    Description\n0x0     4     MaxCharSize   UINT    Maximum character size in bytes\n0x4     12    DefaultChar   BYTE[2] Default replacement character \n0x6     12    LeadByte      BYTE[12] Lead byte ranges for MBCS",
      "name_source": "LoD/1.07",
      "method": "CAL",
      "index": "CAL:8fef33b7be657857e90895678ccb4fd8",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "63906d1f35f7842042066a6643d2050c",
        "CFG": "93ed6a55cbc9b3cb34db69a54e1f806b",
        "PRO": "9f903305dac24c951f3cebb45cf66933",
        "CAL": "8fef33b7be657857e90895678ccb4fd8",
        "CON": "2b3767d0f4a9d1a69e158866fa7f542a",
        "APS": null
      },
      "callees": {
        "LoD/1.07": [
          "LocaleMapStringWithConversion|0x4028DC",
          "GetCPInfo|0xF",
          "GetCharacterTypeInfo|0x402B2B"
        ],
        "LoD/1.08": [
          "LocaleMapStringWithConversion|0x4028DC",
          "GetCPInfo|0xF",
          "GetCharacterTypeInfo|0x402B2B"
        ],
        "LoD/1.09": [
          "GetCharacterTypeInfo|0x402B2B",
          "GetCPInfo|0xF",
          "LocaleMapStringWithConversion|0x4028DC"
        ],
        "LoD/1.09b": [
          "GetCPInfo|0xF",
          "LocaleMapStringWithConversion|0x4028DC",
          "GetCharacterTypeInfo|0x402B2B"
        ],
        "LoD/1.09d": [
          "LocaleMapStringWithConversion|0x4028DC",
          "GetCPInfo|0xF",
          "GetCharacterTypeInfo|0x402B2B"
        ],
        "LoD/1.10": [
          "GetCPInfo|0xF",
          "LocaleMapStringWithConversion|0x4028DC",
          "GetCharacterTypeInfo|0x402B2B"
        ],
        "LoD/1.11": [
          "GetCharacterTypeInfo|0x402B2B",
          "LocaleMapStringWithConversion|0x4028DC",
          "GetCPInfo|0xF"
        ],
        "LoD/1.11b": [
          "GetCPInfo|0xF",
          "LocaleMapStringWithConversion|0x4028DC",
          "GetCharacterTypeInfo|0x402B2B"
        ],
        "LoD/1.12a": [
          "GetCharacterTypeInfo|0x402B2B",
          "GetCPInfo|0xF",
          "LocaleMapStringWithConversion|0x4028DC"
        ],
        "LoD/1.13c": [
          "GetCPInfo|0xF",
          "GetCharacterTypeInfo|0x402B2B",
          "LocaleMapStringWithConversion|0x4028DC"
        ],
        "LoD/1.13d": [
          "LocaleMapStringWithConversion|0x4028DC",
          "GetCPInfo|0xF",
          "GetCharacterTypeInfo|0x402B2B"
        ],
        "LoD/1.14a": [
          "GetCPInfo|0xF",
          "LocaleMapStringWithConversion|0x4028DC",
          "GetCharacterTypeInfo|0x402B2B"
        ],
        "LoD/1.14b": [
          "GetCharacterTypeInfo|0x402B2B",
          "LocaleMapStringWithConversion|0x4028DC",
          "GetCPInfo|0xF"
        ],
        "LoD/1.14c": [
          "LocaleMapStringWithConversion|0x4028DC",
          "GetCharacterTypeInfo|0x402B2B",
          "GetCPInfo|0xF"
        ],
        "LoD/1.14d": [
          "GetCPInfo|0xF",
          "LocaleMapStringWithConversion|0x4028DC",
          "GetCharacterTypeInfo|0x402B2B"
        ]
      },
      "callers": {
        "LoD/1.07": [
          "InitializeCodePageLocale|0x401622"
        ],
        "LoD/1.08": [
          "InitializeCodePageLocale|0x401622"
        ],
        "LoD/1.09": [
          "InitializeCodePageLocale|0x401622"
        ],
        "LoD/1.09b": [
          "InitializeCodePageLocale|0x401622"
        ],
        "LoD/1.09d": [
          "InitializeCodePageLocale|0x401622"
        ],
        "LoD/1.10": [
          "InitializeCodePageLocale|0x401622"
        ],
        "LoD/1.11": [
          "InitializeCodePageLocale|0x401622"
        ],
        "LoD/1.11b": [
          "InitializeCodePageLocale|0x401622"
        ],
        "LoD/1.12a": [
          "InitializeCodePageLocale|0x401622"
        ],
        "LoD/1.13c": [
          "InitializeCodePageLocale|0x401622"
        ],
        "LoD/1.13d": [
          "InitializeCodePageLocale|0x401622"
        ],
        "LoD/1.14a": [
          "InitializeCodePageLocale|0x401622"
        ],
        "LoD/1.14b": [
          "InitializeCodePageLocale|0x401622"
        ],
        "LoD/1.14c": [
          "InitializeCodePageLocale|0x401622"
        ],
        "LoD/1.14d": [
          "InitializeCodePageLocale|0x401622"
        ]
      },
      "instruction_counts": {
        "LoD/1.07": 124,
        "LoD/1.08": 124,
        "LoD/1.09": 124,
        "LoD/1.09b": 124,
        "LoD/1.09d": 124,
        "LoD/1.10": 124,
        "LoD/1.11": 124,
        "LoD/1.11b": 124,
        "LoD/1.12a": 124,
        "LoD/1.13c": 124,
        "LoD/1.13d": 124,
        "LoD/1.14a": 124,
        "LoD/1.14b": 124,
        "LoD/1.14c": 124,
        "LoD/1.14d": 124
      },
      "stack_frame_sizes": {
        "LoD/1.07": 1308,
        "LoD/1.08": 1308,
        "LoD/1.09": 1308,
        "LoD/1.09b": 1308,
        "LoD/1.09d": 1308,
        "LoD/1.10": 1308,
        "LoD/1.11": 1308,
        "LoD/1.11b": 1308,
        "LoD/1.12a": 1308,
        "LoD/1.13c": 1308,
        "LoD/1.13d": 1308,
        "LoD/1.14a": 1308,
        "LoD/1.14b": 1308,
        "LoD/1.14c": 1308,
        "LoD/1.14d": 1308
      },
      "basic_block_counts": {
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
        "LoD/1.13d": 29,
        "LoD/1.14a": 29,
        "LoD/1.14b": 29,
        "LoD/1.14c": 29,
        "LoD/1.14d": 29
      },
      "loop_counts": {
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
        "LoD/1.13d": 6,
        "LoD/1.14a": 6,
        "LoD/1.14b": 6,
        "LoD/1.14c": 6,
        "LoD/1.14d": 6
      },
      "mnemonic_hashes": {
        "LoD/1.07": "63906d1f35f7842042066a6643d2050c",
        "LoD/1.08": "63906d1f35f7842042066a6643d2050c",
        "LoD/1.09": "63906d1f35f7842042066a6643d2050c",
        "LoD/1.09b": "63906d1f35f7842042066a6643d2050c",
        "LoD/1.09d": "63906d1f35f7842042066a6643d2050c",
        "LoD/1.10": "63906d1f35f7842042066a6643d2050c",
        "LoD/1.11": "63906d1f35f7842042066a6643d2050c",
        "LoD/1.11b": "63906d1f35f7842042066a6643d2050c",
        "LoD/1.12a": "63906d1f35f7842042066a6643d2050c",
        "LoD/1.13c": "63906d1f35f7842042066a6643d2050c",
        "LoD/1.13d": "63906d1f35f7842042066a6643d2050c",
        "LoD/1.14a": "63906d1f35f7842042066a6643d2050c",
        "LoD/1.14b": "63906d1f35f7842042066a6643d2050c",
        "LoD/1.14c": "63906d1f35f7842042066a6643d2050c",
        "LoD/1.14d": "63906d1f35f7842042066a6643d2050c"
      },
      "constants": {
        "LoD/1.07": [
          256,
          512,
          1300,
          4220864,
          4221121
        ],
        "LoD/1.08": [
          256,
          512,
          1300,
          4220864,
          4221121
        ],
        "LoD/1.09": [
          256,
          512,
          1300,
          4220864,
          4221121
        ],
        "LoD/1.09b": [
          256,
          512,
          1300,
          4220864,
          4221121
        ],
        "LoD/1.09d": [
          256,
          512,
          1300,
          4220864,
          4221121
        ],
        "LoD/1.10": [
          256,
          512,
          1300,
          4220864,
          4221121
        ],
        "LoD/1.11": [
          256,
          512,
          1300,
          4220864,
          4221121
        ],
        "LoD/1.11b": [
          256,
          512,
          1300,
          4220864,
          4221121
        ],
        "LoD/1.12a": [
          256,
          512,
          1300,
          4220864,
          4221121
        ],
        "LoD/1.13c": [
          256,
          512,
          1300,
          4220864,
          4221121
        ],
        "LoD/1.13d": [
          256,
          512,
          1300,
          4220864,
          4221121
        ],
        "LoD/1.14a": [
          256,
          512,
          1300,
          4220864,
          4221121
        ],
        "LoD/1.14b": [
          256,
          512,
          1300,
          4220864,
          4221121
        ],
        "LoD/1.14c": [
          256,
          512,
          1300,
          4220864,
          4221121
        ],
        "LoD/1.14d": [
          256,
          512,
          1300,
          4220864,
          4221121
        ]
      },
      "globals": {
        "LoD/1.07": [
          "0xFFFFFFFFFFBFFFE8|",
          "0x6798|g_dwCurrentCodePage",
          "0x5038|PTR_GetCPInfo_00405038",
          "0xFFFFFFFFFFBFFEE9|",
          "0xFFFFFFFFFFBFFFEE|",
          "0xFFFFFFFFFFBFFEE8|",
          "0xFFFFFFFFFFBFFFEF|",
          "0xFFFFFFFFFFBFFFF0|",
          "0xFFFFFFFFFFBFFAE8|",
          "0x69C4|g_dwCodePageProperties"
        ],
        "LoD/1.08": [
          "0xFFFFFFFFFFBFFFE8|",
          "0x6798|g_dwCurrentCodePage",
          "0x5038|PTR_GetCPInfo_00405038",
          "0xFFFFFFFFFFBFFEE9|",
          "0xFFFFFFFFFFBFFFEE|",
          "0xFFFFFFFFFFBFFEE8|",
          "0xFFFFFFFFFFBFFFEF|",
          "0xFFFFFFFFFFBFFFF0|",
          "0xFFFFFFFFFFBFFAE8|",
          "0x69C4|g_dwCodePageProperties"
        ],
        "LoD/1.09": [
          "0xFFFFFFFFFFBFFFE8|",
          "0x6798|g_dwCurrentCodePage",
          "0x5038|PTR_GetCPInfo_00405038",
          "0xFFFFFFFFFFBFFEE9|",
          "0xFFFFFFFFFFBFFFEE|",
          "0xFFFFFFFFFFBFFEE8|",
          "0xFFFFFFFFFFBFFFEF|",
          "0xFFFFFFFFFFBFFFF0|",
          "0xFFFFFFFFFFBFFAE8|",
          "0x69C4|g_dwCodePageProperties"
        ],
        "LoD/1.09b": [
          "0xFFFFFFFFFFBFFFE8|",
          "0x6798|g_dwCurrentCodePage",
          "0x5038|PTR_GetCPInfo_00405038",
          "0xFFFFFFFFFFBFFEE9|",
          "0xFFFFFFFFFFBFFFEE|",
          "0xFFFFFFFFFFBFFEE8|",
          "0xFFFFFFFFFFBFFFEF|",
          "0xFFFFFFFFFFBFFFF0|",
          "0xFFFFFFFFFFBFFAE8|",
          "0x69C4|g_dwCodePageProperties"
        ],
        "LoD/1.09d": [
          "0xFFFFFFFFFFBFFFE8|",
          "0x6798|g_dwCurrentCodePage",
          "0x5038|PTR_GetCPInfo_00405038",
          "0xFFFFFFFFFFBFFEE9|",
          "0xFFFFFFFFFFBFFFEE|",
          "0xFFFFFFFFFFBFFEE8|",
          "0xFFFFFFFFFFBFFFEF|",
          "0xFFFFFFFFFFBFFFF0|",
          "0xFFFFFFFFFFBFFAE8|",
          "0x69C4|g_dwCodePageProperties"
        ],
        "LoD/1.10": [
          "0xFFFFFFFFFFBFFFE8|",
          "0x6798|g_dwCurrentCodePage",
          "0x5038|PTR_GetCPInfo_00405038",
          "0xFFFFFFFFFFBFFEE9|",
          "0xFFFFFFFFFFBFFFEE|",
          "0xFFFFFFFFFFBFFEE8|",
          "0xFFFFFFFFFFBFFFEF|",
          "0xFFFFFFFFFFBFFFF0|",
          "0xFFFFFFFFFFBFFAE8|",
          "0x69C4|g_dwCodePageProperties"
        ],
        "LoD/1.11": [
          "0xFFFFFFFFFFBFFFE8|",
          "0x6798|g_dwCurrentCodePage",
          "0x5038|PTR_GetCPInfo_00405038",
          "0xFFFFFFFFFFBFFEE9|",
          "0xFFFFFFFFFFBFFFEE|",
          "0xFFFFFFFFFFBFFEE8|",
          "0xFFFFFFFFFFBFFFEF|",
          "0xFFFFFFFFFFBFFFF0|",
          "0xFFFFFFFFFFBFFAE8|",
          "0x69C4|g_dwCodePageProperties"
        ],
        "LoD/1.11b": [
          "0xFFFFFFFFFFBFFFE8|",
          "0x6798|g_dwCurrentCodePage",
          "0x5038|PTR_GetCPInfo_00405038",
          "0xFFFFFFFFFFBFFEE9|",
          "0xFFFFFFFFFFBFFFEE|",
          "0xFFFFFFFFFFBFFEE8|",
          "0xFFFFFFFFFFBFFFEF|",
          "0xFFFFFFFFFFBFFFF0|",
          "0xFFFFFFFFFFBFFAE8|",
          "0x69C4|g_dwCodePageProperties"
        ],
        "LoD/1.12a": [
          "0xFFFFFFFFFFBFFFE8|",
          "0x6798|g_dwCurrentCodePage",
          "0x5038|PTR_GetCPInfo_00405038",
          "0xFFFFFFFFFFBFFEE9|",
          "0xFFFFFFFFFFBFFFEE|",
          "0xFFFFFFFFFFBFFEE8|",
          "0xFFFFFFFFFFBFFFEF|",
          "0xFFFFFFFFFFBFFFF0|",
          "0xFFFFFFFFFFBFFAE8|",
          "0x69C4|g_dwCodePageProperties"
        ],
        "LoD/1.13c": [
          "0xFFFFFFFFFFBFFFE8|",
          "0x6798|g_dwCurrentCodePage",
          "0x5038|PTR_GetCPInfo_00405038",
          "0xFFFFFFFFFFBFFEE9|",
          "0xFFFFFFFFFFBFFFEE|",
          "0xFFFFFFFFFFBFFEE8|",
          "0xFFFFFFFFFFBFFFEF|",
          "0xFFFFFFFFFFBFFFF0|",
          "0xFFFFFFFFFFBFFAE8|",
          "0x69C4|g_dwCodePageProperties"
        ],
        "LoD/1.13d": [
          "0xFFFFFFFFFFBFFFE8|",
          "0x6798|g_dwCurrentCodePage",
          "0x5038|PTR_GetCPInfo_00405038",
          "0xFFFFFFFFFFBFFEE9|",
          "0xFFFFFFFFFFBFFFEE|",
          "0xFFFFFFFFFFBFFEE8|",
          "0xFFFFFFFFFFBFFFEF|",
          "0xFFFFFFFFFFBFFFF0|",
          "0xFFFFFFFFFFBFFAE8|",
          "0x69C4|g_dwCodePageProperties"
        ],
        "LoD/1.14a": [
          "0xFFFFFFFFFFBFFFE8|",
          "0x6798|g_dwCurrentCodePage",
          "0x5038|PTR_GetCPInfo_00405038",
          "0xFFFFFFFFFFBFFEE9|",
          "0xFFFFFFFFFFBFFFEE|",
          "0xFFFFFFFFFFBFFEE8|",
          "0xFFFFFFFFFFBFFFEF|",
          "0xFFFFFFFFFFBFFFF0|",
          "0xFFFFFFFFFFBFFAE8|",
          "0x69C4|g_dwCodePageProperties"
        ],
        "LoD/1.14b": [
          "0xFFFFFFFFFFBFFFE8|",
          "0x6798|g_dwCurrentCodePage",
          "0x5038|PTR_GetCPInfo_00405038",
          "0xFFFFFFFFFFBFFEE9|",
          "0xFFFFFFFFFFBFFFEE|",
          "0xFFFFFFFFFFBFFEE8|",
          "0xFFFFFFFFFFBFFFEF|",
          "0xFFFFFFFFFFBFFFF0|",
          "0xFFFFFFFFFFBFFAE8|",
          "0x69C4|g_dwCodePageProperties"
        ],
        "LoD/1.14c": [
          "0xFFFFFFFFFFBFFFE8|",
          "0x6798|g_dwCurrentCodePage",
          "0x5038|PTR_GetCPInfo_00405038",
          "0xFFFFFFFFFFBFFEE9|",
          "0xFFFFFFFFFFBFFFEE|",
          "0xFFFFFFFFFFBFFEE8|",
          "0xFFFFFFFFFFBFFFEF|",
          "0xFFFFFFFFFFBFFFF0|",
          "0xFFFFFFFFFFBFFAE8|",
          "0x69C4|g_dwCodePageProperties"
        ],
        "LoD/1.14d": [
          "0xFFFFFFFFFFBFFFE8|",
          "0x6798|g_dwCurrentCodePage",
          "0x5038|PTR_GetCPInfo_00405038",
          "0xFFFFFFFFFFBFFEE9|",
          "0xFFFFFFFFFFBFFFEE|",
          "0xFFFFFFFFFFBFFEE8|",
          "0xFFFFFFFFFFBFFFEF|",
          "0xFFFFFFFFFFBFFFF0|",
          "0xFFFFFFFFFFBFFAE8|",
          "0x69C4|g_dwCodePageProperties"
        ]
      }
    },
    "diablo ii.exe_InitializeCodePageOnce": {
      "addresses": {
        "LoD/1.07": "0x004019E6",
        "LoD/1.08": "0x004019E6",
        "LoD/1.09": "0x004019E6",
        "LoD/1.09b": "0x004019E6",
        "LoD/1.09d": "0x004019E6",
        "LoD/1.10": "0x004019E6",
        "LoD/1.11": "0x004019E6",
        "LoD/1.11b": "0x004019E6",
        "LoD/1.12a": "0x004019E6",
        "LoD/1.13c": "0x004019E6",
        "LoD/1.13d": "0x004019E6",
        "LoD/1.14a": "0x004019E6",
        "LoD/1.14b": "0x004019E6",
        "LoD/1.14c": "0x004019E6",
        "LoD/1.14d": "0x004019E6"
      },
      "rvas": {
        "LoD/1.07": "0x19E6",
        "LoD/1.08": "0x19E6",
        "LoD/1.09": "0x19E6",
        "LoD/1.09b": "0x19E6",
        "LoD/1.09d": "0x19E6",
        "LoD/1.10": "0x19E6",
        "LoD/1.11": "0x19E6",
        "LoD/1.11b": "0x19E6",
        "LoD/1.12a": "0x19E6",
        "LoD/1.13c": "0x19E6",
        "LoD/1.13d": "0x19E6",
        "LoD/1.14a": "0x19E6",
        "LoD/1.14b": "0x19E6",
        "LoD/1.14c": "0x19E6",
        "LoD/1.14d": "0x19E6"
      },
      "sizes": {
        "LoD/1.07": 28,
        "LoD/1.08": 28,
        "LoD/1.09": 28,
        "LoD/1.09b": 28,
        "LoD/1.09d": 28,
        "LoD/1.10": 28,
        "LoD/1.11": 28,
        "LoD/1.11b": 28,
        "LoD/1.12a": 28,
        "LoD/1.13c": 28,
        "LoD/1.13d": 28,
        "LoD/1.14a": 28,
        "LoD/1.14b": 28,
        "LoD/1.14c": 28,
        "LoD/1.14d": 28
      },
      "name": "InitializeCodePageOnce",
      "signature": "void InitializeCodePageOnce(void)",
      "calling_convention": "__stdcall",
      "return_type": "void",
      "comment": "Ensures code page locale initialization occurs only once during program execution.\n\nAlgorithm:\n1. Check initialization flag g_fCodePageInitialized for zero (uninitialized state)\n2. If uninitialized, call InitializeCodePageLocale(-3) to set up system locale\n3. Set initialization flag g_fCodePageInitialized to true (1) to prevent re-initialization\n4. Return immediately if already initialized (early exit optimization)\n\nParameters:\nNone\n\nReturns:\nvoid - No return value, initialization is fire-and-forget\n\nSpecial Cases:\n- Thread-safe one-time initialization using simple boolean flag\n- Early return optimization prevents redundant initialization calls\n- Flag remains set for program lifetime once initialization completes\n\nMagic Numbers Reference:\n0xfffffffd (-3) - Special code page identifier passed to InitializeCodePageLocale\n                  Likely represents CP_THREAD_ACP (thread's current ANSI code page)\n\nError Handling:\n- No explicit error handling; relies on InitializeCodePageLocale for error management\n- Boolean flag ensures initialization attempts happen only once regardless of success/failure",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:750c71b47c1aaa7e04385ca0c70f7831",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "750c71b47c1aaa7e04385ca0c70f7831",
        "CFG": "716bb67a3d1eac006a8b7d10a21c5b78",
        "PRO": "a50a456766e4f98144ab970dbc0ce16b",
        "CAL": null,
        "CON": null,
        "APS": null
      },
      "callees": {
        "LoD/1.07": [
          "InitializeCodePageLocale|0x401622"
        ],
        "LoD/1.08": [
          "InitializeCodePageLocale|0x401622"
        ],
        "LoD/1.09": [
          "InitializeCodePageLocale|0x401622"
        ],
        "LoD/1.09b": [
          "InitializeCodePageLocale|0x401622"
        ],
        "LoD/1.09d": [
          "InitializeCodePageLocale|0x401622"
        ],
        "LoD/1.10": [
          "InitializeCodePageLocale|0x401622"
        ],
        "LoD/1.11": [
          "InitializeCodePageLocale|0x401622"
        ],
        "LoD/1.11b": [
          "InitializeCodePageLocale|0x401622"
        ],
        "LoD/1.12a": [
          "InitializeCodePageLocale|0x401622"
        ],
        "LoD/1.13c": [
          "InitializeCodePageLocale|0x401622"
        ],
        "LoD/1.13d": [
          "InitializeCodePageLocale|0x401622"
        ],
        "LoD/1.14a": [
          "InitializeCodePageLocale|0x401622"
        ],
        "LoD/1.14b": [
          "InitializeCodePageLocale|0x401622"
        ],
        "LoD/1.14c": [
          "InitializeCodePageLocale|0x401622"
        ],
        "LoD/1.14d": [
          "InitializeCodePageLocale|0x401622"
        ]
      },
      "callers": {
        "LoD/1.07": [
          "FUN_00401f06|0x401F06",
          "InitializeModuleData|0x402017",
          "InitializeEnvironmentVariables|0x401F5E"
        ],
        "LoD/1.08": [
          "InitializeEnvironmentVariables|0x401F5E",
          "InitializeModuleData|0x402017",
          "FUN_00401f06|0x401F06"
        ],
        "LoD/1.09": [
          "InitializeEnvironmentVariables|0x401F5E",
          "FUN_00401f06|0x401F06",
          "InitializeModuleData|0x402017"
        ],
        "LoD/1.09b": [
          "FUN_00401f06|0x401F06",
          "InitializeEnvironmentVariables|0x401F5E",
          "InitializeModuleData|0x402017"
        ],
        "LoD/1.09d": [
          "InitializeEnvironmentVariables|0x401F5E",
          "InitializeModuleData|0x402017",
          "FUN_00401f06|0x401F06"
        ],
        "LoD/1.10": [
          "InitializeEnvironmentVariables|0x401F5E",
          "InitializeModuleData|0x402017",
          "FUN_00401f06|0x401F06"
        ],
        "LoD/1.11": [
          "InitializeModuleData|0x402017",
          "FUN_00401f06|0x401F06",
          "InitializeEnvironmentVariables|0x401F5E"
        ],
        "LoD/1.11b": [
          "FUN_00401f06|0x401F06",
          "InitializeModuleData|0x402017",
          "InitializeEnvironmentVariables|0x401F5E"
        ],
        "LoD/1.12a": [
          "InitializeEnvironmentVariables|0x401F5E",
          "InitializeModuleData|0x402017",
          "FUN_00401f06|0x401F06"
        ],
        "LoD/1.13c": [
          "FUN_00401f06|0x401F06",
          "InitializeModuleData|0x402017",
          "InitializeEnvironmentVariables|0x401F5E"
        ],
        "LoD/1.13d": [
          "InitializeModuleData|0x402017",
          "InitializeEnvironmentVariables|0x401F5E",
          "FUN_00401f06|0x401F06"
        ],
        "LoD/1.14a": [
          "FUN_00401f06|0x401F06",
          "InitializeEnvironmentVariables|0x401F5E",
          "InitializeModuleData|0x402017"
        ],
        "LoD/1.14b": [
          "InitializeModuleData|0x402017",
          "InitializeEnvironmentVariables|0x401F5E",
          "FUN_00401f06|0x401F06"
        ],
        "LoD/1.14c": [
          "InitializeModuleData|0x402017",
          "FUN_00401f06|0x401F06",
          "InitializeEnvironmentVariables|0x401F5E"
        ],
        "LoD/1.14d": [
          "InitializeModuleData|0x402017",
          "FUN_00401f06|0x401F06",
          "InitializeEnvironmentVariables|0x401F5E"
        ]
      },
      "instruction_counts": {
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
        "LoD/1.13d": 7,
        "LoD/1.14a": 7,
        "LoD/1.14b": 7,
        "LoD/1.14c": 7,
        "LoD/1.14d": 7
      },
      "stack_frame_sizes": {
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
        "LoD/1.13d": 4,
        "LoD/1.14a": 4,
        "LoD/1.14b": 4,
        "LoD/1.14c": 4,
        "LoD/1.14d": 4
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
        "LoD/1.13d": 3,
        "LoD/1.14a": 3,
        "LoD/1.14b": 3,
        "LoD/1.14c": 3,
        "LoD/1.14d": 3
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
        "LoD/1.13d": 0,
        "LoD/1.14a": 0,
        "LoD/1.14b": 0,
        "LoD/1.14c": 0,
        "LoD/1.14d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "750c71b47c1aaa7e04385ca0c70f7831",
        "LoD/1.08": "750c71b47c1aaa7e04385ca0c70f7831",
        "LoD/1.09": "750c71b47c1aaa7e04385ca0c70f7831",
        "LoD/1.09b": "750c71b47c1aaa7e04385ca0c70f7831",
        "LoD/1.09d": "750c71b47c1aaa7e04385ca0c70f7831",
        "LoD/1.10": "750c71b47c1aaa7e04385ca0c70f7831",
        "LoD/1.11": "750c71b47c1aaa7e04385ca0c70f7831",
        "LoD/1.11b": "750c71b47c1aaa7e04385ca0c70f7831",
        "LoD/1.12a": "750c71b47c1aaa7e04385ca0c70f7831",
        "LoD/1.13c": "750c71b47c1aaa7e04385ca0c70f7831",
        "LoD/1.13d": "750c71b47c1aaa7e04385ca0c70f7831",
        "LoD/1.14a": "750c71b47c1aaa7e04385ca0c70f7831",
        "LoD/1.14b": "750c71b47c1aaa7e04385ca0c70f7831",
        "LoD/1.14c": "750c71b47c1aaa7e04385ca0c70f7831",
        "LoD/1.14d": "750c71b47c1aaa7e04385ca0c70f7831"
      },
      "globals": {
        "LoD/1.07": [
          "0x6788|g_fCodePageInitialized"
        ],
        "LoD/1.08": [
          "0x6788|g_fCodePageInitialized"
        ],
        "LoD/1.09": [
          "0x6788|g_fCodePageInitialized"
        ],
        "LoD/1.09b": [
          "0x6788|g_fCodePageInitialized"
        ],
        "LoD/1.09d": [
          "0x6788|g_fCodePageInitialized"
        ],
        "LoD/1.10": [
          "0x6788|g_fCodePageInitialized"
        ],
        "LoD/1.11": [
          "0x6788|g_fCodePageInitialized"
        ],
        "LoD/1.11b": [
          "0x6788|g_fCodePageInitialized"
        ],
        "LoD/1.12a": [
          "0x6788|g_fCodePageInitialized"
        ],
        "LoD/1.13c": [
          "0x6788|g_fCodePageInitialized"
        ],
        "LoD/1.13d": [
          "0x6788|g_fCodePageInitialized"
        ],
        "LoD/1.14a": [
          "0x6788|g_fCodePageInitialized"
        ],
        "LoD/1.14b": [
          "0x6788|g_fCodePageInitialized"
        ],
        "LoD/1.14c": [
          "0x6788|g_fCodePageInitialized"
        ],
        "LoD/1.14d": [
          "0x6788|g_fCodePageInitialized"
        ]
      }
    },
    "diablo ii.exe_MNE_0fd63ca17819": {
      "addresses": {
        "LoD/1.07": "0x00401A02",
        "LoD/1.08": "0x00401A02",
        "LoD/1.09": "0x00401A02",
        "LoD/1.09b": "0x00401A02",
        "LoD/1.09d": "0x00401A02",
        "LoD/1.10": "0x00401A02",
        "LoD/1.11": "0x00401A02",
        "LoD/1.11b": "0x00401A02",
        "LoD/1.12a": "0x00401A02",
        "LoD/1.13c": "0x00401A02",
        "LoD/1.13d": "0x00401A02",
        "LoD/1.14a": "0x00401A02",
        "LoD/1.14b": "0x00401A02",
        "LoD/1.14c": "0x00401A02",
        "LoD/1.14d": "0x00401A02"
      },
      "rvas": {
        "LoD/1.07": "0x1A02",
        "LoD/1.08": "0x1A02",
        "LoD/1.09": "0x1A02",
        "LoD/1.09b": "0x1A02",
        "LoD/1.09d": "0x1A02",
        "LoD/1.10": "0x1A02",
        "LoD/1.11": "0x1A02",
        "LoD/1.11b": "0x1A02",
        "LoD/1.12a": "0x1A02",
        "LoD/1.13c": "0x1A02",
        "LoD/1.13d": "0x1A02",
        "LoD/1.14a": "0x1A02",
        "LoD/1.14b": "0x1A02",
        "LoD/1.14c": "0x1A02",
        "LoD/1.14d": "0x1A02"
      },
      "sizes": {
        "LoD/1.07": 56,
        "LoD/1.08": 56,
        "LoD/1.09": 56,
        "LoD/1.09b": 56,
        "LoD/1.09d": 56,
        "LoD/1.10": 56,
        "LoD/1.11": 56,
        "LoD/1.11b": 56,
        "LoD/1.12a": 56,
        "LoD/1.13c": 56,
        "LoD/1.13d": 56,
        "LoD/1.14a": 56,
        "LoD/1.14b": 56,
        "LoD/1.14c": 56,
        "LoD/1.14d": 56
      },
      "return_type": "int",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:0fd63ca178190d07551a06ea40081aaa",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "0fd63ca178190d07551a06ea40081aaa",
        "CFG": "c5adb86ae14c9188b0ae60db194a761c",
        "PRO": "2f281cb40124fe42bb61dcaf12c71960",
        "CAL": null,
        "CON": null,
        "APS": null
      },
      "display_name": "FUN_00401a02",
      "callees": {
        "LoD/1.07": [
          "FUN_00402c74|0x402C74"
        ],
        "LoD/1.08": [
          "FUN_00402c74|0x402C74"
        ],
        "LoD/1.09": [
          "FUN_00402c74|0x402C74"
        ],
        "LoD/1.09b": [
          "FUN_00402c74|0x402C74"
        ],
        "LoD/1.09d": [
          "FUN_00402c74|0x402C74"
        ],
        "LoD/1.10": [
          "FUN_00402c74|0x402C74"
        ],
        "LoD/1.11": [
          "FUN_00402c74|0x402C74"
        ],
        "LoD/1.11b": [
          "FUN_00402c74|0x402C74"
        ],
        "LoD/1.12a": [
          "FUN_00402c74|0x402C74"
        ],
        "LoD/1.13c": [
          "FUN_00402c74|0x402C74"
        ],
        "LoD/1.13d": [
          "FUN_00402c74|0x402C74"
        ],
        "LoD/1.14a": [
          "FUN_00402c74|0x402C74"
        ],
        "LoD/1.14b": [
          "FUN_00402c74|0x402C74"
        ],
        "LoD/1.14c": [
          "FUN_00402c74|0x402C74"
        ],
        "LoD/1.14d": [
          "FUN_00402c74|0x402C74"
        ]
      },
      "callers": {
        "LoD/1.07": [
          "FUN_004013b0|0x4013B0"
        ],
        "LoD/1.08": [
          "FUN_004013b0|0x4013B0"
        ],
        "LoD/1.09": [
          "FUN_004013b0|0x4013B0"
        ],
        "LoD/1.09b": [
          "FUN_004013b0|0x4013B0"
        ],
        "LoD/1.09d": [
          "FUN_004013b0|0x4013B0"
        ],
        "LoD/1.10": [
          "FUN_004013b0|0x4013B0"
        ],
        "LoD/1.11": [
          "FUN_004013b0|0x4013B0"
        ],
        "LoD/1.11b": [
          "FUN_004013b0|0x4013B0"
        ],
        "LoD/1.12a": [
          "FUN_004013b0|0x4013B0"
        ],
        "LoD/1.13c": [
          "FUN_004013b0|0x4013B0"
        ],
        "LoD/1.13d": [
          "FUN_004013b0|0x4013B0"
        ],
        "LoD/1.14a": [
          "FUN_004013b0|0x4013B0"
        ],
        "LoD/1.14b": [
          "FUN_004013b0|0x4013B0"
        ],
        "LoD/1.14c": [
          "FUN_004013b0|0x4013B0"
        ],
        "LoD/1.14d": [
          "FUN_004013b0|0x4013B0"
        ]
      },
      "instruction_counts": {
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
        "LoD/1.13d": 25,
        "LoD/1.14a": 25,
        "LoD/1.14b": 25,
        "LoD/1.14c": 25,
        "LoD/1.14d": 25
      },
      "stack_frame_sizes": {
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
        "LoD/1.13d": 12,
        "LoD/1.14a": 12,
        "LoD/1.14b": 12,
        "LoD/1.14c": 12,
        "LoD/1.14d": 12
      },
      "basic_block_counts": {
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
        "LoD/1.13d": 8,
        "LoD/1.14a": 8,
        "LoD/1.14b": 8,
        "LoD/1.14c": 8,
        "LoD/1.14d": 8
      },
      "loop_counts": {
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
        "LoD/1.13d": 1,
        "LoD/1.14a": 1,
        "LoD/1.14b": 1,
        "LoD/1.14c": 1,
        "LoD/1.14d": 1
      },
      "mnemonic_hashes": {
        "LoD/1.07": "0fd63ca178190d07551a06ea40081aaa",
        "LoD/1.08": "0fd63ca178190d07551a06ea40081aaa",
        "LoD/1.09": "0fd63ca178190d07551a06ea40081aaa",
        "LoD/1.09b": "0fd63ca178190d07551a06ea40081aaa",
        "LoD/1.09d": "0fd63ca178190d07551a06ea40081aaa",
        "LoD/1.10": "0fd63ca178190d07551a06ea40081aaa",
        "LoD/1.11": "0fd63ca178190d07551a06ea40081aaa",
        "LoD/1.11b": "0fd63ca178190d07551a06ea40081aaa",
        "LoD/1.12a": "0fd63ca178190d07551a06ea40081aaa",
        "LoD/1.13c": "0fd63ca178190d07551a06ea40081aaa",
        "LoD/1.13d": "0fd63ca178190d07551a06ea40081aaa",
        "LoD/1.14a": "0fd63ca178190d07551a06ea40081aaa",
        "LoD/1.14b": "0fd63ca178190d07551a06ea40081aaa",
        "LoD/1.14c": "0fd63ca178190d07551a06ea40081aaa",
        "LoD/1.14d": "0fd63ca178190d07551a06ea40081aaa"
      },
      "globals": {
        "LoD/1.07": [
          "0x67AC|g_fIsMultiByteCodePage",
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ],
        "LoD/1.08": [
          "0x67AC|g_fIsMultiByteCodePage",
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ],
        "LoD/1.09": [
          "0x67AC|g_fIsMultiByteCodePage",
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ],
        "LoD/1.09b": [
          "0x67AC|g_fIsMultiByteCodePage",
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ],
        "LoD/1.09d": [
          "0x67AC|g_fIsMultiByteCodePage",
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ],
        "LoD/1.10": [
          "0x67AC|g_fIsMultiByteCodePage",
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ],
        "LoD/1.11": [
          "0x67AC|g_fIsMultiByteCodePage",
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ],
        "LoD/1.11b": [
          "0x67AC|g_fIsMultiByteCodePage",
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ],
        "LoD/1.12a": [
          "0x67AC|g_fIsMultiByteCodePage",
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ],
        "LoD/1.13c": [
          "0x67AC|g_fIsMultiByteCodePage",
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ],
        "LoD/1.13d": [
          "0x67AC|g_fIsMultiByteCodePage",
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ],
        "LoD/1.14a": [
          "0x67AC|g_fIsMultiByteCodePage",
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ],
        "LoD/1.14b": [
          "0x67AC|g_fIsMultiByteCodePage",
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ],
        "LoD/1.14c": [
          "0x67AC|g_fIsMultiByteCodePage",
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ],
        "LoD/1.14d": [
          "0x67AC|g_fIsMultiByteCodePage",
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ]
      }
    },
    "diablo ii.exe__strncat": {
      "addresses": {
        "LoD/1.07": "0x00401A40",
        "LoD/1.08": "0x00401A40",
        "LoD/1.09": "0x00401A40",
        "LoD/1.09b": "0x00401A40",
        "LoD/1.09d": "0x00401A40",
        "LoD/1.10": "0x00401A40",
        "LoD/1.11": "0x00401A40",
        "LoD/1.11b": "0x00401A40",
        "LoD/1.12a": "0x00401A40",
        "LoD/1.13c": "0x00401A40",
        "LoD/1.13d": "0x00401A40",
        "LoD/1.14a": "0x00401A40",
        "LoD/1.14b": "0x00401A40",
        "LoD/1.14c": "0x00401A40",
        "LoD/1.14d": "0x00401A40"
      },
      "rvas": {
        "LoD/1.07": "0x1A40",
        "LoD/1.08": "0x1A40",
        "LoD/1.09": "0x1A40",
        "LoD/1.09b": "0x1A40",
        "LoD/1.09d": "0x1A40",
        "LoD/1.10": "0x1A40",
        "LoD/1.11": "0x1A40",
        "LoD/1.11b": "0x1A40",
        "LoD/1.12a": "0x1A40",
        "LoD/1.13c": "0x1A40",
        "LoD/1.13d": "0x1A40",
        "LoD/1.14a": "0x1A40",
        "LoD/1.14b": "0x1A40",
        "LoD/1.14c": "0x1A40",
        "LoD/1.14d": "0x1A40"
      },
      "sizes": {
        "LoD/1.07": 291,
        "LoD/1.08": 291,
        "LoD/1.09": 291,
        "LoD/1.09b": 291,
        "LoD/1.09d": 291,
        "LoD/1.10": 291,
        "LoD/1.11": 291,
        "LoD/1.11b": 291,
        "LoD/1.12a": 291,
        "LoD/1.13c": 291,
        "LoD/1.13d": 291,
        "LoD/1.14a": 291,
        "LoD/1.14b": 291,
        "LoD/1.14c": 291,
        "LoD/1.14d": 291
      },
      "name": "_strncat",
      "signature": "char * _strncat(char * _Dest, char * _Source, size_t _Count)",
      "calling_convention": "__cdecl",
      "return_type": "char *",
      "comment": "Library Function - Single Match\n _strncat\n\nLibraries: Visual Studio 1998 Debug, Visual Studio 1998 Release",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:82b4813eddefea8f8cb9d2712dc5bde7",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "82b4813eddefea8f8cb9d2712dc5bde7",
        "CFG": "96e6811c918363bd3b5c342452247f77",
        "PRO": "5319aa74b13d859919d68c27e04215a3",
        "CAL": null,
        "CON": null,
        "APS": null
      },
      "callers": {
        "LoD/1.07": [
          "FUN_004013b0|0x4013B0"
        ],
        "LoD/1.08": [
          "FUN_004013b0|0x4013B0"
        ],
        "LoD/1.09": [
          "FUN_004013b0|0x4013B0"
        ],
        "LoD/1.09b": [
          "FUN_004013b0|0x4013B0"
        ],
        "LoD/1.09d": [
          "FUN_004013b0|0x4013B0"
        ],
        "LoD/1.10": [
          "FUN_004013b0|0x4013B0"
        ],
        "LoD/1.11": [
          "FUN_004013b0|0x4013B0"
        ],
        "LoD/1.11b": [
          "FUN_004013b0|0x4013B0"
        ],
        "LoD/1.12a": [
          "FUN_004013b0|0x4013B0"
        ],
        "LoD/1.13c": [
          "FUN_004013b0|0x4013B0"
        ],
        "LoD/1.13d": [
          "FUN_004013b0|0x4013B0"
        ],
        "LoD/1.14a": [
          "FUN_004013b0|0x4013B0"
        ],
        "LoD/1.14b": [
          "FUN_004013b0|0x4013B0"
        ],
        "LoD/1.14c": [
          "FUN_004013b0|0x4013B0"
        ],
        "LoD/1.14d": [
          "FUN_004013b0|0x4013B0"
        ]
      },
      "instruction_counts": {
        "LoD/1.07": 123,
        "LoD/1.08": 123,
        "LoD/1.09": 123,
        "LoD/1.09b": 123,
        "LoD/1.09d": 123,
        "LoD/1.10": 123,
        "LoD/1.11": 123,
        "LoD/1.11b": 123,
        "LoD/1.12a": 123,
        "LoD/1.13c": 123,
        "LoD/1.13d": 123,
        "LoD/1.14a": 123,
        "LoD/1.14b": 123,
        "LoD/1.14c": 123,
        "LoD/1.14d": 123
      },
      "stack_frame_sizes": {
        "LoD/1.07": 16,
        "LoD/1.08": 16,
        "LoD/1.09": 16,
        "LoD/1.09b": 16,
        "LoD/1.09d": 16,
        "LoD/1.10": 16,
        "LoD/1.11": 16,
        "LoD/1.11b": 16,
        "LoD/1.12a": 16,
        "LoD/1.13c": 16,
        "LoD/1.13d": 16,
        "LoD/1.14a": 16,
        "LoD/1.14b": 16,
        "LoD/1.14c": 16,
        "LoD/1.14d": 16
      },
      "basic_block_counts": {
        "LoD/1.07": 36,
        "LoD/1.08": 36,
        "LoD/1.09": 36,
        "LoD/1.09b": 36,
        "LoD/1.09d": 36,
        "LoD/1.10": 36,
        "LoD/1.11": 36,
        "LoD/1.11b": 36,
        "LoD/1.12a": 36,
        "LoD/1.13c": 36,
        "LoD/1.13d": 36,
        "LoD/1.14a": 36,
        "LoD/1.14b": 36,
        "LoD/1.14c": 36,
        "LoD/1.14d": 36
      },
      "loop_counts": {
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
        "LoD/1.13d": 9,
        "LoD/1.14a": 9,
        "LoD/1.14b": 9,
        "LoD/1.14c": 9,
        "LoD/1.14d": 9
      },
      "mnemonic_hashes": {
        "LoD/1.07": "82b4813eddefea8f8cb9d2712dc5bde7",
        "LoD/1.08": "82b4813eddefea8f8cb9d2712dc5bde7",
        "LoD/1.09": "82b4813eddefea8f8cb9d2712dc5bde7",
        "LoD/1.09b": "82b4813eddefea8f8cb9d2712dc5bde7",
        "LoD/1.09d": "82b4813eddefea8f8cb9d2712dc5bde7",
        "LoD/1.10": "82b4813eddefea8f8cb9d2712dc5bde7",
        "LoD/1.11": "82b4813eddefea8f8cb9d2712dc5bde7",
        "LoD/1.11b": "82b4813eddefea8f8cb9d2712dc5bde7",
        "LoD/1.12a": "82b4813eddefea8f8cb9d2712dc5bde7",
        "LoD/1.13c": "82b4813eddefea8f8cb9d2712dc5bde7",
        "LoD/1.13d": "82b4813eddefea8f8cb9d2712dc5bde7",
        "LoD/1.14a": "82b4813eddefea8f8cb9d2712dc5bde7",
        "LoD/1.14b": "82b4813eddefea8f8cb9d2712dc5bde7",
        "LoD/1.14c": "82b4813eddefea8f8cb9d2712dc5bde7",
        "LoD/1.14d": "82b4813eddefea8f8cb9d2712dc5bde7"
      },
      "constants": {
        "LoD/1.07": [
          16711680
        ],
        "LoD/1.08": [
          16711680
        ],
        "LoD/1.09": [
          16711680
        ],
        "LoD/1.09b": [
          16711680
        ],
        "LoD/1.09d": [
          16711680
        ],
        "LoD/1.10": [
          16711680
        ],
        "LoD/1.11": [
          16711680
        ],
        "LoD/1.11b": [
          16711680
        ],
        "LoD/1.12a": [
          16711680
        ],
        "LoD/1.13c": [
          16711680
        ],
        "LoD/1.13d": [
          16711680
        ],
        "LoD/1.14a": [
          16711680
        ],
        "LoD/1.14b": [
          16711680
        ],
        "LoD/1.14c": [
          16711680
        ],
        "LoD/1.14d": [
          16711680
        ]
      },
      "globals": {
        "LoD/1.07": [
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ],
        "LoD/1.08": [
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ],
        "LoD/1.09": [
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ],
        "LoD/1.09b": [
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ],
        "LoD/1.09d": [
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ],
        "LoD/1.10": [
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ],
        "LoD/1.11": [
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ],
        "LoD/1.11b": [
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ],
        "LoD/1.12a": [
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ],
        "LoD/1.13c": [
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ],
        "LoD/1.13d": [
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ],
        "LoD/1.14a": [
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ],
        "LoD/1.14b": [
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ],
        "LoD/1.14c": [
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ],
        "LoD/1.14d": [
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ]
      }
    },
    "diablo ii.exe_MNE_cfea3c92c099": {
      "addresses": {
        "LoD/1.07": "0x00401B63",
        "LoD/1.08": "0x00401B63",
        "LoD/1.09": "0x00401B63",
        "LoD/1.09b": "0x00401B63",
        "LoD/1.09d": "0x00401B63",
        "LoD/1.10": "0x00401B63",
        "LoD/1.11": "0x00401B63",
        "LoD/1.11b": "0x00401B63",
        "LoD/1.12a": "0x00401B63",
        "LoD/1.13c": "0x00401B63",
        "LoD/1.13d": "0x00401B63",
        "LoD/1.14a": "0x00401B63",
        "LoD/1.14b": "0x00401B63",
        "LoD/1.14c": "0x00401B63",
        "LoD/1.14d": "0x00401B63"
      },
      "rvas": {
        "LoD/1.07": "0x1B63",
        "LoD/1.08": "0x1B63",
        "LoD/1.09": "0x1B63",
        "LoD/1.09b": "0x1B63",
        "LoD/1.09d": "0x1B63",
        "LoD/1.10": "0x1B63",
        "LoD/1.11": "0x1B63",
        "LoD/1.11b": "0x1B63",
        "LoD/1.12a": "0x1B63",
        "LoD/1.13c": "0x1B63",
        "LoD/1.13d": "0x1B63",
        "LoD/1.14a": "0x1B63",
        "LoD/1.14b": "0x1B63",
        "LoD/1.14c": "0x1B63",
        "LoD/1.14d": "0x1B63"
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
        "LoD/1.13d": 23,
        "LoD/1.14a": 23,
        "LoD/1.14b": 23,
        "LoD/1.14c": 23,
        "LoD/1.14d": 23
      },
      "return_type": "byte *",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:cfea3c92c09904dc7826c9e24e773236",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "cfea3c92c09904dc7826c9e24e773236",
        "CFG": "98e7620973d02b6613d9b483d7e32e88",
        "PRO": "7dc457e6b44146890a20553a859e64ee",
        "CAL": null,
        "CON": null,
        "APS": null
      },
      "display_name": "FUN_00401b63",
      "callers": {
        "LoD/1.07": [
          "FUN_0040146d|0x40146D"
        ],
        "LoD/1.08": [
          "FUN_0040146d|0x40146D"
        ],
        "LoD/1.09": [
          "FUN_0040146d|0x40146D"
        ],
        "LoD/1.09b": [
          "FUN_0040146d|0x40146D"
        ],
        "LoD/1.09d": [
          "FUN_0040146d|0x40146D"
        ],
        "LoD/1.10": [
          "FUN_0040146d|0x40146D"
        ],
        "LoD/1.11": [
          "FUN_0040146d|0x40146D"
        ],
        "LoD/1.11b": [
          "FUN_0040146d|0x40146D"
        ],
        "LoD/1.12a": [
          "FUN_0040146d|0x40146D"
        ],
        "LoD/1.13c": [
          "FUN_0040146d|0x40146D"
        ],
        "LoD/1.13d": [
          "FUN_0040146d|0x40146D"
        ],
        "LoD/1.14a": [
          "FUN_0040146d|0x40146D"
        ],
        "LoD/1.14b": [
          "FUN_0040146d|0x40146D"
        ],
        "LoD/1.14c": [
          "FUN_0040146d|0x40146D"
        ],
        "LoD/1.14d": [
          "FUN_0040146d|0x40146D"
        ]
      },
      "instruction_counts": {
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
        "LoD/1.13d": 9,
        "LoD/1.14a": 9,
        "LoD/1.14b": 9,
        "LoD/1.14c": 9,
        "LoD/1.14d": 9
      },
      "stack_frame_sizes": {
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
        "LoD/1.13d": 8,
        "LoD/1.14a": 8,
        "LoD/1.14b": 8,
        "LoD/1.14c": 8,
        "LoD/1.14d": 8
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
        "LoD/1.13d": 3,
        "LoD/1.14a": 3,
        "LoD/1.14b": 3,
        "LoD/1.14c": 3,
        "LoD/1.14d": 3
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
        "LoD/1.13d": 0,
        "LoD/1.14a": 0,
        "LoD/1.14b": 0,
        "LoD/1.14c": 0,
        "LoD/1.14d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "cfea3c92c09904dc7826c9e24e773236",
        "LoD/1.08": "cfea3c92c09904dc7826c9e24e773236",
        "LoD/1.09": "cfea3c92c09904dc7826c9e24e773236",
        "LoD/1.09b": "cfea3c92c09904dc7826c9e24e773236",
        "LoD/1.09d": "cfea3c92c09904dc7826c9e24e773236",
        "LoD/1.10": "cfea3c92c09904dc7826c9e24e773236",
        "LoD/1.11": "cfea3c92c09904dc7826c9e24e773236",
        "LoD/1.11b": "cfea3c92c09904dc7826c9e24e773236",
        "LoD/1.12a": "cfea3c92c09904dc7826c9e24e773236",
        "LoD/1.13c": "cfea3c92c09904dc7826c9e24e773236",
        "LoD/1.13d": "cfea3c92c09904dc7826c9e24e773236",
        "LoD/1.14a": "cfea3c92c09904dc7826c9e24e773236",
        "LoD/1.14b": "cfea3c92c09904dc7826c9e24e773236",
        "LoD/1.14c": "cfea3c92c09904dc7826c9e24e773236",
        "LoD/1.14d": "cfea3c92c09904dc7826c9e24e773236"
      },
      "constants": {
        "LoD/1.07": [
          4221121
        ],
        "LoD/1.08": [
          4221121
        ],
        "LoD/1.09": [
          4221121
        ],
        "LoD/1.09b": [
          4221121
        ],
        "LoD/1.09d": [
          4221121
        ],
        "LoD/1.10": [
          4221121
        ],
        "LoD/1.11": [
          4221121
        ],
        "LoD/1.11b": [
          4221121
        ],
        "LoD/1.12a": [
          4221121
        ],
        "LoD/1.13c": [
          4221121
        ],
        "LoD/1.13d": [
          4221121
        ],
        "LoD/1.14a": [
          4221121
        ],
        "LoD/1.14b": [
          4221121
        ],
        "LoD/1.14c": [
          4221121
        ],
        "LoD/1.14d": [
          4221121
        ]
      },
      "globals": {
        "LoD/1.07": [
          "0xFFFFFFFFFFC00004|",
          "0x68C1|DAT_004068c0+1"
        ],
        "LoD/1.08": [
          "0xFFFFFFFFFFC00004|",
          "0x68C1|DAT_004068c0+1"
        ],
        "LoD/1.09": [
          "0xFFFFFFFFFFC00004|",
          "0x68C1|DAT_004068c0+1"
        ],
        "LoD/1.09b": [
          "0xFFFFFFFFFFC00004|",
          "0x68C1|DAT_004068c0+1"
        ],
        "LoD/1.09d": [
          "0xFFFFFFFFFFC00004|",
          "0x68C1|DAT_004068c0+1"
        ],
        "LoD/1.10": [
          "0xFFFFFFFFFFC00004|",
          "0x68C1|DAT_004068c0+1"
        ],
        "LoD/1.11": [
          "0xFFFFFFFFFFC00004|",
          "0x68C1|DAT_004068c0+1"
        ],
        "LoD/1.11b": [
          "0xFFFFFFFFFFC00004|",
          "0x68C1|DAT_004068c0+1"
        ],
        "LoD/1.12a": [
          "0xFFFFFFFFFFC00004|",
          "0x68C1|DAT_004068c0+1"
        ],
        "LoD/1.13c": [
          "0xFFFFFFFFFFC00004|",
          "0x68C1|DAT_004068c0+1"
        ],
        "LoD/1.13d": [
          "0xFFFFFFFFFFC00004|",
          "0x68C1|DAT_004068c0+1"
        ],
        "LoD/1.14a": [
          "0xFFFFFFFFFFC00004|",
          "0x68C1|DAT_004068c0+1"
        ],
        "LoD/1.14b": [
          "0xFFFFFFFFFFC00004|",
          "0x68C1|DAT_004068c0+1"
        ],
        "LoD/1.14c": [
          "0xFFFFFFFFFFC00004|",
          "0x68C1|DAT_004068c0+1"
        ],
        "LoD/1.14d": [
          "0xFFFFFFFFFFC00004|",
          "0x68C1|DAT_004068c0+1"
        ]
      }
    },
    "diablo ii.exe__strlen": {
      "addresses": {
        "LoD/1.07": "0x00401B80",
        "LoD/1.08": "0x00401B80",
        "LoD/1.09": "0x00401B80",
        "LoD/1.09b": "0x00401B80",
        "LoD/1.09d": "0x00401B80",
        "LoD/1.10": "0x00401B80",
        "LoD/1.11": "0x00401B80",
        "LoD/1.11b": "0x00401B80",
        "LoD/1.12a": "0x00401B80",
        "LoD/1.13c": "0x00401B80",
        "LoD/1.13d": "0x00401B80",
        "LoD/1.14a": "0x00401B80",
        "LoD/1.14b": "0x00401B80",
        "LoD/1.14c": "0x00401B80",
        "LoD/1.14d": "0x00401B80"
      },
      "rvas": {
        "LoD/1.07": "0x1B80",
        "LoD/1.08": "0x1B80",
        "LoD/1.09": "0x1B80",
        "LoD/1.09b": "0x1B80",
        "LoD/1.09d": "0x1B80",
        "LoD/1.10": "0x1B80",
        "LoD/1.11": "0x1B80",
        "LoD/1.11b": "0x1B80",
        "LoD/1.12a": "0x1B80",
        "LoD/1.13c": "0x1B80",
        "LoD/1.13d": "0x1B80",
        "LoD/1.14a": "0x1B80",
        "LoD/1.14b": "0x1B80",
        "LoD/1.14c": "0x1B80",
        "LoD/1.14d": "0x1B80"
      },
      "sizes": {
        "LoD/1.07": 123,
        "LoD/1.08": 123,
        "LoD/1.09": 123,
        "LoD/1.09b": 123,
        "LoD/1.09d": 123,
        "LoD/1.10": 123,
        "LoD/1.11": 123,
        "LoD/1.11b": 123,
        "LoD/1.12a": 123,
        "LoD/1.13c": 123,
        "LoD/1.13d": 123,
        "LoD/1.14a": 123,
        "LoD/1.14b": 123,
        "LoD/1.14c": 123,
        "LoD/1.14d": 123
      },
      "name": "_strlen",
      "signature": "size_t _strlen(char * _Str)",
      "calling_convention": "__cdecl",
      "return_type": "size_t",
      "comment": "Library Function - Single Match\n _strlen\n\nLibraries: Visual Studio 1998 Debug, Visual Studio 1998 Release",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:2e762c1c6c457f4a0349d0f895009434",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "2e762c1c6c457f4a0349d0f895009434",
        "CFG": "955555387ef5c42bce3cb46728bb931a",
        "PRO": "218e20f78ff67609d741b817a576974e",
        "CAL": null,
        "CON": null,
        "APS": null
      },
      "callers": {
        "LoD/1.07": [
          "FUN_0040146d|0x40146D",
          "DisplayRuntimeError|0x402789",
          "InitializeEnvironmentVariables|0x401F5E"
        ],
        "LoD/1.08": [
          "InitializeEnvironmentVariables|0x401F5E",
          "DisplayRuntimeError|0x402789",
          "FUN_0040146d|0x40146D"
        ],
        "LoD/1.09": [
          "InitializeEnvironmentVariables|0x401F5E",
          "FUN_0040146d|0x40146D",
          "DisplayRuntimeError|0x402789"
        ],
        "LoD/1.09b": [
          "DisplayRuntimeError|0x402789",
          "InitializeEnvironmentVariables|0x401F5E",
          "FUN_0040146d|0x40146D"
        ],
        "LoD/1.09d": [
          "InitializeEnvironmentVariables|0x401F5E",
          "FUN_0040146d|0x40146D",
          "DisplayRuntimeError|0x402789"
        ],
        "LoD/1.10": [
          "InitializeEnvironmentVariables|0x401F5E",
          "FUN_0040146d|0x40146D",
          "DisplayRuntimeError|0x402789"
        ],
        "LoD/1.11": [
          "InitializeEnvironmentVariables|0x401F5E",
          "DisplayRuntimeError|0x402789",
          "FUN_0040146d|0x40146D"
        ],
        "LoD/1.11b": [
          "FUN_0040146d|0x40146D",
          "InitializeEnvironmentVariables|0x401F5E",
          "DisplayRuntimeError|0x402789"
        ],
        "LoD/1.12a": [
          "InitializeEnvironmentVariables|0x401F5E",
          "FUN_0040146d|0x40146D",
          "DisplayRuntimeError|0x402789"
        ],
        "LoD/1.13c": [
          "FUN_0040146d|0x40146D",
          "InitializeEnvironmentVariables|0x401F5E",
          "DisplayRuntimeError|0x402789"
        ],
        "LoD/1.13d": [
          "FUN_0040146d|0x40146D",
          "DisplayRuntimeError|0x402789",
          "InitializeEnvironmentVariables|0x401F5E"
        ],
        "LoD/1.14a": [
          "FUN_0040146d|0x40146D",
          "DisplayRuntimeError|0x402789",
          "InitializeEnvironmentVariables|0x401F5E"
        ],
        "LoD/1.14b": [
          "InitializeEnvironmentVariables|0x401F5E",
          "DisplayRuntimeError|0x402789",
          "FUN_0040146d|0x40146D"
        ],
        "LoD/1.14c": [
          "FUN_0040146d|0x40146D",
          "DisplayRuntimeError|0x402789",
          "InitializeEnvironmentVariables|0x401F5E"
        ],
        "LoD/1.14d": [
          "FUN_0040146d|0x40146D",
          "DisplayRuntimeError|0x402789",
          "InitializeEnvironmentVariables|0x401F5E"
        ]
      },
      "instruction_counts": {
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
        "LoD/1.13d": 44,
        "LoD/1.14a": 44,
        "LoD/1.14b": 44,
        "LoD/1.14c": 44,
        "LoD/1.14d": 44
      },
      "stack_frame_sizes": {
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
        "LoD/1.13d": 8,
        "LoD/1.14a": 8,
        "LoD/1.14b": 8,
        "LoD/1.14c": 8,
        "LoD/1.14d": 8
      },
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
        "LoD/1.13d": 14,
        "LoD/1.14a": 14,
        "LoD/1.14b": 14,
        "LoD/1.14c": 14,
        "LoD/1.14d": 14
      },
      "loop_counts": {
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
        "LoD/1.13d": 3,
        "LoD/1.14a": 3,
        "LoD/1.14b": 3,
        "LoD/1.14c": 3,
        "LoD/1.14d": 3
      },
      "mnemonic_hashes": {
        "LoD/1.07": "2e762c1c6c457f4a0349d0f895009434",
        "LoD/1.08": "2e762c1c6c457f4a0349d0f895009434",
        "LoD/1.09": "2e762c1c6c457f4a0349d0f895009434",
        "LoD/1.09b": "2e762c1c6c457f4a0349d0f895009434",
        "LoD/1.09d": "2e762c1c6c457f4a0349d0f895009434",
        "LoD/1.10": "2e762c1c6c457f4a0349d0f895009434",
        "LoD/1.11": "2e762c1c6c457f4a0349d0f895009434",
        "LoD/1.11b": "2e762c1c6c457f4a0349d0f895009434",
        "LoD/1.12a": "2e762c1c6c457f4a0349d0f895009434",
        "LoD/1.13c": "2e762c1c6c457f4a0349d0f895009434",
        "LoD/1.13d": "2e762c1c6c457f4a0349d0f895009434",
        "LoD/1.14a": "2e762c1c6c457f4a0349d0f895009434",
        "LoD/1.14b": "2e762c1c6c457f4a0349d0f895009434",
        "LoD/1.14c": "2e762c1c6c457f4a0349d0f895009434",
        "LoD/1.14d": "2e762c1c6c457f4a0349d0f895009434"
      },
      "constants": {
        "LoD/1.07": [
          16711680
        ],
        "LoD/1.08": [
          16711680
        ],
        "LoD/1.09": [
          16711680
        ],
        "LoD/1.09b": [
          16711680
        ],
        "LoD/1.09d": [
          16711680
        ],
        "LoD/1.10": [
          16711680
        ],
        "LoD/1.11": [
          16711680
        ],
        "LoD/1.11b": [
          16711680
        ],
        "LoD/1.12a": [
          16711680
        ],
        "LoD/1.13c": [
          16711680
        ],
        "LoD/1.13d": [
          16711680
        ],
        "LoD/1.14a": [
          16711680
        ],
        "LoD/1.14b": [
          16711680
        ],
        "LoD/1.14c": [
          16711680
        ],
        "LoD/1.14d": [
          16711680
        ]
      },
      "globals": {
        "LoD/1.07": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.08": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.09": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.09b": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.09d": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.10": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.11": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.11b": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.12a": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.13c": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.13d": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.14a": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.14b": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.14c": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.14d": [
          "0xFFFFFFFFFFC00004|"
        ]
      }
    },
    "diablo ii.exe_MNE_8cf740ead1ec": {
      "addresses": {
        "LoD/1.07": "0x00401C00"
      },
      "rvas": {
        "LoD/1.07": "0x1C00"
      },
      "sizes": {
        "LoD/1.07": 133
      },
      "return_type": "uint *",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:8cf740ead1ec396b63dfd5a3659dee5d",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "8cf740ead1ec396b63dfd5a3659dee5d",
        "CFG": "0aa1b8c240c978586c56f7da856f0866",
        "PRO": "34afa7d74dd6b64746d7b43ea3ed9c2b",
        "CAL": null,
        "CON": null,
        "APS": null
      },
      "display_name": "FUN_00401c00",
      "callees": {
        "LoD/1.07": [
          "FUN_00402cd6|0x402CD6"
        ]
      },
      "callers": {
        "LoD/1.07": [
          "FUN_0040146d|0x40146D"
        ]
      },
      "instruction_counts": {
        "LoD/1.07": 69
      },
      "stack_frame_sizes": {
        "LoD/1.07": 12
      },
      "basic_block_counts": {
        "LoD/1.07": 19
      },
      "loop_counts": {
        "LoD/1.07": 5
      },
      "mnemonic_hashes": {
        "LoD/1.07": "8cf740ead1ec396b63dfd5a3659dee5d"
      },
      "globals": {
        "LoD/1.07": [
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|"
        ]
      }
    },
    "diablo ii.exe_InitializeGlobalConstructors": {
      "addresses": {
        "LoD/1.07": "0x00401C80",
        "LoD/1.08": "0x00401C80",
        "LoD/1.09": "0x00401C80",
        "LoD/1.09b": "0x00401C80",
        "LoD/1.09d": "0x00401C80",
        "LoD/1.10": "0x00401C80",
        "LoD/1.11": "0x00401C80",
        "LoD/1.11b": "0x00401C80",
        "LoD/1.12a": "0x00401C80",
        "LoD/1.13c": "0x00401C80",
        "LoD/1.13d": "0x00401C80",
        "LoD/1.14a": "0x00401C80",
        "LoD/1.14b": "0x00401C80",
        "LoD/1.14c": "0x00401C80",
        "LoD/1.14d": "0x00401C80"
      },
      "rvas": {
        "LoD/1.07": "0x1C80",
        "LoD/1.08": "0x1C80",
        "LoD/1.09": "0x1C80",
        "LoD/1.09b": "0x1C80",
        "LoD/1.09d": "0x1C80",
        "LoD/1.10": "0x1C80",
        "LoD/1.11": "0x1C80",
        "LoD/1.11b": "0x1C80",
        "LoD/1.12a": "0x1C80",
        "LoD/1.13c": "0x1C80",
        "LoD/1.13d": "0x1C80",
        "LoD/1.14a": "0x1C80",
        "LoD/1.14b": "0x1C80",
        "LoD/1.14c": "0x1C80",
        "LoD/1.14d": "0x1C80"
      },
      "sizes": {
        "LoD/1.07": 45,
        "LoD/1.08": 45,
        "LoD/1.09": 45,
        "LoD/1.09b": 45,
        "LoD/1.09d": 45,
        "LoD/1.10": 45,
        "LoD/1.11": 45,
        "LoD/1.11b": 45,
        "LoD/1.12a": 45,
        "LoD/1.13c": 45,
        "LoD/1.13d": 45,
        "LoD/1.14a": 45,
        "LoD/1.14b": 45,
        "LoD/1.14c": 45,
        "LoD/1.14d": 45
      },
      "name": "InitializeGlobalConstructors",
      "signature": "undefined InitializeGlobalConstructors(void)",
      "calling_convention": "__stdcall",
      "return_type": "undefined",
      "comment": "Initialize global constructors and destructors during DLL loading.\n\nAlgorithm:\n1. Check if optional InitializeSubsystem function pointer exists (0x1002e468)\n2. If present, call the InitializeSubsystem function\n3. Call constructor array iterator with constructor table range (0x1002a008 to 0x1002a010)\n4. Call destructor array iterator with destructor table range (0x1002a000 to 0x1002a004)\n5. Return to caller (DllMain)\n\nParameters:\nNone\n\nReturns:\nvoid - No return value, initialization always completes\n\nSpecial Cases:\n- If g_pfnInitializeSubsystem is NULL, step 2 is skipped safely\n- Constructor/destructor arrays may be empty (start == end), iterator handles gracefully\n- Function called during DLL_PROCESS_ATTACH in DllMain\n\nMagic Numbers Reference:\n0x1002e468 - g_pfnInitializeSubsystem function pointer storage\n0x1002a008 - g_ppfnStaticCtorsStart (constructor array beginning)\n0x1002a010 - g_ppfnStaticCtorsEnd (constructor array end)\n0x1002a000 - g_ppfnStaticDtorsStart (destructor array beginning) \n0x1002a004 - g_ppfnStaticDtorsEnd (destructor array end)",
      "name_source": "LoD/1.07",
      "method": "CON",
      "index": "CON:ffd1b1836e107aac13283afea09b6464",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "91b5192dddb89e963abc2be4471149da",
        "CFG": "f5a9d1c9bfa4d6ec79162a8bb1035352",
        "PRO": "fba0e24939e8722376e743b66770e3ea",
        "CAL": null,
        "CON": "ffd1b1836e107aac13283afea09b6464",
        "APS": null
      },
      "callees": {
        "LoD/1.07": [
          "RunConstructorArray|0x401D68"
        ],
        "LoD/1.08": [
          "RunConstructorArray|0x401D68"
        ],
        "LoD/1.09": [
          "RunConstructorArray|0x401D68"
        ],
        "LoD/1.09b": [
          "RunConstructorArray|0x401D68"
        ],
        "LoD/1.09d": [
          "RunConstructorArray|0x401D68"
        ],
        "LoD/1.10": [
          "RunConstructorArray|0x401D68"
        ],
        "LoD/1.11": [
          "RunConstructorArray|0x401D68"
        ],
        "LoD/1.11b": [
          "RunConstructorArray|0x401D68"
        ],
        "LoD/1.12a": [
          "RunConstructorArray|0x401D68"
        ],
        "LoD/1.13c": [
          "RunConstructorArray|0x401D68"
        ],
        "LoD/1.13d": [
          "RunConstructorArray|0x401D68"
        ],
        "LoD/1.14a": [
          "RunConstructorArray|0x401D68"
        ],
        "LoD/1.14b": [
          "RunConstructorArray|0x401D68"
        ],
        "LoD/1.14c": [
          "RunConstructorArray|0x401D68"
        ],
        "LoD/1.14d": [
          "RunConstructorArray|0x401D68"
        ]
      },
      "callers": {
        "LoD/1.07": [
          "entry|0x4014E3"
        ],
        "LoD/1.08": [
          "entry|0x4014E3"
        ],
        "LoD/1.09": [
          "entry|0x4014E3"
        ],
        "LoD/1.09b": [
          "entry|0x4014E3"
        ],
        "LoD/1.09d": [
          "entry|0x4014E3"
        ],
        "LoD/1.10": [
          "entry|0x4014E3"
        ],
        "LoD/1.11": [
          "entry|0x4014E3"
        ],
        "LoD/1.11b": [
          "entry|0x4014E3"
        ],
        "LoD/1.12a": [
          "entry|0x4014E3"
        ],
        "LoD/1.13c": [
          "entry|0x4014E3"
        ],
        "LoD/1.13d": [
          "entry|0x4014E3"
        ],
        "LoD/1.14a": [
          "entry|0x4014E3"
        ],
        "LoD/1.14b": [
          "entry|0x4014E3"
        ],
        "LoD/1.14c": [
          "entry|0x4014E3"
        ],
        "LoD/1.14d": [
          "entry|0x4014E3"
        ]
      },
      "instruction_counts": {
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
        "LoD/1.13d": 12,
        "LoD/1.14a": 12,
        "LoD/1.14b": 12,
        "LoD/1.14c": 12,
        "LoD/1.14d": 12
      },
      "stack_frame_sizes": {
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
        "LoD/1.13d": 4,
        "LoD/1.14a": 4,
        "LoD/1.14b": 4,
        "LoD/1.14c": 4,
        "LoD/1.14d": 4
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
        "LoD/1.13d": 3,
        "LoD/1.14a": 3,
        "LoD/1.14b": 3,
        "LoD/1.14c": 3,
        "LoD/1.14d": 3
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
        "LoD/1.13d": 0,
        "LoD/1.14a": 0,
        "LoD/1.14b": 0,
        "LoD/1.14c": 0,
        "LoD/1.14d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "91b5192dddb89e963abc2be4471149da",
        "LoD/1.08": "91b5192dddb89e963abc2be4471149da",
        "LoD/1.09": "91b5192dddb89e963abc2be4471149da",
        "LoD/1.09b": "91b5192dddb89e963abc2be4471149da",
        "LoD/1.09d": "91b5192dddb89e963abc2be4471149da",
        "LoD/1.10": "91b5192dddb89e963abc2be4471149da",
        "LoD/1.11": "91b5192dddb89e963abc2be4471149da",
        "LoD/1.11b": "91b5192dddb89e963abc2be4471149da",
        "LoD/1.12a": "91b5192dddb89e963abc2be4471149da",
        "LoD/1.13c": "91b5192dddb89e963abc2be4471149da",
        "LoD/1.13d": "91b5192dddb89e963abc2be4471149da",
        "LoD/1.14a": "91b5192dddb89e963abc2be4471149da",
        "LoD/1.14b": "91b5192dddb89e963abc2be4471149da",
        "LoD/1.14c": "91b5192dddb89e963abc2be4471149da",
        "LoD/1.14d": "91b5192dddb89e963abc2be4471149da"
      },
      "constants": {
        "LoD/1.07": [
          4218880,
          4218884,
          4218888,
          4218896
        ],
        "LoD/1.08": [
          4218880,
          4218884,
          4218888,
          4218896
        ],
        "LoD/1.09": [
          4218880,
          4218884,
          4218888,
          4218896
        ],
        "LoD/1.09b": [
          4218880,
          4218884,
          4218888,
          4218896
        ],
        "LoD/1.09d": [
          4218880,
          4218884,
          4218888,
          4218896
        ],
        "LoD/1.10": [
          4218880,
          4218884,
          4218888,
          4218896
        ],
        "LoD/1.11": [
          4218880,
          4218884,
          4218888,
          4218896
        ],
        "LoD/1.11b": [
          4218880,
          4218884,
          4218888,
          4218896
        ],
        "LoD/1.12a": [
          4218880,
          4218884,
          4218888,
          4218896
        ],
        "LoD/1.13c": [
          4218880,
          4218884,
          4218888,
          4218896
        ],
        "LoD/1.13d": [
          4218880,
          4218884,
          4218888,
          4218896
        ],
        "LoD/1.14a": [
          4218880,
          4218884,
          4218888,
          4218896
        ],
        "LoD/1.14b": [
          4218880,
          4218884,
          4218888,
          4218896
        ],
        "LoD/1.14c": [
          4218880,
          4218884,
          4218888,
          4218896
        ],
        "LoD/1.14d": [
          4218880,
          4218884,
          4218888,
          4218896
        ]
      },
      "globals": {
        "LoD/1.07": [
          "0x6794|g_pfnInitializeSubsystem",
          "0x6010|DAT_00406010",
          "0x6008|DAT_00406008",
          "0x6004|DAT_00406004",
          "0x6000|DAT_00406000"
        ],
        "LoD/1.08": [
          "0x6794|g_pfnInitializeSubsystem",
          "0x6010|DAT_00406010",
          "0x6008|DAT_00406008",
          "0x6004|DAT_00406004",
          "0x6000|DAT_00406000"
        ],
        "LoD/1.09": [
          "0x6794|g_pfnInitializeSubsystem",
          "0x6010|DAT_00406010",
          "0x6008|DAT_00406008",
          "0x6004|DAT_00406004",
          "0x6000|DAT_00406000"
        ],
        "LoD/1.09b": [
          "0x6794|g_pfnInitializeSubsystem",
          "0x6010|DAT_00406010",
          "0x6008|DAT_00406008",
          "0x6004|DAT_00406004",
          "0x6000|DAT_00406000"
        ],
        "LoD/1.09d": [
          "0x6794|g_pfnInitializeSubsystem",
          "0x6010|DAT_00406010",
          "0x6008|DAT_00406008",
          "0x6004|DAT_00406004",
          "0x6000|DAT_00406000"
        ],
        "LoD/1.10": [
          "0x6794|g_pfnInitializeSubsystem",
          "0x6010|DAT_00406010",
          "0x6008|DAT_00406008",
          "0x6004|DAT_00406004",
          "0x6000|DAT_00406000"
        ],
        "LoD/1.11": [
          "0x6794|g_pfnInitializeSubsystem",
          "0x6010|DAT_00406010",
          "0x6008|DAT_00406008",
          "0x6004|DAT_00406004",
          "0x6000|DAT_00406000"
        ],
        "LoD/1.11b": [
          "0x6794|g_pfnInitializeSubsystem",
          "0x6010|DAT_00406010",
          "0x6008|DAT_00406008",
          "0x6004|DAT_00406004",
          "0x6000|DAT_00406000"
        ],
        "LoD/1.12a": [
          "0x6794|g_pfnInitializeSubsystem",
          "0x6010|DAT_00406010",
          "0x6008|DAT_00406008",
          "0x6004|DAT_00406004",
          "0x6000|DAT_00406000"
        ],
        "LoD/1.13c": [
          "0x6794|g_pfnInitializeSubsystem",
          "0x6010|DAT_00406010",
          "0x6008|DAT_00406008",
          "0x6004|DAT_00406004",
          "0x6000|DAT_00406000"
        ],
        "LoD/1.13d": [
          "0x6794|g_pfnInitializeSubsystem",
          "0x6010|DAT_00406010",
          "0x6008|DAT_00406008",
          "0x6004|DAT_00406004",
          "0x6000|DAT_00406000"
        ],
        "LoD/1.14a": [
          "0x6794|g_pfnInitializeSubsystem",
          "0x6010|DAT_00406010",
          "0x6008|DAT_00406008",
          "0x6004|DAT_00406004",
          "0x6000|DAT_00406000"
        ],
        "LoD/1.14b": [
          "0x6794|g_pfnInitializeSubsystem",
          "0x6010|DAT_00406010",
          "0x6008|DAT_00406008",
          "0x6004|DAT_00406004",
          "0x6000|DAT_00406000"
        ],
        "LoD/1.14c": [
          "0x6794|g_pfnInitializeSubsystem",
          "0x6010|DAT_00406010",
          "0x6008|DAT_00406008",
          "0x6004|DAT_00406004",
          "0x6000|DAT_00406000"
        ],
        "LoD/1.14d": [
          "0x6794|g_pfnInitializeSubsystem",
          "0x6010|DAT_00406010",
          "0x6008|DAT_00406008",
          "0x6004|DAT_00406004",
          "0x6000|DAT_00406000"
        ]
      }
    },
    "diablo ii.exe_ReportError": {
      "addresses": {
        "LoD/1.07": "0x00401CAD",
        "LoD/1.08": "0x00401CAD",
        "LoD/1.09": "0x00401CAD",
        "LoD/1.09b": "0x00401CAD",
        "LoD/1.09d": "0x00401CAD",
        "LoD/1.10": "0x00401CAD",
        "LoD/1.11": "0x00401CAD",
        "LoD/1.11b": "0x00401CAD",
        "LoD/1.12a": "0x00401CAD",
        "LoD/1.13c": "0x00401CAD",
        "LoD/1.13d": "0x00401CAD",
        "LoD/1.14a": "0x00401CAD",
        "LoD/1.14b": "0x00401CAD",
        "LoD/1.14c": "0x00401CAD",
        "LoD/1.14d": "0x00401CAD"
      },
      "rvas": {
        "LoD/1.07": "0x1CAD",
        "LoD/1.08": "0x1CAD",
        "LoD/1.09": "0x1CAD",
        "LoD/1.09b": "0x1CAD",
        "LoD/1.09d": "0x1CAD",
        "LoD/1.10": "0x1CAD",
        "LoD/1.11": "0x1CAD",
        "LoD/1.11b": "0x1CAD",
        "LoD/1.12a": "0x1CAD",
        "LoD/1.13c": "0x1CAD",
        "LoD/1.13d": "0x1CAD",
        "LoD/1.14a": "0x1CAD",
        "LoD/1.14b": "0x1CAD",
        "LoD/1.14c": "0x1CAD",
        "LoD/1.14d": "0x1CAD"
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
        "LoD/1.13d": 17,
        "LoD/1.14a": 17,
        "LoD/1.14b": 17,
        "LoD/1.14c": 17,
        "LoD/1.14d": 17
      },
      "name": "ReportError",
      "signature": "void ReportError(uint dwErrorCode)",
      "calling_convention": "__cdecl",
      "return_type": "void",
      "comment": "Simple error reporting wrapper that forwards error codes with default parameters.\n\nAlgorithm:\n1. Accept the error code parameter from the caller\n2. Forward the error code to FUN_6ff2b2cd along with two zero parameters\n3. Return immediately after the function call\n\nParameters:\ndwErrorCode (uint) - Error code to be reported or logged\n\nReturns:\nvoid - No return value (noreturn function based on callers)",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:cd85d17a6b193c95680d3fdca645abba",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "cd85d17a6b193c95680d3fdca645abba",
        "CFG": "62e304a7d521240f86cfa75cc629cf4d",
        "PRO": "b275099b8b97a883fb7870f620754373",
        "CAL": null,
        "CON": null,
        "APS": null
      },
      "callees": {
        "LoD/1.07": [
          "ProcessTerminationHandler|0x401CCF"
        ],
        "LoD/1.08": [
          "ProcessTerminationHandler|0x401CCF"
        ],
        "LoD/1.09": [
          "ProcessTerminationHandler|0x401CCF"
        ],
        "LoD/1.09b": [
          "ProcessTerminationHandler|0x401CCF"
        ],
        "LoD/1.09d": [
          "ProcessTerminationHandler|0x401CCF"
        ],
        "LoD/1.10": [
          "ProcessTerminationHandler|0x401CCF"
        ],
        "LoD/1.11": [
          "ProcessTerminationHandler|0x401CCF"
        ],
        "LoD/1.11b": [
          "ProcessTerminationHandler|0x401CCF"
        ],
        "LoD/1.12a": [
          "ProcessTerminationHandler|0x401CCF"
        ],
        "LoD/1.13c": [
          "ProcessTerminationHandler|0x401CCF"
        ],
        "LoD/1.13d": [
          "ProcessTerminationHandler|0x401CCF"
        ],
        "LoD/1.14a": [
          "ProcessTerminationHandler|0x401CCF"
        ],
        "LoD/1.14b": [
          "ProcessTerminationHandler|0x401CCF"
        ],
        "LoD/1.14c": [
          "ProcessTerminationHandler|0x401CCF"
        ],
        "LoD/1.14d": [
          "ProcessTerminationHandler|0x401CCF"
        ]
      },
      "callers": {
        "LoD/1.07": [
          "entry|0x4014E3"
        ],
        "LoD/1.08": [
          "entry|0x4014E3"
        ],
        "LoD/1.09": [
          "entry|0x4014E3"
        ],
        "LoD/1.09b": [
          "entry|0x4014E3"
        ],
        "LoD/1.09d": [
          "entry|0x4014E3"
        ],
        "LoD/1.10": [
          "entry|0x4014E3"
        ],
        "LoD/1.11": [
          "entry|0x4014E3"
        ],
        "LoD/1.11b": [
          "entry|0x4014E3"
        ],
        "LoD/1.12a": [
          "entry|0x4014E3"
        ],
        "LoD/1.13c": [
          "entry|0x4014E3"
        ],
        "LoD/1.13d": [
          "entry|0x4014E3"
        ],
        "LoD/1.14a": [
          "entry|0x4014E3"
        ],
        "LoD/1.14b": [
          "entry|0x4014E3"
        ],
        "LoD/1.14c": [
          "entry|0x4014E3"
        ],
        "LoD/1.14d": [
          "entry|0x4014E3"
        ]
      },
      "instruction_counts": {
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
        "LoD/1.13d": 6,
        "LoD/1.14a": 6,
        "LoD/1.14b": 6,
        "LoD/1.14c": 6,
        "LoD/1.14d": 6
      },
      "stack_frame_sizes": {
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
        "LoD/1.13d": 8,
        "LoD/1.14a": 8,
        "LoD/1.14b": 8,
        "LoD/1.14c": 8,
        "LoD/1.14d": 8
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
        "LoD/1.13d": 1,
        "LoD/1.14a": 1,
        "LoD/1.14b": 1,
        "LoD/1.14c": 1,
        "LoD/1.14d": 1
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
        "LoD/1.13d": 0,
        "LoD/1.14a": 0,
        "LoD/1.14b": 0,
        "LoD/1.14c": 0,
        "LoD/1.14d": 0
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
        "LoD/1.13d": "cd85d17a6b193c95680d3fdca645abba",
        "LoD/1.14a": "cd85d17a6b193c95680d3fdca645abba",
        "LoD/1.14b": "cd85d17a6b193c95680d3fdca645abba",
        "LoD/1.14c": "cd85d17a6b193c95680d3fdca645abba",
        "LoD/1.14d": "cd85d17a6b193c95680d3fdca645abba"
      },
      "globals": {
        "LoD/1.07": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.08": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.09": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.09b": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.09d": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.10": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.11": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.11b": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.12a": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.13c": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.13d": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.14a": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.14b": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.14c": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.14d": [
          "0xFFFFFFFFFFC00004|"
        ]
      }
    },
    "diablo ii.exe___exit": {
      "addresses": {
        "LoD/1.07": "0x00401CBE",
        "LoD/1.08": "0x00401CBE",
        "LoD/1.09": "0x00401CBE",
        "LoD/1.09b": "0x00401CBE",
        "LoD/1.09d": "0x00401CBE",
        "LoD/1.10": "0x00401CBE",
        "LoD/1.11": "0x00401CBE",
        "LoD/1.11b": "0x00401CBE",
        "LoD/1.12a": "0x00401CBE",
        "LoD/1.13c": "0x00401CBE",
        "LoD/1.13d": "0x00401CBE",
        "LoD/1.14a": "0x00401CBE",
        "LoD/1.14b": "0x00401CBE",
        "LoD/1.14c": "0x00401CBE",
        "LoD/1.14d": "0x00401CBE"
      },
      "rvas": {
        "LoD/1.07": "0x1CBE",
        "LoD/1.08": "0x1CBE",
        "LoD/1.09": "0x1CBE",
        "LoD/1.09b": "0x1CBE",
        "LoD/1.09d": "0x1CBE",
        "LoD/1.10": "0x1CBE",
        "LoD/1.11": "0x1CBE",
        "LoD/1.11b": "0x1CBE",
        "LoD/1.12a": "0x1CBE",
        "LoD/1.13c": "0x1CBE",
        "LoD/1.13d": "0x1CBE",
        "LoD/1.14a": "0x1CBE",
        "LoD/1.14b": "0x1CBE",
        "LoD/1.14c": "0x1CBE",
        "LoD/1.14d": "0x1CBE"
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
        "LoD/1.13d": 17,
        "LoD/1.14a": 17,
        "LoD/1.14b": 17,
        "LoD/1.14c": 17,
        "LoD/1.14d": 17
      },
      "name": "__exit",
      "signature": "void __exit(int _Code)",
      "calling_convention": "__cdecl",
      "return_type": "void",
      "comment": "Library Function - Single Match\n __exit\n\nLibrary: Visual Studio 2003 Release",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:cd85d17a6b193c95680d3fdca645abba",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "cd85d17a6b193c95680d3fdca645abba",
        "CFG": "62e304a7d521240f86cfa75cc629cf4d",
        "PRO": "f2238f9eeeea41b2f4bb34406e2503e2",
        "CAL": null,
        "CON": null,
        "APS": null
      },
      "callees": {
        "LoD/1.07": [
          "ProcessTerminationHandler|0x401CCF"
        ],
        "LoD/1.08": [
          "ProcessTerminationHandler|0x401CCF"
        ],
        "LoD/1.09": [
          "ProcessTerminationHandler|0x401CCF"
        ],
        "LoD/1.09b": [
          "ProcessTerminationHandler|0x401CCF"
        ],
        "LoD/1.09d": [
          "ProcessTerminationHandler|0x401CCF"
        ],
        "LoD/1.10": [
          "ProcessTerminationHandler|0x401CCF"
        ],
        "LoD/1.11": [
          "ProcessTerminationHandler|0x401CCF"
        ],
        "LoD/1.11b": [
          "ProcessTerminationHandler|0x401CCF"
        ],
        "LoD/1.12a": [
          "ProcessTerminationHandler|0x401CCF"
        ],
        "LoD/1.13c": [
          "ProcessTerminationHandler|0x401CCF"
        ],
        "LoD/1.13d": [
          "ProcessTerminationHandler|0x401CCF"
        ],
        "LoD/1.14a": [
          "ProcessTerminationHandler|0x401CCF"
        ],
        "LoD/1.14b": [
          "ProcessTerminationHandler|0x401CCF"
        ],
        "LoD/1.14c": [
          "ProcessTerminationHandler|0x401CCF"
        ],
        "LoD/1.14d": [
          "ProcessTerminationHandler|0x401CCF"
        ]
      },
      "callers": {
        "LoD/1.07": [
          "AmsgExit|0x4015D9"
        ],
        "LoD/1.08": [
          "AmsgExit|0x4015D9"
        ],
        "LoD/1.09": [
          "AmsgExit|0x4015D9"
        ],
        "LoD/1.09b": [
          "AmsgExit|0x4015D9"
        ],
        "LoD/1.09d": [
          "AmsgExit|0x4015D9"
        ],
        "LoD/1.10": [
          "AmsgExit|0x4015D9"
        ],
        "LoD/1.11": [
          "AmsgExit|0x4015D9"
        ],
        "LoD/1.11b": [
          "AmsgExit|0x4015D9"
        ],
        "LoD/1.12a": [
          "AmsgExit|0x4015D9"
        ],
        "LoD/1.13c": [
          "AmsgExit|0x4015D9"
        ],
        "LoD/1.13d": [
          "AmsgExit|0x4015D9"
        ],
        "LoD/1.14a": [
          "AmsgExit|0x4015D9"
        ],
        "LoD/1.14b": [
          "AmsgExit|0x4015D9"
        ],
        "LoD/1.14c": [
          "AmsgExit|0x4015D9"
        ],
        "LoD/1.14d": [
          "AmsgExit|0x4015D9"
        ]
      },
      "instruction_counts": {
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
        "LoD/1.13d": 6,
        "LoD/1.14a": 6,
        "LoD/1.14b": 6,
        "LoD/1.14c": 6,
        "LoD/1.14d": 6
      },
      "stack_frame_sizes": {
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
        "LoD/1.13d": 8,
        "LoD/1.14a": 8,
        "LoD/1.14b": 8,
        "LoD/1.14c": 8,
        "LoD/1.14d": 8
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
        "LoD/1.13d": 1,
        "LoD/1.14a": 1,
        "LoD/1.14b": 1,
        "LoD/1.14c": 1,
        "LoD/1.14d": 1
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
        "LoD/1.13d": 0,
        "LoD/1.14a": 0,
        "LoD/1.14b": 0,
        "LoD/1.14c": 0,
        "LoD/1.14d": 0
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
        "LoD/1.13d": "cd85d17a6b193c95680d3fdca645abba",
        "LoD/1.14a": "cd85d17a6b193c95680d3fdca645abba",
        "LoD/1.14b": "cd85d17a6b193c95680d3fdca645abba",
        "LoD/1.14c": "cd85d17a6b193c95680d3fdca645abba",
        "LoD/1.14d": "cd85d17a6b193c95680d3fdca645abba"
      },
      "globals": {
        "LoD/1.07": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.08": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.09": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.09b": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.09d": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.10": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.11": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.11b": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.12a": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.13c": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.13d": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.14a": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.14b": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.14c": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.14d": [
          "0xFFFFFFFFFFC00004|"
        ]
      }
    },
    "diablo ii.exe_ProcessTerminationHandler": {
      "addresses": {
        "LoD/1.07": "0x00401CCF",
        "LoD/1.08": "0x00401CCF",
        "LoD/1.09": "0x00401CCF",
        "LoD/1.09b": "0x00401CCF",
        "LoD/1.09d": "0x00401CCF",
        "LoD/1.10": "0x00401CCF",
        "LoD/1.11": "0x00401CCF",
        "LoD/1.11b": "0x00401CCF",
        "LoD/1.12a": "0x00401CCF",
        "LoD/1.13c": "0x00401CCF",
        "LoD/1.13d": "0x00401CCF",
        "LoD/1.14a": "0x00401CCF",
        "LoD/1.14b": "0x00401CCF",
        "LoD/1.14c": "0x00401CCF",
        "LoD/1.14d": "0x00401CCF"
      },
      "rvas": {
        "LoD/1.07": "0x1CCF",
        "LoD/1.08": "0x1CCF",
        "LoD/1.09": "0x1CCF",
        "LoD/1.09b": "0x1CCF",
        "LoD/1.09d": "0x1CCF",
        "LoD/1.10": "0x1CCF",
        "LoD/1.11": "0x1CCF",
        "LoD/1.11b": "0x1CCF",
        "LoD/1.12a": "0x1CCF",
        "LoD/1.13c": "0x1CCF",
        "LoD/1.13d": "0x1CCF",
        "LoD/1.14a": "0x1CCF",
        "LoD/1.14b": "0x1CCF",
        "LoD/1.14c": "0x1CCF",
        "LoD/1.14d": "0x1CCF"
      },
      "sizes": {
        "LoD/1.07": 153,
        "LoD/1.08": 153,
        "LoD/1.09": 153,
        "LoD/1.09b": 153,
        "LoD/1.09d": 153,
        "LoD/1.10": 153,
        "LoD/1.11": 153,
        "LoD/1.11b": 153,
        "LoD/1.12a": 153,
        "LoD/1.13c": 153,
        "LoD/1.13d": 153,
        "LoD/1.14a": 153,
        "LoD/1.14b": 153,
        "LoD/1.14c": 153,
        "LoD/1.14d": 153
      },
      "name": "ProcessTerminationHandler",
      "signature": "void ProcessTerminationHandler(uint dwExitCode, int nCleanupMode, int nDeferExit)",
      "calling_convention": "__cdecl",
      "return_type": "void",
      "comment": "Process termination handler with optional cleanup and deferred exit capability\n\nAlgorithm:\n1. Check immediate termination flag (DAT_1003c944) - if set, terminate process immediately using TerminateProcess\n2. Set termination active flag (DAT_1003c940 = 1) to indicate termination is in progress\n3. Store defer exit flag in global state (DAT_1003c93c) as byte value from nDeferExit parameter\n4. If cleanup mode is enabled (nCleanupMode == 0), execute cleanup sequence:\n   a. Check if cleanup function pointer array exists (DAT_1003cdf0 != NULL)\n   b. Calculate start position at end of array (DAT_1003cdec - 4) for LIFO iteration\n   c. Iterate backwards through function pointer array calling each non-null cleanup function\n   d. Call RunConstructorArray for address range 0x1002a014 to 0x1002a018\n5. Always call RunConstructorArray for address range 0x1002a01c to 0x1002a020 regardless of cleanup mode\n6. Check defer exit flag - if nDeferExit is non-zero, return without exiting process\n7. Set final termination flag (DAT_1003c944 = 1) and call ExitProcess with specified exit code\n\nParameters:\nuExitCode - Process exit code to pass to Windows ExitProcess API (type: uint)\nnCleanupMode - Cleanup execution control (0 = run cleanup functions, non-zero = skip cleanup)\nnDeferExit - Exit deferral control (0 = exit immediately after cleanup, non-zero = return without exiting)\n\nReturns:\nvoid - Function does not return when nDeferExit is 0 (calls ExitProcess which terminates process)",
      "name_source": "LoD/1.07",
      "method": "CAL",
      "index": "CAL:27ebe146dce13416596cd9c00f1a4f1a",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "45d9b348a966df89d3a7165f288b5d47",
        "CFG": "3032efab47d2992b12e125a9e89e3ead",
        "PRO": "740da805cb7379a963f118613cdee827",
        "CAL": "27ebe146dce13416596cd9c00f1a4f1a",
        "CON": "766020a54044a9b7654219135ae64bfe",
        "APS": null
      },
      "callees": {
        "LoD/1.07": [
          "ExitProcess|0xE",
          "GetCurrentProcess|0x13",
          "TerminateProcess|0x12",
          "RunConstructorArray|0x401D68"
        ],
        "LoD/1.08": [
          "GetCurrentProcess|0x13",
          "TerminateProcess|0x12",
          "RunConstructorArray|0x401D68",
          "ExitProcess|0xE"
        ],
        "LoD/1.09": [
          "ExitProcess|0xE",
          "TerminateProcess|0x12",
          "GetCurrentProcess|0x13",
          "RunConstructorArray|0x401D68"
        ],
        "LoD/1.09b": [
          "GetCurrentProcess|0x13",
          "ExitProcess|0xE",
          "RunConstructorArray|0x401D68",
          "TerminateProcess|0x12"
        ],
        "LoD/1.09d": [
          "RunConstructorArray|0x401D68",
          "GetCurrentProcess|0x13",
          "ExitProcess|0xE",
          "TerminateProcess|0x12"
        ],
        "LoD/1.10": [
          "TerminateProcess|0x12",
          "GetCurrentProcess|0x13",
          "ExitProcess|0xE",
          "RunConstructorArray|0x401D68"
        ],
        "LoD/1.11": [
          "RunConstructorArray|0x401D68",
          "TerminateProcess|0x12",
          "GetCurrentProcess|0x13",
          "ExitProcess|0xE"
        ],
        "LoD/1.11b": [
          "RunConstructorArray|0x401D68",
          "ExitProcess|0xE",
          "TerminateProcess|0x12",
          "GetCurrentProcess|0x13"
        ],
        "LoD/1.12a": [
          "GetCurrentProcess|0x13",
          "ExitProcess|0xE",
          "RunConstructorArray|0x401D68",
          "TerminateProcess|0x12"
        ],
        "LoD/1.13c": [
          "RunConstructorArray|0x401D68",
          "TerminateProcess|0x12",
          "ExitProcess|0xE",
          "GetCurrentProcess|0x13"
        ],
        "LoD/1.13d": [
          "RunConstructorArray|0x401D68",
          "ExitProcess|0xE",
          "TerminateProcess|0x12",
          "GetCurrentProcess|0x13"
        ],
        "LoD/1.14a": [
          "RunConstructorArray|0x401D68",
          "ExitProcess|0xE",
          "TerminateProcess|0x12",
          "GetCurrentProcess|0x13"
        ],
        "LoD/1.14b": [
          "TerminateProcess|0x12",
          "RunConstructorArray|0x401D68",
          "ExitProcess|0xE",
          "GetCurrentProcess|0x13"
        ],
        "LoD/1.14c": [
          "TerminateProcess|0x12",
          "GetCurrentProcess|0x13",
          "ExitProcess|0xE",
          "RunConstructorArray|0x401D68"
        ],
        "LoD/1.14d": [
          "RunConstructorArray|0x401D68",
          "TerminateProcess|0x12",
          "GetCurrentProcess|0x13",
          "ExitProcess|0xE"
        ]
      },
      "callers": {
        "LoD/1.07": [
          "ReportError|0x401CAD",
          "__exit|0x401CBE"
        ],
        "LoD/1.08": [
          "__exit|0x401CBE",
          "ReportError|0x401CAD"
        ],
        "LoD/1.09": [
          "__exit|0x401CBE",
          "ReportError|0x401CAD"
        ],
        "LoD/1.09b": [
          "__exit|0x401CBE",
          "ReportError|0x401CAD"
        ],
        "LoD/1.09d": [
          "__exit|0x401CBE",
          "ReportError|0x401CAD"
        ],
        "LoD/1.10": [
          "__exit|0x401CBE",
          "ReportError|0x401CAD"
        ],
        "LoD/1.11": [
          "__exit|0x401CBE",
          "ReportError|0x401CAD"
        ],
        "LoD/1.11b": [
          "ReportError|0x401CAD",
          "__exit|0x401CBE"
        ],
        "LoD/1.12a": [
          "ReportError|0x401CAD",
          "__exit|0x401CBE"
        ],
        "LoD/1.13c": [
          "ReportError|0x401CAD",
          "__exit|0x401CBE"
        ],
        "LoD/1.13d": [
          "__exit|0x401CBE",
          "ReportError|0x401CAD"
        ],
        "LoD/1.14a": [
          "ReportError|0x401CAD",
          "__exit|0x401CBE"
        ],
        "LoD/1.14b": [
          "__exit|0x401CBE",
          "ReportError|0x401CAD"
        ],
        "LoD/1.14c": [
          "__exit|0x401CBE",
          "ReportError|0x401CAD"
        ],
        "LoD/1.14d": [
          "ReportError|0x401CAD",
          "__exit|0x401CBE"
        ]
      },
      "instruction_counts": {
        "LoD/1.07": 49,
        "LoD/1.08": 49,
        "LoD/1.09": 49,
        "LoD/1.09b": 49,
        "LoD/1.09d": 49,
        "LoD/1.10": 49,
        "LoD/1.11": 49,
        "LoD/1.11b": 49,
        "LoD/1.12a": 49,
        "LoD/1.13c": 49,
        "LoD/1.13d": 49,
        "LoD/1.14a": 49,
        "LoD/1.14b": 49,
        "LoD/1.14c": 49,
        "LoD/1.14d": 49
      },
      "stack_frame_sizes": {
        "LoD/1.07": 16,
        "LoD/1.08": 16,
        "LoD/1.09": 16,
        "LoD/1.09b": 16,
        "LoD/1.09d": 16,
        "LoD/1.10": 16,
        "LoD/1.11": 16,
        "LoD/1.11b": 16,
        "LoD/1.12a": 16,
        "LoD/1.13c": 16,
        "LoD/1.13d": 16,
        "LoD/1.14a": 16,
        "LoD/1.14b": 16,
        "LoD/1.14c": 16,
        "LoD/1.14d": 16
      },
      "basic_block_counts": {
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
        "LoD/1.13d": 13,
        "LoD/1.14a": 13,
        "LoD/1.14b": 13,
        "LoD/1.14c": 13,
        "LoD/1.14d": 13
      },
      "loop_counts": {
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
        "LoD/1.13d": 1,
        "LoD/1.14a": 1,
        "LoD/1.14b": 1,
        "LoD/1.14c": 1,
        "LoD/1.14d": 1
      },
      "mnemonic_hashes": {
        "LoD/1.07": "45d9b348a966df89d3a7165f288b5d47",
        "LoD/1.08": "45d9b348a966df89d3a7165f288b5d47",
        "LoD/1.09": "45d9b348a966df89d3a7165f288b5d47",
        "LoD/1.09b": "45d9b348a966df89d3a7165f288b5d47",
        "LoD/1.09d": "45d9b348a966df89d3a7165f288b5d47",
        "LoD/1.10": "45d9b348a966df89d3a7165f288b5d47",
        "LoD/1.11": "45d9b348a966df89d3a7165f288b5d47",
        "LoD/1.11b": "45d9b348a966df89d3a7165f288b5d47",
        "LoD/1.12a": "45d9b348a966df89d3a7165f288b5d47",
        "LoD/1.13c": "45d9b348a966df89d3a7165f288b5d47",
        "LoD/1.13d": "45d9b348a966df89d3a7165f288b5d47",
        "LoD/1.14a": "45d9b348a966df89d3a7165f288b5d47",
        "LoD/1.14b": "45d9b348a966df89d3a7165f288b5d47",
        "LoD/1.14c": "45d9b348a966df89d3a7165f288b5d47",
        "LoD/1.14d": "45d9b348a966df89d3a7165f288b5d47"
      },
      "constants": {
        "LoD/1.07": [
          4218900,
          4218904,
          4218908,
          4218912
        ],
        "LoD/1.08": [
          4218900,
          4218904,
          4218908,
          4218912
        ],
        "LoD/1.09": [
          4218900,
          4218904,
          4218908,
          4218912
        ],
        "LoD/1.09b": [
          4218900,
          4218904,
          4218908,
          4218912
        ],
        "LoD/1.09d": [
          4218900,
          4218904,
          4218908,
          4218912
        ],
        "LoD/1.10": [
          4218900,
          4218904,
          4218908,
          4218912
        ],
        "LoD/1.11": [
          4218900,
          4218904,
          4218908,
          4218912
        ],
        "LoD/1.11b": [
          4218900,
          4218904,
          4218908,
          4218912
        ],
        "LoD/1.12a": [
          4218900,
          4218904,
          4218908,
          4218912
        ],
        "LoD/1.13c": [
          4218900,
          4218904,
          4218908,
          4218912
        ],
        "LoD/1.13d": [
          4218900,
          4218904,
          4218908,
          4218912
        ],
        "LoD/1.14a": [
          4218900,
          4218904,
          4218908,
          4218912
        ],
        "LoD/1.14b": [
          4218900,
          4218904,
          4218908,
          4218912
        ],
        "LoD/1.14c": [
          4218900,
          4218904,
          4218908,
          4218912
        ],
        "LoD/1.14d": [
          4218900,
          4218904,
          4218908,
          4218912
        ]
      },
      "globals": {
        "LoD/1.07": [
          "0x650C|DAT_0040650c",
          "0xFFFFFFFFFFC00004|",
          "0x5048|PTR_GetCurrentProcess_00405048",
          "0x5044|PTR_TerminateProcess_00405044",
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC0000C|",
          "0x6508|DAT_00406508",
          "0x6504|DAT_00406504",
          "0x6790|DAT_00406790",
          "0x678C|DAT_0040678c"
        ],
        "LoD/1.08": [
          "0x650C|DAT_0040650c",
          "0xFFFFFFFFFFC00004|",
          "0x5048|PTR_GetCurrentProcess_00405048",
          "0x5044|PTR_TerminateProcess_00405044",
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC0000C|",
          "0x6508|DAT_00406508",
          "0x6504|DAT_00406504",
          "0x6790|DAT_00406790",
          "0x678C|DAT_0040678c"
        ],
        "LoD/1.09": [
          "0x650C|DAT_0040650c",
          "0xFFFFFFFFFFC00004|",
          "0x5048|PTR_GetCurrentProcess_00405048",
          "0x5044|PTR_TerminateProcess_00405044",
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC0000C|",
          "0x6508|DAT_00406508",
          "0x6504|DAT_00406504",
          "0x6790|DAT_00406790",
          "0x678C|DAT_0040678c"
        ],
        "LoD/1.09b": [
          "0x650C|DAT_0040650c",
          "0xFFFFFFFFFFC00004|",
          "0x5048|PTR_GetCurrentProcess_00405048",
          "0x5044|PTR_TerminateProcess_00405044",
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC0000C|",
          "0x6508|DAT_00406508",
          "0x6504|DAT_00406504",
          "0x6790|DAT_00406790",
          "0x678C|DAT_0040678c"
        ],
        "LoD/1.09d": [
          "0x650C|DAT_0040650c",
          "0xFFFFFFFFFFC00004|",
          "0x5048|PTR_GetCurrentProcess_00405048",
          "0x5044|PTR_TerminateProcess_00405044",
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC0000C|",
          "0x6508|DAT_00406508",
          "0x6504|DAT_00406504",
          "0x6790|DAT_00406790",
          "0x678C|DAT_0040678c"
        ],
        "LoD/1.10": [
          "0x650C|DAT_0040650c",
          "0xFFFFFFFFFFC00004|",
          "0x5048|PTR_GetCurrentProcess_00405048",
          "0x5044|PTR_TerminateProcess_00405044",
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC0000C|",
          "0x6508|DAT_00406508",
          "0x6504|DAT_00406504",
          "0x6790|DAT_00406790",
          "0x678C|DAT_0040678c"
        ],
        "LoD/1.11": [
          "0x650C|DAT_0040650c",
          "0xFFFFFFFFFFC00004|",
          "0x5048|PTR_GetCurrentProcess_00405048",
          "0x5044|PTR_TerminateProcess_00405044",
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC0000C|",
          "0x6508|DAT_00406508",
          "0x6504|DAT_00406504",
          "0x6790|DAT_00406790",
          "0x678C|DAT_0040678c"
        ],
        "LoD/1.11b": [
          "0x650C|DAT_0040650c",
          "0xFFFFFFFFFFC00004|",
          "0x5048|PTR_GetCurrentProcess_00405048",
          "0x5044|PTR_TerminateProcess_00405044",
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC0000C|",
          "0x6508|DAT_00406508",
          "0x6504|DAT_00406504",
          "0x6790|DAT_00406790",
          "0x678C|DAT_0040678c"
        ],
        "LoD/1.12a": [
          "0x650C|DAT_0040650c",
          "0xFFFFFFFFFFC00004|",
          "0x5048|PTR_GetCurrentProcess_00405048",
          "0x5044|PTR_TerminateProcess_00405044",
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC0000C|",
          "0x6508|DAT_00406508",
          "0x6504|DAT_00406504",
          "0x6790|DAT_00406790",
          "0x678C|DAT_0040678c"
        ],
        "LoD/1.13c": [
          "0x650C|DAT_0040650c",
          "0xFFFFFFFFFFC00004|",
          "0x5048|PTR_GetCurrentProcess_00405048",
          "0x5044|PTR_TerminateProcess_00405044",
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC0000C|",
          "0x6508|DAT_00406508",
          "0x6504|DAT_00406504",
          "0x6790|DAT_00406790",
          "0x678C|DAT_0040678c"
        ],
        "LoD/1.13d": [
          "0x650C|DAT_0040650c",
          "0xFFFFFFFFFFC00004|",
          "0x5048|PTR_GetCurrentProcess_00405048",
          "0x5044|PTR_TerminateProcess_00405044",
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC0000C|",
          "0x6508|DAT_00406508",
          "0x6504|DAT_00406504",
          "0x6790|DAT_00406790",
          "0x678C|DAT_0040678c"
        ],
        "LoD/1.14a": [
          "0x650C|DAT_0040650c",
          "0xFFFFFFFFFFC00004|",
          "0x5048|PTR_GetCurrentProcess_00405048",
          "0x5044|PTR_TerminateProcess_00405044",
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC0000C|",
          "0x6508|DAT_00406508",
          "0x6504|DAT_00406504",
          "0x6790|DAT_00406790",
          "0x678C|DAT_0040678c"
        ],
        "LoD/1.14b": [
          "0x650C|DAT_0040650c",
          "0xFFFFFFFFFFC00004|",
          "0x5048|PTR_GetCurrentProcess_00405048",
          "0x5044|PTR_TerminateProcess_00405044",
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC0000C|",
          "0x6508|DAT_00406508",
          "0x6504|DAT_00406504",
          "0x6790|DAT_00406790",
          "0x678C|DAT_0040678c"
        ],
        "LoD/1.14c": [
          "0x650C|DAT_0040650c",
          "0xFFFFFFFFFFC00004|",
          "0x5048|PTR_GetCurrentProcess_00405048",
          "0x5044|PTR_TerminateProcess_00405044",
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC0000C|",
          "0x6508|DAT_00406508",
          "0x6504|DAT_00406504",
          "0x6790|DAT_00406790",
          "0x678C|DAT_0040678c"
        ],
        "LoD/1.14d": [
          "0x650C|DAT_0040650c",
          "0xFFFFFFFFFFC00004|",
          "0x5048|PTR_GetCurrentProcess_00405048",
          "0x5044|PTR_TerminateProcess_00405044",
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC0000C|",
          "0x6508|DAT_00406508",
          "0x6504|DAT_00406504",
          "0x6790|DAT_00406790",
          "0x678C|DAT_0040678c"
        ]
      }
    },
    "diablo ii.exe_RunConstructorArray": {
      "addresses": {
        "LoD/1.07": "0x00401D68",
        "LoD/1.08": "0x00401D68",
        "LoD/1.09": "0x00401D68",
        "LoD/1.09b": "0x00401D68",
        "LoD/1.09d": "0x00401D68",
        "LoD/1.10": "0x00401D68",
        "LoD/1.11": "0x00401D68",
        "LoD/1.11b": "0x00401D68",
        "LoD/1.12a": "0x00401D68",
        "LoD/1.13c": "0x00401D68",
        "LoD/1.13d": "0x00401D68",
        "LoD/1.14a": "0x00401D68",
        "LoD/1.14b": "0x00401D68",
        "LoD/1.14c": "0x00401D68",
        "LoD/1.14d": "0x00401D68"
      },
      "rvas": {
        "LoD/1.07": "0x1D68",
        "LoD/1.08": "0x1D68",
        "LoD/1.09": "0x1D68",
        "LoD/1.09b": "0x1D68",
        "LoD/1.09d": "0x1D68",
        "LoD/1.10": "0x1D68",
        "LoD/1.11": "0x1D68",
        "LoD/1.11b": "0x1D68",
        "LoD/1.12a": "0x1D68",
        "LoD/1.13c": "0x1D68",
        "LoD/1.13d": "0x1D68",
        "LoD/1.14a": "0x1D68",
        "LoD/1.14b": "0x1D68",
        "LoD/1.14c": "0x1D68",
        "LoD/1.14d": "0x1D68"
      },
      "sizes": {
        "LoD/1.07": 26,
        "LoD/1.08": 26,
        "LoD/1.09": 26,
        "LoD/1.09b": 26,
        "LoD/1.09d": 26,
        "LoD/1.10": 26,
        "LoD/1.11": 26,
        "LoD/1.11b": 26,
        "LoD/1.12a": 26,
        "LoD/1.13c": 26,
        "LoD/1.13d": 26,
        "LoD/1.14a": 26,
        "LoD/1.14b": 26,
        "LoD/1.14c": 26,
        "LoD/1.14d": 26
      },
      "name": "RunConstructorArray",
      "signature": "void RunConstructorArray(void * * ppfnStart, void * * ppfnEnd)",
      "calling_convention": "__cdecl",
      "return_type": "void",
      "comment": "Executes an array of constructor or initialization function pointers in sequence.\n\nAlgorithm:\n1. Iterate through function pointer array from ppfnStart to ppfnEnd (exclusive)\n2. For each 4-byte aligned function pointer entry:\n   a. Load the function pointer value into EAX\n   b. Test if pointer is non-null (TEST EAX,EAX) \n   c. Skip null pointers (JZ to increment)\n   d. Call the function pointer (CALL EAX) with no parameters\n3. Advance to next function pointer (ADD ESI,0x4)\n4. Continue until reaching end pointer (CMP ESI,[ESP+0xc])\n5. Return when all valid function pointers have been executed\n\nParameters:\n- ppfnStart (void * *): Pointer to start of function pointer array\n- ppfnEnd (void * *): Pointer to end of function pointer array (exclusive)\n\nReturns:\n- void: No return value\n\nSpecial Cases:\n- Null function pointers are safely skipped without error\n- Empty array (ppfnStart == ppfnEnd) exits immediately\n- No parameter validation - assumes valid array bounds\n\nError Handling:\n- No explicit error handling\n- Relies on caller to provide valid array bounds\n- Function calls are made with no error checking",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:f1060dff4c8b86b7cd32c42f8f136fb6",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "f1060dff4c8b86b7cd32c42f8f136fb6",
        "CFG": "0a074b8816415288c3cc84ef0b37ed0c",
        "PRO": "c5843f3db205987ea5094c55a1bdaf18",
        "CAL": null,
        "CON": null,
        "APS": null
      },
      "callers": {
        "LoD/1.07": [
          "InitializeGlobalConstructors|0x401C80",
          "ProcessTerminationHandler|0x401CCF"
        ],
        "LoD/1.08": [
          "InitializeGlobalConstructors|0x401C80",
          "ProcessTerminationHandler|0x401CCF"
        ],
        "LoD/1.09": [
          "InitializeGlobalConstructors|0x401C80",
          "ProcessTerminationHandler|0x401CCF"
        ],
        "LoD/1.09b": [
          "ProcessTerminationHandler|0x401CCF",
          "InitializeGlobalConstructors|0x401C80"
        ],
        "LoD/1.09d": [
          "InitializeGlobalConstructors|0x401C80",
          "ProcessTerminationHandler|0x401CCF"
        ],
        "LoD/1.10": [
          "ProcessTerminationHandler|0x401CCF",
          "InitializeGlobalConstructors|0x401C80"
        ],
        "LoD/1.11": [
          "ProcessTerminationHandler|0x401CCF",
          "InitializeGlobalConstructors|0x401C80"
        ],
        "LoD/1.11b": [
          "InitializeGlobalConstructors|0x401C80",
          "ProcessTerminationHandler|0x401CCF"
        ],
        "LoD/1.12a": [
          "InitializeGlobalConstructors|0x401C80",
          "ProcessTerminationHandler|0x401CCF"
        ],
        "LoD/1.13c": [
          "InitializeGlobalConstructors|0x401C80",
          "ProcessTerminationHandler|0x401CCF"
        ],
        "LoD/1.13d": [
          "InitializeGlobalConstructors|0x401C80",
          "ProcessTerminationHandler|0x401CCF"
        ],
        "LoD/1.14a": [
          "InitializeGlobalConstructors|0x401C80",
          "ProcessTerminationHandler|0x401CCF"
        ],
        "LoD/1.14b": [
          "InitializeGlobalConstructors|0x401C80",
          "ProcessTerminationHandler|0x401CCF"
        ],
        "LoD/1.14c": [
          "InitializeGlobalConstructors|0x401C80",
          "ProcessTerminationHandler|0x401CCF"
        ],
        "LoD/1.14d": [
          "ProcessTerminationHandler|0x401CCF",
          "InitializeGlobalConstructors|0x401C80"
        ]
      },
      "instruction_counts": {
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
        "LoD/1.13d": 12,
        "LoD/1.14a": 12,
        "LoD/1.14b": 12,
        "LoD/1.14c": 12,
        "LoD/1.14d": 12
      },
      "stack_frame_sizes": {
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
        "LoD/1.13d": 12,
        "LoD/1.14a": 12,
        "LoD/1.14b": 12,
        "LoD/1.14c": 12,
        "LoD/1.14d": 12
      },
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
        "LoD/1.13d": 6,
        "LoD/1.14a": 6,
        "LoD/1.14b": 6,
        "LoD/1.14c": 6,
        "LoD/1.14d": 6
      },
      "loop_counts": {
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
        "LoD/1.13d": 1,
        "LoD/1.14a": 1,
        "LoD/1.14b": 1,
        "LoD/1.14c": 1,
        "LoD/1.14d": 1
      },
      "mnemonic_hashes": {
        "LoD/1.07": "f1060dff4c8b86b7cd32c42f8f136fb6",
        "LoD/1.08": "f1060dff4c8b86b7cd32c42f8f136fb6",
        "LoD/1.09": "f1060dff4c8b86b7cd32c42f8f136fb6",
        "LoD/1.09b": "f1060dff4c8b86b7cd32c42f8f136fb6",
        "LoD/1.09d": "f1060dff4c8b86b7cd32c42f8f136fb6",
        "LoD/1.10": "f1060dff4c8b86b7cd32c42f8f136fb6",
        "LoD/1.11": "f1060dff4c8b86b7cd32c42f8f136fb6",
        "LoD/1.11b": "f1060dff4c8b86b7cd32c42f8f136fb6",
        "LoD/1.12a": "f1060dff4c8b86b7cd32c42f8f136fb6",
        "LoD/1.13c": "f1060dff4c8b86b7cd32c42f8f136fb6",
        "LoD/1.13d": "f1060dff4c8b86b7cd32c42f8f136fb6",
        "LoD/1.14a": "f1060dff4c8b86b7cd32c42f8f136fb6",
        "LoD/1.14b": "f1060dff4c8b86b7cd32c42f8f136fb6",
        "LoD/1.14c": "f1060dff4c8b86b7cd32c42f8f136fb6",
        "LoD/1.14d": "f1060dff4c8b86b7cd32c42f8f136fb6"
      },
      "globals": {
        "LoD/1.07": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ],
        "LoD/1.08": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ],
        "LoD/1.09": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ],
        "LoD/1.09b": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ],
        "LoD/1.09d": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ],
        "LoD/1.10": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ],
        "LoD/1.11": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ],
        "LoD/1.11b": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ],
        "LoD/1.12a": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ],
        "LoD/1.13c": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ],
        "LoD/1.13d": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ],
        "LoD/1.14a": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ],
        "LoD/1.14b": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ],
        "LoD/1.14c": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ],
        "LoD/1.14d": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ]
      }
    },
    "diablo ii.exe_MNE_41f8d80d32bc": {
      "addresses": {
        "LoD/1.07": "0x00401D82",
        "LoD/1.08": "0x00401D82",
        "LoD/1.09": "0x00401D82",
        "LoD/1.09b": "0x00401D82",
        "LoD/1.09d": "0x00401D82",
        "LoD/1.10": "0x00401D82",
        "LoD/1.11": "0x00401D82",
        "LoD/1.11b": "0x00401D82",
        "LoD/1.12a": "0x00401D82",
        "LoD/1.13c": "0x00401D82",
        "LoD/1.13d": "0x00401D82",
        "LoD/1.14a": "0x00401D82",
        "LoD/1.14b": "0x00401D82",
        "LoD/1.14c": "0x00401D82",
        "LoD/1.14d": "0x00401D82"
      },
      "rvas": {
        "LoD/1.07": "0x1D82",
        "LoD/1.08": "0x1D82",
        "LoD/1.09": "0x1D82",
        "LoD/1.09b": "0x1D82",
        "LoD/1.09d": "0x1D82",
        "LoD/1.10": "0x1D82",
        "LoD/1.11": "0x1D82",
        "LoD/1.11b": "0x1D82",
        "LoD/1.12a": "0x1D82",
        "LoD/1.13c": "0x1D82",
        "LoD/1.13d": "0x1D82",
        "LoD/1.14a": "0x1D82",
        "LoD/1.14b": "0x1D82",
        "LoD/1.14c": "0x1D82",
        "LoD/1.14d": "0x1D82"
      },
      "sizes": {
        "LoD/1.07": 321,
        "LoD/1.08": 321,
        "LoD/1.09": 321,
        "LoD/1.09b": 321,
        "LoD/1.09d": 321,
        "LoD/1.10": 321,
        "LoD/1.11": 321,
        "LoD/1.11b": 321,
        "LoD/1.12a": 321,
        "LoD/1.13c": 321,
        "LoD/1.13d": 321,
        "LoD/1.14a": 321,
        "LoD/1.14b": 321,
        "LoD/1.14c": 321,
        "LoD/1.14d": 321
      },
      "return_type": "LONG",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:41f8d80d32bced9021e52454a2115142",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "41f8d80d32bced9021e52454a2115142",
        "CFG": "1083f5d6440b72c4249e3f9668fe9e20",
        "PRO": "8a9092ef4379e1004af4fb44eeae13cc",
        "CAL": null,
        "CON": null,
        "APS": null
      },
      "display_name": "FUN_00401d82",
      "callees": {
        "LoD/1.07": [
          "UnhandledExceptionFilter|0x14",
          "FUN_00401ec3|0x401EC3"
        ],
        "LoD/1.08": [
          "UnhandledExceptionFilter|0x14",
          "FUN_00401ec3|0x401EC3"
        ],
        "LoD/1.09": [
          "FUN_00401ec3|0x401EC3",
          "UnhandledExceptionFilter|0x14"
        ],
        "LoD/1.09b": [
          "UnhandledExceptionFilter|0x14",
          "FUN_00401ec3|0x401EC3"
        ],
        "LoD/1.09d": [
          "FUN_00401ec3|0x401EC3",
          "UnhandledExceptionFilter|0x14"
        ],
        "LoD/1.10": [
          "FUN_00401ec3|0x401EC3",
          "UnhandledExceptionFilter|0x14"
        ],
        "LoD/1.11": [
          "UnhandledExceptionFilter|0x14",
          "FUN_00401ec3|0x401EC3"
        ],
        "LoD/1.11b": [
          "UnhandledExceptionFilter|0x14",
          "FUN_00401ec3|0x401EC3"
        ],
        "LoD/1.12a": [
          "UnhandledExceptionFilter|0x14",
          "FUN_00401ec3|0x401EC3"
        ],
        "LoD/1.13c": [
          "UnhandledExceptionFilter|0x14",
          "FUN_00401ec3|0x401EC3"
        ],
        "LoD/1.13d": [
          "FUN_00401ec3|0x401EC3",
          "UnhandledExceptionFilter|0x14"
        ],
        "LoD/1.14a": [
          "FUN_00401ec3|0x401EC3",
          "UnhandledExceptionFilter|0x14"
        ],
        "LoD/1.14b": [
          "UnhandledExceptionFilter|0x14",
          "FUN_00401ec3|0x401EC3"
        ],
        "LoD/1.14c": [
          "FUN_00401ec3|0x401EC3",
          "UnhandledExceptionFilter|0x14"
        ],
        "LoD/1.14d": [
          "UnhandledExceptionFilter|0x14",
          "FUN_00401ec3|0x401EC3"
        ]
      },
      "callers": {
        "LoD/1.07": [
          "entry|0x4014E3"
        ],
        "LoD/1.08": [
          "entry|0x4014E3"
        ],
        "LoD/1.09": [
          "entry|0x4014E3"
        ],
        "LoD/1.09b": [
          "entry|0x4014E3"
        ],
        "LoD/1.09d": [
          "entry|0x4014E3"
        ],
        "LoD/1.10": [
          "entry|0x4014E3"
        ],
        "LoD/1.11": [
          "entry|0x4014E3"
        ],
        "LoD/1.11b": [
          "entry|0x4014E3"
        ],
        "LoD/1.12a": [
          "entry|0x4014E3"
        ],
        "LoD/1.13c": [
          "entry|0x4014E3"
        ],
        "LoD/1.13d": [
          "entry|0x4014E3"
        ],
        "LoD/1.14a": [
          "entry|0x4014E3"
        ],
        "LoD/1.14b": [
          "entry|0x4014E3"
        ],
        "LoD/1.14c": [
          "entry|0x4014E3"
        ],
        "LoD/1.14d": [
          "entry|0x4014E3"
        ]
      },
      "instruction_counts": {
        "LoD/1.07": 89,
        "LoD/1.08": 89,
        "LoD/1.09": 89,
        "LoD/1.09b": 89,
        "LoD/1.09d": 89,
        "LoD/1.10": 89,
        "LoD/1.11": 89,
        "LoD/1.11b": 89,
        "LoD/1.12a": 89,
        "LoD/1.13c": 89,
        "LoD/1.13d": 89,
        "LoD/1.14a": 89,
        "LoD/1.14b": 89,
        "LoD/1.14c": 89,
        "LoD/1.14d": 89
      },
      "stack_frame_sizes": {
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
        "LoD/1.13d": 12,
        "LoD/1.14a": 12,
        "LoD/1.14b": 12,
        "LoD/1.14c": 12,
        "LoD/1.14d": 12
      },
      "basic_block_counts": {
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
        "LoD/1.13d": 29,
        "LoD/1.14a": 29,
        "LoD/1.14b": 29,
        "LoD/1.14c": 29,
        "LoD/1.14d": 29
      },
      "loop_counts": {
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
        "LoD/1.13d": 1,
        "LoD/1.14a": 1,
        "LoD/1.14b": 1,
        "LoD/1.14c": 1,
        "LoD/1.14d": 1
      },
      "mnemonic_hashes": {
        "LoD/1.07": "41f8d80d32bced9021e52454a2115142",
        "LoD/1.08": "41f8d80d32bced9021e52454a2115142",
        "LoD/1.09": "41f8d80d32bced9021e52454a2115142",
        "LoD/1.09b": "41f8d80d32bced9021e52454a2115142",
        "LoD/1.09d": "41f8d80d32bced9021e52454a2115142",
        "LoD/1.10": "41f8d80d32bced9021e52454a2115142",
        "LoD/1.11": "41f8d80d32bced9021e52454a2115142",
        "LoD/1.11b": "41f8d80d32bced9021e52454a2115142",
        "LoD/1.12a": "41f8d80d32bced9021e52454a2115142",
        "LoD/1.13c": "41f8d80d32bced9021e52454a2115142",
        "LoD/1.13d": "41f8d80d32bced9021e52454a2115142",
        "LoD/1.14a": "41f8d80d32bced9021e52454a2115142",
        "LoD/1.14b": "41f8d80d32bced9021e52454a2115142",
        "LoD/1.14c": "41f8d80d32bced9021e52454a2115142",
        "LoD/1.14d": "41f8d80d32bced9021e52454a2115142"
      },
      "constants": {
        "LoD/1.07": [
          4219224
        ],
        "LoD/1.08": [
          4219224
        ],
        "LoD/1.09": [
          4219224
        ],
        "LoD/1.09b": [
          4219224
        ],
        "LoD/1.09d": [
          4219224
        ],
        "LoD/1.10": [
          4219224
        ],
        "LoD/1.11": [
          4219224
        ],
        "LoD/1.11b": [
          4219224
        ],
        "LoD/1.12a": [
          4219224
        ],
        "LoD/1.13c": [
          4219224
        ],
        "LoD/1.13d": [
          4219224
        ],
        "LoD/1.14a": [
          4219224
        ],
        "LoD/1.14b": [
          4219224
        ],
        "LoD/1.14c": [
          4219224
        ],
        "LoD/1.14d": [
          4219224
        ]
      },
      "globals": {
        "LoD/1.07": [
          "0xFFFFFFFFFFC00004|",
          "0x6510|DAT_00406510",
          "0xFFFFFFFFFFC00008|",
          "0x61C8|DAT_004061c8",
          "0x61CC|DAT_004061cc",
          "0x617C|DAT_0040617c",
          "0x6188|DAT_00406188",
          "0x61D4|DAT_004061d4",
          "0x504C|PTR_UnhandledExceptionFilter_0040504c"
        ],
        "LoD/1.08": [
          "0xFFFFFFFFFFC00004|",
          "0x6510|DAT_00406510",
          "0xFFFFFFFFFFC00008|",
          "0x61C8|DAT_004061c8",
          "0x61CC|DAT_004061cc",
          "0x617C|DAT_0040617c",
          "0x6188|DAT_00406188",
          "0x61D4|DAT_004061d4",
          "0x504C|PTR_UnhandledExceptionFilter_0040504c"
        ],
        "LoD/1.09": [
          "0xFFFFFFFFFFC00004|",
          "0x6510|DAT_00406510",
          "0xFFFFFFFFFFC00008|",
          "0x61C8|DAT_004061c8",
          "0x61CC|DAT_004061cc",
          "0x617C|DAT_0040617c",
          "0x6188|DAT_00406188",
          "0x61D4|DAT_004061d4",
          "0x504C|PTR_UnhandledExceptionFilter_0040504c"
        ],
        "LoD/1.09b": [
          "0xFFFFFFFFFFC00004|",
          "0x6510|DAT_00406510",
          "0xFFFFFFFFFFC00008|",
          "0x61C8|DAT_004061c8",
          "0x61CC|DAT_004061cc",
          "0x617C|DAT_0040617c",
          "0x6188|DAT_00406188",
          "0x61D4|DAT_004061d4",
          "0x504C|PTR_UnhandledExceptionFilter_0040504c"
        ],
        "LoD/1.09d": [
          "0xFFFFFFFFFFC00004|",
          "0x6510|DAT_00406510",
          "0xFFFFFFFFFFC00008|",
          "0x61C8|DAT_004061c8",
          "0x61CC|DAT_004061cc",
          "0x617C|DAT_0040617c",
          "0x6188|DAT_00406188",
          "0x61D4|DAT_004061d4",
          "0x504C|PTR_UnhandledExceptionFilter_0040504c"
        ],
        "LoD/1.10": [
          "0xFFFFFFFFFFC00004|",
          "0x6510|DAT_00406510",
          "0xFFFFFFFFFFC00008|",
          "0x61C8|DAT_004061c8",
          "0x61CC|DAT_004061cc",
          "0x617C|DAT_0040617c",
          "0x6188|DAT_00406188",
          "0x61D4|DAT_004061d4",
          "0x504C|PTR_UnhandledExceptionFilter_0040504c"
        ],
        "LoD/1.11": [
          "0xFFFFFFFFFFC00004|",
          "0x6510|DAT_00406510",
          "0xFFFFFFFFFFC00008|",
          "0x61C8|DAT_004061c8",
          "0x61CC|DAT_004061cc",
          "0x617C|DAT_0040617c",
          "0x6188|DAT_00406188",
          "0x61D4|DAT_004061d4",
          "0x504C|PTR_UnhandledExceptionFilter_0040504c"
        ],
        "LoD/1.11b": [
          "0xFFFFFFFFFFC00004|",
          "0x6510|DAT_00406510",
          "0xFFFFFFFFFFC00008|",
          "0x61C8|DAT_004061c8",
          "0x61CC|DAT_004061cc",
          "0x617C|DAT_0040617c",
          "0x6188|DAT_00406188",
          "0x61D4|DAT_004061d4",
          "0x504C|PTR_UnhandledExceptionFilter_0040504c"
        ],
        "LoD/1.12a": [
          "0xFFFFFFFFFFC00004|",
          "0x6510|DAT_00406510",
          "0xFFFFFFFFFFC00008|",
          "0x61C8|DAT_004061c8",
          "0x61CC|DAT_004061cc",
          "0x617C|DAT_0040617c",
          "0x6188|DAT_00406188",
          "0x61D4|DAT_004061d4",
          "0x504C|PTR_UnhandledExceptionFilter_0040504c"
        ],
        "LoD/1.13c": [
          "0xFFFFFFFFFFC00004|",
          "0x6510|DAT_00406510",
          "0xFFFFFFFFFFC00008|",
          "0x61C8|DAT_004061c8",
          "0x61CC|DAT_004061cc",
          "0x617C|DAT_0040617c",
          "0x6188|DAT_00406188",
          "0x61D4|DAT_004061d4",
          "0x504C|PTR_UnhandledExceptionFilter_0040504c"
        ],
        "LoD/1.13d": [
          "0xFFFFFFFFFFC00004|",
          "0x6510|DAT_00406510",
          "0xFFFFFFFFFFC00008|",
          "0x61C8|DAT_004061c8",
          "0x61CC|DAT_004061cc",
          "0x617C|DAT_0040617c",
          "0x6188|DAT_00406188",
          "0x61D4|DAT_004061d4",
          "0x504C|PTR_UnhandledExceptionFilter_0040504c"
        ],
        "LoD/1.14a": [
          "0xFFFFFFFFFFC00004|",
          "0x6510|DAT_00406510",
          "0xFFFFFFFFFFC00008|",
          "0x61C8|DAT_004061c8",
          "0x61CC|DAT_004061cc",
          "0x617C|DAT_0040617c",
          "0x6188|DAT_00406188",
          "0x61D4|DAT_004061d4",
          "0x504C|PTR_UnhandledExceptionFilter_0040504c"
        ],
        "LoD/1.14b": [
          "0xFFFFFFFFFFC00004|",
          "0x6510|DAT_00406510",
          "0xFFFFFFFFFFC00008|",
          "0x61C8|DAT_004061c8",
          "0x61CC|DAT_004061cc",
          "0x617C|DAT_0040617c",
          "0x6188|DAT_00406188",
          "0x61D4|DAT_004061d4",
          "0x504C|PTR_UnhandledExceptionFilter_0040504c"
        ],
        "LoD/1.14c": [
          "0xFFFFFFFFFFC00004|",
          "0x6510|DAT_00406510",
          "0xFFFFFFFFFFC00008|",
          "0x61C8|DAT_004061c8",
          "0x61CC|DAT_004061cc",
          "0x617C|DAT_0040617c",
          "0x6188|DAT_00406188",
          "0x61D4|DAT_004061d4",
          "0x504C|PTR_UnhandledExceptionFilter_0040504c"
        ],
        "LoD/1.14d": [
          "0xFFFFFFFFFFC00004|",
          "0x6510|DAT_00406510",
          "0xFFFFFFFFFFC00008|",
          "0x61C8|DAT_004061c8",
          "0x61CC|DAT_004061cc",
          "0x617C|DAT_0040617c",
          "0x6188|DAT_00406188",
          "0x61D4|DAT_004061d4",
          "0x504C|PTR_UnhandledExceptionFilter_0040504c"
        ]
      }
    },
    "diablo ii.exe_MNE_a073910011de": {
      "addresses": {
        "LoD/1.07": "0x00401EC3",
        "LoD/1.08": "0x00401EC3",
        "LoD/1.09": "0x00401EC3",
        "LoD/1.09b": "0x00401EC3",
        "LoD/1.09d": "0x00401EC3",
        "LoD/1.10": "0x00401EC3",
        "LoD/1.11": "0x00401EC3",
        "LoD/1.11b": "0x00401EC3",
        "LoD/1.12a": "0x00401EC3",
        "LoD/1.13c": "0x00401EC3",
        "LoD/1.13d": "0x00401EC3",
        "LoD/1.14a": "0x00401EC3",
        "LoD/1.14b": "0x00401EC3",
        "LoD/1.14c": "0x00401EC3",
        "LoD/1.14d": "0x00401EC3"
      },
      "rvas": {
        "LoD/1.07": "0x1EC3",
        "LoD/1.08": "0x1EC3",
        "LoD/1.09": "0x1EC3",
        "LoD/1.09b": "0x1EC3",
        "LoD/1.09d": "0x1EC3",
        "LoD/1.10": "0x1EC3",
        "LoD/1.11": "0x1EC3",
        "LoD/1.11b": "0x1EC3",
        "LoD/1.12a": "0x1EC3",
        "LoD/1.13c": "0x1EC3",
        "LoD/1.13d": "0x1EC3",
        "LoD/1.14a": "0x1EC3",
        "LoD/1.14b": "0x1EC3",
        "LoD/1.14c": "0x1EC3",
        "LoD/1.14d": "0x1EC3"
      },
      "sizes": {
        "LoD/1.07": 67,
        "LoD/1.08": 67,
        "LoD/1.09": 67,
        "LoD/1.09b": 67,
        "LoD/1.09d": 67,
        "LoD/1.10": 67,
        "LoD/1.11": 67,
        "LoD/1.11b": 67,
        "LoD/1.12a": 67,
        "LoD/1.13c": 67,
        "LoD/1.13d": 67,
        "LoD/1.14a": 67,
        "LoD/1.14b": 67,
        "LoD/1.14c": 67,
        "LoD/1.14d": 67
      },
      "return_type": "int *",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:a073910011def1e1e9e25496ccd37ec0",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "a073910011def1e1e9e25496ccd37ec0",
        "CFG": "1cf28c92c8a3817ec2934904c82e8c98",
        "PRO": "26f5cd7217d8e31b5ca266955f9c63f2",
        "CAL": null,
        "CON": null,
        "APS": null
      },
      "display_name": "FUN_00401ec3",
      "callers": {
        "LoD/1.07": [
          "FUN_00401d82|0x401D82"
        ],
        "LoD/1.08": [
          "FUN_00401d82|0x401D82"
        ],
        "LoD/1.09": [
          "FUN_00401d82|0x401D82"
        ],
        "LoD/1.09b": [
          "FUN_00401d82|0x401D82"
        ],
        "LoD/1.09d": [
          "FUN_00401d82|0x401D82"
        ],
        "LoD/1.10": [
          "FUN_00401d82|0x401D82"
        ],
        "LoD/1.11": [
          "FUN_00401d82|0x401D82"
        ],
        "LoD/1.11b": [
          "FUN_00401d82|0x401D82"
        ],
        "LoD/1.12a": [
          "FUN_00401d82|0x401D82"
        ],
        "LoD/1.13c": [
          "FUN_00401d82|0x401D82"
        ],
        "LoD/1.13d": [
          "FUN_00401d82|0x401D82"
        ],
        "LoD/1.14a": [
          "FUN_00401d82|0x401D82"
        ],
        "LoD/1.14b": [
          "FUN_00401d82|0x401D82"
        ],
        "LoD/1.14c": [
          "FUN_00401d82|0x401D82"
        ],
        "LoD/1.14d": [
          "FUN_00401d82|0x401D82"
        ]
      },
      "instruction_counts": {
        "LoD/1.07": 22,
        "LoD/1.08": 22,
        "LoD/1.09": 22,
        "LoD/1.09b": 22,
        "LoD/1.09d": 22,
        "LoD/1.10": 22,
        "LoD/1.11": 22,
        "LoD/1.11b": 22,
        "LoD/1.12a": 22,
        "LoD/1.13c": 22,
        "LoD/1.13d": 22,
        "LoD/1.14a": 22,
        "LoD/1.14b": 22,
        "LoD/1.14c": 22,
        "LoD/1.14d": 22
      },
      "stack_frame_sizes": {
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
        "LoD/1.13d": 8,
        "LoD/1.14a": 8,
        "LoD/1.14b": 8,
        "LoD/1.14c": 8,
        "LoD/1.14d": 8
      },
      "basic_block_counts": {
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
        "LoD/1.13d": 8,
        "LoD/1.14a": 8,
        "LoD/1.14b": 8,
        "LoD/1.14c": 8,
        "LoD/1.14d": 8
      },
      "loop_counts": {
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
        "LoD/1.13d": 1,
        "LoD/1.14a": 1,
        "LoD/1.14b": 1,
        "LoD/1.14c": 1,
        "LoD/1.14d": 1
      },
      "mnemonic_hashes": {
        "LoD/1.07": "a073910011def1e1e9e25496ccd37ec0",
        "LoD/1.08": "a073910011def1e1e9e25496ccd37ec0",
        "LoD/1.09": "a073910011def1e1e9e25496ccd37ec0",
        "LoD/1.09b": "a073910011def1e1e9e25496ccd37ec0",
        "LoD/1.09d": "a073910011def1e1e9e25496ccd37ec0",
        "LoD/1.10": "a073910011def1e1e9e25496ccd37ec0",
        "LoD/1.11": "a073910011def1e1e9e25496ccd37ec0",
        "LoD/1.11b": "a073910011def1e1e9e25496ccd37ec0",
        "LoD/1.12a": "a073910011def1e1e9e25496ccd37ec0",
        "LoD/1.13c": "a073910011def1e1e9e25496ccd37ec0",
        "LoD/1.13d": "a073910011def1e1e9e25496ccd37ec0",
        "LoD/1.14a": "a073910011def1e1e9e25496ccd37ec0",
        "LoD/1.14b": "a073910011def1e1e9e25496ccd37ec0",
        "LoD/1.14c": "a073910011def1e1e9e25496ccd37ec0",
        "LoD/1.14d": "a073910011def1e1e9e25496ccd37ec0"
      },
      "constants": {
        "LoD/1.07": [
          4219216
        ],
        "LoD/1.08": [
          4219216
        ],
        "LoD/1.09": [
          4219216
        ],
        "LoD/1.09b": [
          4219216
        ],
        "LoD/1.09d": [
          4219216
        ],
        "LoD/1.10": [
          4219216
        ],
        "LoD/1.11": [
          4219216
        ],
        "LoD/1.11b": [
          4219216
        ],
        "LoD/1.12a": [
          4219216
        ],
        "LoD/1.13c": [
          4219216
        ],
        "LoD/1.13d": [
          4219216
        ],
        "LoD/1.14a": [
          4219216
        ],
        "LoD/1.14b": [
          4219216
        ],
        "LoD/1.14c": [
          4219216
        ],
        "LoD/1.14d": [
          4219216
        ]
      },
      "globals": {
        "LoD/1.07": [
          "0xFFFFFFFFFFC00004|",
          "0x61D0|DAT_004061d0",
          "0x6150|DAT_00406150",
          "0x61C8|DAT_004061c8",
          "0x615C|DAT_0040615c",
          "0x6168|DAT_00406168"
        ],
        "LoD/1.08": [
          "0xFFFFFFFFFFC00004|",
          "0x61D0|DAT_004061d0",
          "0x6150|DAT_00406150",
          "0x61C8|DAT_004061c8",
          "0x615C|DAT_0040615c",
          "0x6168|DAT_00406168"
        ],
        "LoD/1.09": [
          "0xFFFFFFFFFFC00004|",
          "0x61D0|DAT_004061d0",
          "0x6150|DAT_00406150",
          "0x61C8|DAT_004061c8",
          "0x615C|DAT_0040615c",
          "0x6168|DAT_00406168"
        ],
        "LoD/1.09b": [
          "0xFFFFFFFFFFC00004|",
          "0x61D0|DAT_004061d0",
          "0x6150|DAT_00406150",
          "0x61C8|DAT_004061c8",
          "0x615C|DAT_0040615c",
          "0x6168|DAT_00406168"
        ],
        "LoD/1.09d": [
          "0xFFFFFFFFFFC00004|",
          "0x61D0|DAT_004061d0",
          "0x6150|DAT_00406150",
          "0x61C8|DAT_004061c8",
          "0x615C|DAT_0040615c",
          "0x6168|DAT_00406168"
        ],
        "LoD/1.10": [
          "0xFFFFFFFFFFC00004|",
          "0x61D0|DAT_004061d0",
          "0x6150|DAT_00406150",
          "0x61C8|DAT_004061c8",
          "0x615C|DAT_0040615c",
          "0x6168|DAT_00406168"
        ],
        "LoD/1.11": [
          "0xFFFFFFFFFFC00004|",
          "0x61D0|DAT_004061d0",
          "0x6150|DAT_00406150",
          "0x61C8|DAT_004061c8",
          "0x615C|DAT_0040615c",
          "0x6168|DAT_00406168"
        ],
        "LoD/1.11b": [
          "0xFFFFFFFFFFC00004|",
          "0x61D0|DAT_004061d0",
          "0x6150|DAT_00406150",
          "0x61C8|DAT_004061c8",
          "0x615C|DAT_0040615c",
          "0x6168|DAT_00406168"
        ],
        "LoD/1.12a": [
          "0xFFFFFFFFFFC00004|",
          "0x61D0|DAT_004061d0",
          "0x6150|DAT_00406150",
          "0x61C8|DAT_004061c8",
          "0x615C|DAT_0040615c",
          "0x6168|DAT_00406168"
        ],
        "LoD/1.13c": [
          "0xFFFFFFFFFFC00004|",
          "0x61D0|DAT_004061d0",
          "0x6150|DAT_00406150",
          "0x61C8|DAT_004061c8",
          "0x615C|DAT_0040615c",
          "0x6168|DAT_00406168"
        ],
        "LoD/1.13d": [
          "0xFFFFFFFFFFC00004|",
          "0x61D0|DAT_004061d0",
          "0x6150|DAT_00406150",
          "0x61C8|DAT_004061c8",
          "0x615C|DAT_0040615c",
          "0x6168|DAT_00406168"
        ],
        "LoD/1.14a": [
          "0xFFFFFFFFFFC00004|",
          "0x61D0|DAT_004061d0",
          "0x6150|DAT_00406150",
          "0x61C8|DAT_004061c8",
          "0x615C|DAT_0040615c",
          "0x6168|DAT_00406168"
        ],
        "LoD/1.14b": [
          "0xFFFFFFFFFFC00004|",
          "0x61D0|DAT_004061d0",
          "0x6150|DAT_00406150",
          "0x61C8|DAT_004061c8",
          "0x615C|DAT_0040615c",
          "0x6168|DAT_00406168"
        ],
        "LoD/1.14c": [
          "0xFFFFFFFFFFC00004|",
          "0x61D0|DAT_004061d0",
          "0x6150|DAT_00406150",
          "0x61C8|DAT_004061c8",
          "0x615C|DAT_0040615c",
          "0x6168|DAT_00406168"
        ],
        "LoD/1.14d": [
          "0xFFFFFFFFFFC00004|",
          "0x61D0|DAT_004061d0",
          "0x6150|DAT_00406150",
          "0x61C8|DAT_004061c8",
          "0x615C|DAT_0040615c",
          "0x6168|DAT_00406168"
        ]
      }
    },
    "diablo ii.exe_MNE_93c4b717343a": {
      "addresses": {
        "LoD/1.07": "0x00401F06",
        "LoD/1.08": "0x00401F06",
        "LoD/1.09": "0x00401F06",
        "LoD/1.09b": "0x00401F06",
        "LoD/1.09d": "0x00401F06",
        "LoD/1.10": "0x00401F06",
        "LoD/1.11": "0x00401F06",
        "LoD/1.11b": "0x00401F06",
        "LoD/1.12a": "0x00401F06",
        "LoD/1.13c": "0x00401F06",
        "LoD/1.13d": "0x00401F06",
        "LoD/1.14a": "0x00401F06",
        "LoD/1.14b": "0x00401F06",
        "LoD/1.14c": "0x00401F06",
        "LoD/1.14d": "0x00401F06"
      },
      "rvas": {
        "LoD/1.07": "0x1F06",
        "LoD/1.08": "0x1F06",
        "LoD/1.09": "0x1F06",
        "LoD/1.09b": "0x1F06",
        "LoD/1.09d": "0x1F06",
        "LoD/1.10": "0x1F06",
        "LoD/1.11": "0x1F06",
        "LoD/1.11b": "0x1F06",
        "LoD/1.12a": "0x1F06",
        "LoD/1.13c": "0x1F06",
        "LoD/1.13d": "0x1F06",
        "LoD/1.14a": "0x1F06",
        "LoD/1.14b": "0x1F06",
        "LoD/1.14c": "0x1F06",
        "LoD/1.14d": "0x1F06"
      },
      "sizes": {
        "LoD/1.07": 88,
        "LoD/1.08": 88,
        "LoD/1.09": 88,
        "LoD/1.09b": 88,
        "LoD/1.09d": 88,
        "LoD/1.10": 88,
        "LoD/1.11": 88,
        "LoD/1.11b": 88,
        "LoD/1.12a": 88,
        "LoD/1.13c": 88,
        "LoD/1.13d": 88,
        "LoD/1.14a": 88,
        "LoD/1.14b": 88,
        "LoD/1.14c": 88,
        "LoD/1.14d": 88
      },
      "return_type": "byte *",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:93c4b717343abad7c0cd6bec07bb1588",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "93c4b717343abad7c0cd6bec07bb1588",
        "CFG": "46c9984789f3b338226be49d1e54fb70",
        "PRO": "c0da7238cea3536033ac5edd6a427b50",
        "CAL": null,
        "CON": null,
        "APS": null
      },
      "display_name": "FUN_00401f06",
      "callees": {
        "LoD/1.07": [
          "FUN_00402d8c|0x402D8C",
          "InitializeCodePageOnce|0x4019E6"
        ],
        "LoD/1.08": [
          "InitializeCodePageOnce|0x4019E6",
          "FUN_00402d8c|0x402D8C"
        ],
        "LoD/1.09": [
          "FUN_00402d8c|0x402D8C",
          "InitializeCodePageOnce|0x4019E6"
        ],
        "LoD/1.09b": [
          "FUN_00402d8c|0x402D8C",
          "InitializeCodePageOnce|0x4019E6"
        ],
        "LoD/1.09d": [
          "FUN_00402d8c|0x402D8C",
          "InitializeCodePageOnce|0x4019E6"
        ],
        "LoD/1.10": [
          "InitializeCodePageOnce|0x4019E6",
          "FUN_00402d8c|0x402D8C"
        ],
        "LoD/1.11": [
          "FUN_00402d8c|0x402D8C",
          "InitializeCodePageOnce|0x4019E6"
        ],
        "LoD/1.11b": [
          "FUN_00402d8c|0x402D8C",
          "InitializeCodePageOnce|0x4019E6"
        ],
        "LoD/1.12a": [
          "FUN_00402d8c|0x402D8C",
          "InitializeCodePageOnce|0x4019E6"
        ],
        "LoD/1.13c": [
          "InitializeCodePageOnce|0x4019E6",
          "FUN_00402d8c|0x402D8C"
        ],
        "LoD/1.13d": [
          "InitializeCodePageOnce|0x4019E6",
          "FUN_00402d8c|0x402D8C"
        ],
        "LoD/1.14a": [
          "FUN_00402d8c|0x402D8C",
          "InitializeCodePageOnce|0x4019E6"
        ],
        "LoD/1.14b": [
          "FUN_00402d8c|0x402D8C",
          "InitializeCodePageOnce|0x4019E6"
        ],
        "LoD/1.14c": [
          "FUN_00402d8c|0x402D8C",
          "InitializeCodePageOnce|0x4019E6"
        ],
        "LoD/1.14d": [
          "FUN_00402d8c|0x402D8C",
          "InitializeCodePageOnce|0x4019E6"
        ]
      },
      "callers": {
        "LoD/1.07": [
          "entry|0x4014E3"
        ],
        "LoD/1.08": [
          "entry|0x4014E3"
        ],
        "LoD/1.09": [
          "entry|0x4014E3"
        ],
        "LoD/1.09b": [
          "entry|0x4014E3"
        ],
        "LoD/1.09d": [
          "entry|0x4014E3"
        ],
        "LoD/1.10": [
          "entry|0x4014E3"
        ],
        "LoD/1.11": [
          "entry|0x4014E3"
        ],
        "LoD/1.11b": [
          "entry|0x4014E3"
        ],
        "LoD/1.12a": [
          "entry|0x4014E3"
        ],
        "LoD/1.13c": [
          "entry|0x4014E3"
        ],
        "LoD/1.13d": [
          "entry|0x4014E3"
        ],
        "LoD/1.14a": [
          "entry|0x4014E3"
        ],
        "LoD/1.14b": [
          "entry|0x4014E3"
        ],
        "LoD/1.14c": [
          "entry|0x4014E3"
        ],
        "LoD/1.14d": [
          "entry|0x4014E3"
        ]
      },
      "instruction_counts": {
        "LoD/1.07": 39,
        "LoD/1.08": 39,
        "LoD/1.09": 39,
        "LoD/1.09b": 39,
        "LoD/1.09d": 39,
        "LoD/1.10": 39,
        "LoD/1.11": 39,
        "LoD/1.11b": 39,
        "LoD/1.12a": 39,
        "LoD/1.13c": 39,
        "LoD/1.13d": 39,
        "LoD/1.14a": 39,
        "LoD/1.14b": 39,
        "LoD/1.14c": 39,
        "LoD/1.14d": 39
      },
      "stack_frame_sizes": {
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
        "LoD/1.13d": 4,
        "LoD/1.14a": 4,
        "LoD/1.14b": 4,
        "LoD/1.14c": 4,
        "LoD/1.14d": 4
      },
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
        "LoD/1.13d": 14,
        "LoD/1.14a": 14,
        "LoD/1.14b": 14,
        "LoD/1.14c": 14,
        "LoD/1.14d": 14
      },
      "loop_counts": {
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
        "LoD/1.13d": 4,
        "LoD/1.14a": 4,
        "LoD/1.14b": 4,
        "LoD/1.14c": 4,
        "LoD/1.14d": 4
      },
      "mnemonic_hashes": {
        "LoD/1.07": "93c4b717343abad7c0cd6bec07bb1588",
        "LoD/1.08": "93c4b717343abad7c0cd6bec07bb1588",
        "LoD/1.09": "93c4b717343abad7c0cd6bec07bb1588",
        "LoD/1.09b": "93c4b717343abad7c0cd6bec07bb1588",
        "LoD/1.09d": "93c4b717343abad7c0cd6bec07bb1588",
        "LoD/1.10": "93c4b717343abad7c0cd6bec07bb1588",
        "LoD/1.11": "93c4b717343abad7c0cd6bec07bb1588",
        "LoD/1.11b": "93c4b717343abad7c0cd6bec07bb1588",
        "LoD/1.12a": "93c4b717343abad7c0cd6bec07bb1588",
        "LoD/1.13c": "93c4b717343abad7c0cd6bec07bb1588",
        "LoD/1.13d": "93c4b717343abad7c0cd6bec07bb1588",
        "LoD/1.14a": "93c4b717343abad7c0cd6bec07bb1588",
        "LoD/1.14b": "93c4b717343abad7c0cd6bec07bb1588",
        "LoD/1.14c": "93c4b717343abad7c0cd6bec07bb1588",
        "LoD/1.14d": "93c4b717343abad7c0cd6bec07bb1588"
      },
      "globals": {
        "LoD/1.07": [
          "0x6788|g_fCodePageInitialized",
          "0x69C8|g_lpszCommandLine"
        ],
        "LoD/1.08": [
          "0x6788|g_fCodePageInitialized",
          "0x69C8|g_lpszCommandLine"
        ],
        "LoD/1.09": [
          "0x6788|g_fCodePageInitialized",
          "0x69C8|g_lpszCommandLine"
        ],
        "LoD/1.09b": [
          "0x6788|g_fCodePageInitialized",
          "0x69C8|g_lpszCommandLine"
        ],
        "LoD/1.09d": [
          "0x6788|g_fCodePageInitialized",
          "0x69C8|g_lpszCommandLine"
        ],
        "LoD/1.10": [
          "0x6788|g_fCodePageInitialized",
          "0x69C8|DAT_004069c8"
        ],
        "LoD/1.11": [
          "0x6788|g_fCodePageInitialized",
          "0x69C8|g_lpszCommandLine"
        ],
        "LoD/1.11b": [
          "0x6788|g_fCodePageInitialized",
          "0x69C8|g_lpszCommandLine"
        ],
        "LoD/1.12a": [
          "0x6788|g_fCodePageInitialized",
          "0x69C8|g_lpszCommandLine"
        ],
        "LoD/1.13c": [
          "0x6788|g_fCodePageInitialized",
          "0x69C8|g_lpszCommandLine"
        ],
        "LoD/1.13d": [
          "0x6788|g_fCodePageInitialized",
          "0x69C8|g_lpszCommandLine"
        ],
        "LoD/1.14a": [
          "0x6788|g_fCodePageInitialized",
          "0x69C8|g_lpszCommandLine"
        ],
        "LoD/1.14b": [
          "0x6788|g_fCodePageInitialized",
          "0x69C8|g_lpszCommandLine"
        ],
        "LoD/1.14c": [
          "0x6788|g_fCodePageInitialized",
          "0x69C8|g_lpszCommandLine"
        ],
        "LoD/1.14d": [
          "0x6788|g_fCodePageInitialized",
          "0x69C8|g_lpszCommandLine"
        ]
      }
    },
    "diablo ii.exe_InitializeEnvironmentVariables": {
      "addresses": {
        "LoD/1.07": "0x00401F5E",
        "LoD/1.08": "0x00401F5E",
        "LoD/1.09": "0x00401F5E",
        "LoD/1.09b": "0x00401F5E",
        "LoD/1.09d": "0x00401F5E",
        "LoD/1.10": "0x00401F5E",
        "LoD/1.11": "0x00401F5E",
        "LoD/1.11b": "0x00401F5E",
        "LoD/1.12a": "0x00401F5E",
        "LoD/1.13c": "0x00401F5E",
        "LoD/1.13d": "0x00401F5E",
        "LoD/1.14a": "0x00401F5E",
        "LoD/1.14b": "0x00401F5E",
        "LoD/1.14c": "0x00401F5E",
        "LoD/1.14d": "0x00401F5E"
      },
      "rvas": {
        "LoD/1.07": "0x1F5E",
        "LoD/1.08": "0x1F5E",
        "LoD/1.09": "0x1F5E",
        "LoD/1.09b": "0x1F5E",
        "LoD/1.09d": "0x1F5E",
        "LoD/1.10": "0x1F5E",
        "LoD/1.11": "0x1F5E",
        "LoD/1.11b": "0x1F5E",
        "LoD/1.12a": "0x1F5E",
        "LoD/1.13c": "0x1F5E",
        "LoD/1.13d": "0x1F5E",
        "LoD/1.14a": "0x1F5E",
        "LoD/1.14b": "0x1F5E",
        "LoD/1.14c": "0x1F5E",
        "LoD/1.14d": "0x1F5E"
      },
      "sizes": {
        "LoD/1.07": 185,
        "LoD/1.08": 185,
        "LoD/1.09": 185,
        "LoD/1.09b": 185,
        "LoD/1.09d": 185,
        "LoD/1.10": 185,
        "LoD/1.11": 185,
        "LoD/1.11b": 185,
        "LoD/1.12a": 185,
        "LoD/1.13c": 185,
        "LoD/1.13d": 185,
        "LoD/1.14a": 185,
        "LoD/1.14b": 185,
        "LoD/1.14c": 185,
        "LoD/1.14d": 185
      },
      "name": "InitializeEnvironmentVariables",
      "signature": "void InitializeEnvironmentVariables(void)",
      "calling_convention": "__stdcall",
      "return_type": "void",
      "comment": "Initialize environment variables by parsing command line arguments or environment data.\n\nAlgorithm:\n1. Check if initialization flag (DAT_1003cde8) is zero and call FUN_100217c1() if needed\n2. Count non-assignment entries by iterating through string array at DAT_1003c8b4\n3. Skip entries containing '=' character (assignment operators)\n4. Allocate memory for pointer array to hold (count + 1) string pointers\n5. Store allocated array pointer in global _DAT_1003c924\n6. Validate allocation succeeded, exit with error code 9 if failed\n7. Iterate through string array again, copying non-assignment entries\n8. For each valid entry, allocate buffer and copy string using FUN_10020190\n9. Increment array pointer after each successful copy\n10. Free original string data at DAT_1003c8b4 and set to NULL\n11. Null-terminate the new pointer array\n12. Set completion flag _DAT_1003cde4 to 1\n\nParameters:\nNone\n\nReturns:\nvoid - Function performs initialization and exits on allocation failure\n\nSpecial Cases:\n- Exit with AmsgExit(9) if memory allocation fails\n- Skip entries containing '=' character (environment variable assignments)\n- DAT_1003c8b4 contains original string data, freed after processing\n- _DAT_1003c924 stores the resulting array of string pointers\n- _DAT_1003cde4 flag indicates completion status\n\nMagic Numbers:\n0x9 (9) - Error exit code for memory allocation failure\n0x3D (61) - ASCII value for '=' character used to filter assignments",
      "name_source": "LoD/1.07",
      "method": "CAL",
      "index": "CAL:c16244a47f600858c95b60f915650b56",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "6e538b3bbbeec8f94bef058bdad701fe",
        "CFG": "126bb563d14d36809e55fa377ba7848b",
        "PRO": "5be54e361757f77c0c474905030db3e7",
        "CAL": "c16244a47f600858c95b60f915650b56",
        "CON": null,
        "APS": null
      },
      "callees": {
        "LoD/1.07": [
          "SmartFree|0x402DCE",
          "CopyStringOptimized|0x402E00",
          "AmsgExit|0x4015D9",
          "_strlen|0x401B80",
          "InitializeCodePageOnce|0x4019E6",
          "_malloc|0x402EF0"
        ],
        "LoD/1.08": [
          "InitializeCodePageOnce|0x4019E6",
          "CopyStringOptimized|0x402E00",
          "_strlen|0x401B80",
          "SmartFree|0x402DCE",
          "_malloc|0x402EF0",
          "AmsgExit|0x4015D9"
        ],
        "LoD/1.09": [
          "_strlen|0x401B80",
          "AmsgExit|0x4015D9",
          "SmartFree|0x402DCE",
          "CopyStringOptimized|0x402E00",
          "InitializeCodePageOnce|0x4019E6",
          "_malloc|0x402EF0"
        ],
        "LoD/1.09b": [
          "SmartFree|0x402DCE",
          "CopyStringOptimized|0x402E00",
          "_strlen|0x401B80",
          "_malloc|0x402EF0",
          "InitializeCodePageOnce|0x4019E6",
          "AmsgExit|0x4015D9"
        ],
        "LoD/1.09d": [
          "_malloc|0x402EF0",
          "_strlen|0x401B80",
          "InitializeCodePageOnce|0x4019E6",
          "AmsgExit|0x4015D9",
          "SmartFree|0x402DCE",
          "CopyStringOptimized|0x402E00"
        ],
        "LoD/1.10": [
          "CopyStringOptimized|0x402E00",
          "SmartFree|0x402DCE",
          "InitializeCodePageOnce|0x4019E6",
          "AmsgExit|0x4015D9",
          "_strlen|0x401B80",
          "_malloc|0x402EF0"
        ],
        "LoD/1.11": [
          "InitializeCodePageOnce|0x4019E6",
          "_malloc|0x402EF0",
          "SmartFree|0x402DCE",
          "CopyStringOptimized|0x402E00",
          "_strlen|0x401B80",
          "AmsgExit|0x4015D9"
        ],
        "LoD/1.11b": [
          "_strlen|0x401B80",
          "SmartFree|0x402DCE",
          "AmsgExit|0x4015D9",
          "CopyStringOptimized|0x402E00",
          "_malloc|0x402EF0",
          "InitializeCodePageOnce|0x4019E6"
        ],
        "LoD/1.12a": [
          "CopyStringOptimized|0x402E00",
          "_strlen|0x401B80",
          "SmartFree|0x402DCE",
          "_malloc|0x402EF0",
          "AmsgExit|0x4015D9",
          "InitializeCodePageOnce|0x4019E6"
        ],
        "LoD/1.13c": [
          "_malloc|0x402EF0",
          "SmartFree|0x402DCE",
          "AmsgExit|0x4015D9",
          "CopyStringOptimized|0x402E00",
          "InitializeCodePageOnce|0x4019E6",
          "_strlen|0x401B80"
        ],
        "LoD/1.13d": [
          "_malloc|0x402EF0",
          "CopyStringOptimized|0x402E00",
          "_strlen|0x401B80",
          "AmsgExit|0x4015D9",
          "InitializeCodePageOnce|0x4019E6",
          "SmartFree|0x402DCE"
        ],
        "LoD/1.14a": [
          "AmsgExit|0x4015D9",
          "CopyStringOptimized|0x402E00",
          "_malloc|0x402EF0",
          "InitializeCodePageOnce|0x4019E6",
          "_strlen|0x401B80",
          "SmartFree|0x402DCE"
        ],
        "LoD/1.14b": [
          "_malloc|0x402EF0",
          "CopyStringOptimized|0x402E00",
          "SmartFree|0x402DCE",
          "AmsgExit|0x4015D9",
          "_strlen|0x401B80",
          "InitializeCodePageOnce|0x4019E6"
        ],
        "LoD/1.14c": [
          "SmartFree|0x402DCE",
          "_strlen|0x401B80",
          "_malloc|0x402EF0",
          "AmsgExit|0x4015D9",
          "CopyStringOptimized|0x402E00",
          "InitializeCodePageOnce|0x4019E6"
        ],
        "LoD/1.14d": [
          "_malloc|0x402EF0",
          "CopyStringOptimized|0x402E00",
          "SmartFree|0x402DCE",
          "InitializeCodePageOnce|0x4019E6",
          "AmsgExit|0x4015D9",
          "_strlen|0x401B80"
        ]
      },
      "callers": {
        "LoD/1.07": [
          "entry|0x4014E3"
        ],
        "LoD/1.08": [
          "entry|0x4014E3"
        ],
        "LoD/1.09": [
          "entry|0x4014E3"
        ],
        "LoD/1.09b": [
          "entry|0x4014E3"
        ],
        "LoD/1.09d": [
          "entry|0x4014E3"
        ],
        "LoD/1.10": [
          "entry|0x4014E3"
        ],
        "LoD/1.11": [
          "entry|0x4014E3"
        ],
        "LoD/1.11b": [
          "entry|0x4014E3"
        ],
        "LoD/1.12a": [
          "entry|0x4014E3"
        ],
        "LoD/1.13c": [
          "entry|0x4014E3"
        ],
        "LoD/1.13d": [
          "entry|0x4014E3"
        ],
        "LoD/1.14a": [
          "entry|0x4014E3"
        ],
        "LoD/1.14b": [
          "entry|0x4014E3"
        ],
        "LoD/1.14c": [
          "entry|0x4014E3"
        ],
        "LoD/1.14d": [
          "entry|0x4014E3"
        ]
      },
      "instruction_counts": {
        "LoD/1.07": 71,
        "LoD/1.08": 71,
        "LoD/1.09": 71,
        "LoD/1.09b": 71,
        "LoD/1.09d": 71,
        "LoD/1.10": 71,
        "LoD/1.11": 71,
        "LoD/1.11b": 71,
        "LoD/1.12a": 71,
        "LoD/1.13c": 71,
        "LoD/1.13d": 71,
        "LoD/1.14a": 71,
        "LoD/1.14b": 71,
        "LoD/1.14c": 71,
        "LoD/1.14d": 71
      },
      "stack_frame_sizes": {
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
        "LoD/1.13d": 4,
        "LoD/1.14a": 4,
        "LoD/1.14b": 4,
        "LoD/1.14c": 4,
        "LoD/1.14d": 4
      },
      "basic_block_counts": {
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
        "LoD/1.13d": 18,
        "LoD/1.14a": 18,
        "LoD/1.14b": 18,
        "LoD/1.14c": 18,
        "LoD/1.14d": 18
      },
      "loop_counts": {
        "LoD/1.07": 2,
        "LoD/1.08": 2,
        "LoD/1.09": 2,
        "LoD/1.09b": 2,
        "LoD/1.09d": 2,
        "LoD/1.10": 2,
        "LoD/1.11": 2,
        "LoD/1.11b": 2,
        "LoD/1.12a": 2,
        "LoD/1.13c": 2,
        "LoD/1.13d": 2,
        "LoD/1.14a": 2,
        "LoD/1.14b": 2,
        "LoD/1.14c": 2,
        "LoD/1.14d": 2
      },
      "mnemonic_hashes": {
        "LoD/1.07": "6e538b3bbbeec8f94bef058bdad701fe",
        "LoD/1.08": "6e538b3bbbeec8f94bef058bdad701fe",
        "LoD/1.09": "6e538b3bbbeec8f94bef058bdad701fe",
        "LoD/1.09b": "6e538b3bbbeec8f94bef058bdad701fe",
        "LoD/1.09d": "6e538b3bbbeec8f94bef058bdad701fe",
        "LoD/1.10": "6e538b3bbbeec8f94bef058bdad701fe",
        "LoD/1.11": "6e538b3bbbeec8f94bef058bdad701fe",
        "LoD/1.11b": "6e538b3bbbeec8f94bef058bdad701fe",
        "LoD/1.12a": "6e538b3bbbeec8f94bef058bdad701fe",
        "LoD/1.13c": "6e538b3bbbeec8f94bef058bdad701fe",
        "LoD/1.13d": "6e538b3bbbeec8f94bef058bdad701fe",
        "LoD/1.14a": "6e538b3bbbeec8f94bef058bdad701fe",
        "LoD/1.14b": "6e538b3bbbeec8f94bef058bdad701fe",
        "LoD/1.14c": "6e538b3bbbeec8f94bef058bdad701fe",
        "LoD/1.14d": "6e538b3bbbeec8f94bef058bdad701fe"
      },
      "globals": {
        "LoD/1.07": [
          "0x6788|g_fCodePageInitialized",
          "0x64B4|g_dwModuleHandle",
          "0x64EC|DAT_004064ec",
          "0x6784|DAT_00406784"
        ],
        "LoD/1.08": [
          "0x6788|g_fCodePageInitialized",
          "0x64B4|g_dwModuleHandle",
          "0x64EC|DAT_004064ec",
          "0x6784|DAT_00406784"
        ],
        "LoD/1.09": [
          "0x6788|g_fCodePageInitialized",
          "0x64B4|g_dwModuleHandle",
          "0x64EC|DAT_004064ec",
          "0x6784|DAT_00406784"
        ],
        "LoD/1.09b": [
          "0x6788|g_fCodePageInitialized",
          "0x64B4|g_dwModuleHandle",
          "0x64EC|DAT_004064ec",
          "0x6784|DAT_00406784"
        ],
        "LoD/1.09d": [
          "0x6788|g_fCodePageInitialized",
          "0x64B4|g_dwModuleHandle",
          "0x64EC|DAT_004064ec",
          "0x6784|DAT_00406784"
        ],
        "LoD/1.10": [
          "0x6788|g_fCodePageInitialized",
          "0x64B4|DAT_004064b4",
          "0x64EC|DAT_004064ec",
          "0x6784|DAT_00406784"
        ],
        "LoD/1.11": [
          "0x6788|g_fCodePageInitialized",
          "0x64B4|g_dwModuleHandle",
          "0x64EC|DAT_004064ec",
          "0x6784|DAT_00406784"
        ],
        "LoD/1.11b": [
          "0x6788|g_fCodePageInitialized",
          "0x64B4|g_dwModuleHandle",
          "0x64EC|DAT_004064ec",
          "0x6784|DAT_00406784"
        ],
        "LoD/1.12a": [
          "0x6788|g_fCodePageInitialized",
          "0x64B4|g_dwModuleHandle",
          "0x64EC|DAT_004064ec",
          "0x6784|DAT_00406784"
        ],
        "LoD/1.13c": [
          "0x6788|g_fCodePageInitialized",
          "0x64B4|g_dwModuleHandle",
          "0x64EC|DAT_004064ec",
          "0x6784|DAT_00406784"
        ],
        "LoD/1.13d": [
          "0x6788|g_fCodePageInitialized",
          "0x64B4|g_dwModuleHandle",
          "0x64EC|DAT_004064ec",
          "0x6784|DAT_00406784"
        ],
        "LoD/1.14a": [
          "0x6788|g_fCodePageInitialized",
          "0x64B4|g_dwModuleHandle",
          "0x64EC|DAT_004064ec",
          "0x6784|DAT_00406784"
        ],
        "LoD/1.14b": [
          "0x6788|g_fCodePageInitialized",
          "0x64B4|g_dwModuleHandle",
          "0x64EC|DAT_004064ec",
          "0x6784|DAT_00406784"
        ],
        "LoD/1.14c": [
          "0x6788|g_fCodePageInitialized",
          "0x64B4|g_dwModuleHandle",
          "0x64EC|DAT_004064ec",
          "0x6784|DAT_00406784"
        ],
        "LoD/1.14d": [
          "0x6788|g_fCodePageInitialized",
          "0x64B4|g_dwModuleHandle",
          "0x64EC|DAT_004064ec",
          "0x6784|DAT_00406784"
        ]
      }
    },
    "diablo ii.exe_InitializeModuleData": {
      "addresses": {
        "LoD/1.07": "0x00402017",
        "LoD/1.08": "0x00402017",
        "LoD/1.09": "0x00402017",
        "LoD/1.09b": "0x00402017",
        "LoD/1.09d": "0x00402017",
        "LoD/1.10": "0x00402017",
        "LoD/1.11": "0x00402017",
        "LoD/1.11b": "0x00402017",
        "LoD/1.12a": "0x00402017",
        "LoD/1.13c": "0x00402017",
        "LoD/1.13d": "0x00402017",
        "LoD/1.14a": "0x00402017",
        "LoD/1.14b": "0x00402017",
        "LoD/1.14c": "0x00402017",
        "LoD/1.14d": "0x00402017"
      },
      "rvas": {
        "LoD/1.07": "0x2017",
        "LoD/1.08": "0x2017",
        "LoD/1.09": "0x2017",
        "LoD/1.09b": "0x2017",
        "LoD/1.09d": "0x2017",
        "LoD/1.10": "0x2017",
        "LoD/1.11": "0x2017",
        "LoD/1.11b": "0x2017",
        "LoD/1.12a": "0x2017",
        "LoD/1.13c": "0x2017",
        "LoD/1.13d": "0x2017",
        "LoD/1.14a": "0x2017",
        "LoD/1.14b": "0x2017",
        "LoD/1.14c": "0x2017",
        "LoD/1.14d": "0x2017"
      },
      "sizes": {
        "LoD/1.07": 153,
        "LoD/1.08": 153,
        "LoD/1.09": 153,
        "LoD/1.09b": 153,
        "LoD/1.09d": 153,
        "LoD/1.10": 153,
        "LoD/1.11": 153,
        "LoD/1.11b": 153,
        "LoD/1.12a": 153,
        "LoD/1.13c": 153,
        "LoD/1.13d": 153,
        "LoD/1.14a": 153,
        "LoD/1.14b": 153,
        "LoD/1.14c": 153,
        "LoD/1.14d": 153
      },
      "name": "InitializeModuleData",
      "signature": "void InitializeModuleData(void)",
      "calling_convention": "__stdcall",
      "return_type": "void",
      "comment": "Initialize module data structures and process filename to create dynamic table\n\nAlgorithm:\n1. Check global initialization flag (DAT_1003cde8); call FUN_100217c1() if uninitialized\n2. Get current module filename using GetModuleFileNameA into 260-byte global buffer\n3. Store filename pointer in global variable _DAT_1003c934 for future reference\n4. Select filename source: use override from DAT_1003ce10 if available, otherwise use module filename\n5. Call FUN_1001f501 first time with null pointers to query table size requirements\n6. Allocate memory: dwCount * 4 bytes for main table + dwDataSize bytes for auxiliary data\n7. Validate allocation success; exit with code 8 if malloc fails\n8. Call FUN_1001f501 second time to populate allocated table and auxiliary data\n9. Store table pointer in global _DAT_1003c91c and adjusted count in _DAT_1003c918\n\nParameters:\nNone - function called during DLL initialization\n\nReturns:\nvoid - sets global variables _DAT_1003c91c (table pointer) and _DAT_1003c918 (count-1)\n\nSpecial Cases:\n- Exit code 8: Memory allocation failure\n- Override filename: DAT_1003ce10 takes precedence if first byte non-zero\n- Count adjustment: _DAT_1003c918 stores count decremented by 1\n\nMagic Numbers Reference:\n0x104 (260 decimal): Maximum path length for GetModuleFileNameA buffer\n0x8: Exit code for memory allocation failure\n0x4: Size multiplier for table entries (DWORD/uint size)",
      "name_source": "LoD/1.07",
      "method": "CAL",
      "index": "CAL:b719ab040bfebd0b1940a800c0d3c266",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "78c0be793b204c577b78460711bf70fb",
        "CFG": "5c86dcee1ae591b9319ac28e686a93af",
        "PRO": "daf0572913365e2e4b855eef8c8036f5",
        "CAL": "b719ab040bfebd0b1940a800c0d3c266",
        "CON": "f00205a6c0346eef022dfbc95dfb2228",
        "APS": null
      },
      "callees": {
        "LoD/1.07": [
          "ParseCommandLineArguments|0x4020B0",
          "AmsgExit|0x4015D9",
          "GetModuleFileNameA|0x15",
          "InitializeCodePageOnce|0x4019E6",
          "_malloc|0x402EF0"
        ],
        "LoD/1.08": [
          "InitializeCodePageOnce|0x4019E6",
          "GetModuleFileNameA|0x15",
          "_malloc|0x402EF0",
          "AmsgExit|0x4015D9",
          "ParseCommandLineArguments|0x4020B0"
        ],
        "LoD/1.09": [
          "AmsgExit|0x4015D9",
          "ParseCommandLineArguments|0x4020B0",
          "GetModuleFileNameA|0x15",
          "InitializeCodePageOnce|0x4019E6",
          "_malloc|0x402EF0"
        ],
        "LoD/1.09b": [
          "ParseCommandLineArguments|0x4020B0",
          "_malloc|0x402EF0",
          "GetModuleFileNameA|0x15",
          "InitializeCodePageOnce|0x4019E6",
          "AmsgExit|0x4015D9"
        ],
        "LoD/1.09d": [
          "_malloc|0x402EF0",
          "ParseCommandLineArguments|0x4020B0",
          "InitializeCodePageOnce|0x4019E6",
          "AmsgExit|0x4015D9",
          "GetModuleFileNameA|0x15"
        ],
        "LoD/1.10": [
          "InitializeCodePageOnce|0x4019E6",
          "GetModuleFileNameA|0x15",
          "AmsgExit|0x4015D9",
          "ParseCommandLineArguments|0x4020B0",
          "_malloc|0x402EF0"
        ],
        "LoD/1.11": [
          "InitializeCodePageOnce|0x4019E6",
          "GetModuleFileNameA|0x15",
          "_malloc|0x402EF0",
          "ParseCommandLineArguments|0x4020B0",
          "AmsgExit|0x4015D9"
        ],
        "LoD/1.11b": [
          "ParseCommandLineArguments|0x4020B0",
          "AmsgExit|0x4015D9",
          "_malloc|0x402EF0",
          "InitializeCodePageOnce|0x4019E6",
          "GetModuleFileNameA|0x15"
        ],
        "LoD/1.12a": [
          "GetModuleFileNameA|0x15",
          "_malloc|0x402EF0",
          "AmsgExit|0x4015D9",
          "InitializeCodePageOnce|0x4019E6",
          "ParseCommandLineArguments|0x4020B0"
        ],
        "LoD/1.13c": [
          "_malloc|0x402EF0",
          "GetModuleFileNameA|0x15",
          "AmsgExit|0x4015D9",
          "InitializeCodePageOnce|0x4019E6",
          "ParseCommandLineArguments|0x4020B0"
        ],
        "LoD/1.13d": [
          "ParseCommandLineArguments|0x4020B0",
          "_malloc|0x402EF0",
          "GetModuleFileNameA|0x15",
          "AmsgExit|0x4015D9",
          "InitializeCodePageOnce|0x4019E6"
        ],
        "LoD/1.14a": [
          "ParseCommandLineArguments|0x4020B0",
          "AmsgExit|0x4015D9",
          "_malloc|0x402EF0",
          "InitializeCodePageOnce|0x4019E6",
          "GetModuleFileNameA|0x15"
        ],
        "LoD/1.14b": [
          "_malloc|0x402EF0",
          "AmsgExit|0x4015D9",
          "ParseCommandLineArguments|0x4020B0",
          "GetModuleFileNameA|0x15",
          "InitializeCodePageOnce|0x4019E6"
        ],
        "LoD/1.14c": [
          "ParseCommandLineArguments|0x4020B0",
          "_malloc|0x402EF0",
          "GetModuleFileNameA|0x15",
          "AmsgExit|0x4015D9",
          "InitializeCodePageOnce|0x4019E6"
        ],
        "LoD/1.14d": [
          "ParseCommandLineArguments|0x4020B0",
          "GetModuleFileNameA|0x15",
          "_malloc|0x402EF0",
          "InitializeCodePageOnce|0x4019E6",
          "AmsgExit|0x4015D9"
        ]
      },
      "callers": {
        "LoD/1.07": [
          "entry|0x4014E3"
        ],
        "LoD/1.08": [
          "entry|0x4014E3"
        ],
        "LoD/1.09": [
          "entry|0x4014E3"
        ],
        "LoD/1.09b": [
          "entry|0x4014E3"
        ],
        "LoD/1.09d": [
          "entry|0x4014E3"
        ],
        "LoD/1.10": [
          "entry|0x4014E3"
        ],
        "LoD/1.11": [
          "entry|0x4014E3"
        ],
        "LoD/1.11b": [
          "entry|0x4014E3"
        ],
        "LoD/1.12a": [
          "entry|0x4014E3"
        ],
        "LoD/1.13c": [
          "entry|0x4014E3"
        ],
        "LoD/1.13d": [
          "entry|0x4014E3"
        ],
        "LoD/1.14a": [
          "entry|0x4014E3"
        ],
        "LoD/1.14b": [
          "entry|0x4014E3"
        ],
        "LoD/1.14c": [
          "entry|0x4014E3"
        ],
        "LoD/1.14d": [
          "entry|0x4014E3"
        ]
      },
      "instruction_counts": {
        "LoD/1.07": 62,
        "LoD/1.08": 62,
        "LoD/1.09": 62,
        "LoD/1.09b": 62,
        "LoD/1.09d": 62,
        "LoD/1.10": 62,
        "LoD/1.11": 62,
        "LoD/1.11b": 62,
        "LoD/1.12a": 62,
        "LoD/1.13c": 62,
        "LoD/1.13d": 62,
        "LoD/1.14a": 62,
        "LoD/1.14b": 62,
        "LoD/1.14c": 62,
        "LoD/1.14d": 62
      },
      "stack_frame_sizes": {
        "LoD/1.07": 16,
        "LoD/1.08": 16,
        "LoD/1.09": 16,
        "LoD/1.09b": 16,
        "LoD/1.09d": 16,
        "LoD/1.10": 16,
        "LoD/1.11": 16,
        "LoD/1.11b": 16,
        "LoD/1.12a": 16,
        "LoD/1.13c": 16,
        "LoD/1.13d": 16,
        "LoD/1.14a": 16,
        "LoD/1.14b": 16,
        "LoD/1.14c": 16,
        "LoD/1.14d": 16
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
        "LoD/1.13d": 7,
        "LoD/1.14a": 7,
        "LoD/1.14b": 7,
        "LoD/1.14c": 7,
        "LoD/1.14d": 7
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
        "LoD/1.13d": 0,
        "LoD/1.14a": 0,
        "LoD/1.14b": 0,
        "LoD/1.14c": 0,
        "LoD/1.14d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "78c0be793b204c577b78460711bf70fb",
        "LoD/1.08": "78c0be793b204c577b78460711bf70fb",
        "LoD/1.09": "78c0be793b204c577b78460711bf70fb",
        "LoD/1.09b": "78c0be793b204c577b78460711bf70fb",
        "LoD/1.09d": "78c0be793b204c577b78460711bf70fb",
        "LoD/1.10": "78c0be793b204c577b78460711bf70fb",
        "LoD/1.11": "78c0be793b204c577b78460711bf70fb",
        "LoD/1.11b": "78c0be793b204c577b78460711bf70fb",
        "LoD/1.12a": "78c0be793b204c577b78460711bf70fb",
        "LoD/1.13c": "78c0be793b204c577b78460711bf70fb",
        "LoD/1.13d": "78c0be793b204c577b78460711bf70fb",
        "LoD/1.14a": "78c0be793b204c577b78460711bf70fb",
        "LoD/1.14b": "78c0be793b204c577b78460711bf70fb",
        "LoD/1.14c": "78c0be793b204c577b78460711bf70fb",
        "LoD/1.14d": "78c0be793b204c577b78460711bf70fb"
      },
      "constants": {
        "LoD/1.07": [
          260,
          4220180
        ],
        "LoD/1.08": [
          260,
          4220180
        ],
        "LoD/1.09": [
          260,
          4220180
        ],
        "LoD/1.09b": [
          260,
          4220180
        ],
        "LoD/1.09d": [
          260,
          4220180
        ],
        "LoD/1.10": [
          260,
          4220180
        ],
        "LoD/1.11": [
          260,
          4220180
        ],
        "LoD/1.11b": [
          260,
          4220180
        ],
        "LoD/1.12a": [
          260,
          4220180
        ],
        "LoD/1.13c": [
          260,
          4220180
        ],
        "LoD/1.13d": [
          260,
          4220180
        ],
        "LoD/1.14a": [
          260,
          4220180
        ],
        "LoD/1.14b": [
          260,
          4220180
        ],
        "LoD/1.14c": [
          260,
          4220180
        ],
        "LoD/1.14d": [
          260,
          4220180
        ]
      },
      "globals": {
        "LoD/1.07": [
          "0x6788|g_fCodePageInitialized",
          "0x6514|DAT_00406514",
          "0x5050|PTR_GetModuleFileNameA_00405050",
          "0x69C8|g_lpszCommandLine",
          "0x64FC|DAT_004064fc",
          "0xFFFFFFFFFFBFFFF4|",
          "0xFFFFFFFFFFBFFFF8|",
          "0x64E4|DAT_004064e4",
          "0x64E0|DAT_004064e0"
        ],
        "LoD/1.08": [
          "0x6788|g_fCodePageInitialized",
          "0x6514|DAT_00406514",
          "0x5050|PTR_GetModuleFileNameA_00405050",
          "0x69C8|g_lpszCommandLine",
          "0x64FC|DAT_004064fc",
          "0xFFFFFFFFFFBFFFF4|",
          "0xFFFFFFFFFFBFFFF8|",
          "0x64E4|DAT_004064e4",
          "0x64E0|DAT_004064e0"
        ],
        "LoD/1.09": [
          "0x6788|g_fCodePageInitialized",
          "0x6514|DAT_00406514",
          "0x5050|PTR_GetModuleFileNameA_00405050",
          "0x69C8|g_lpszCommandLine",
          "0x64FC|DAT_004064fc",
          "0xFFFFFFFFFFBFFFF4|",
          "0xFFFFFFFFFFBFFFF8|",
          "0x64E4|DAT_004064e4",
          "0x64E0|DAT_004064e0"
        ],
        "LoD/1.09b": [
          "0x6788|g_fCodePageInitialized",
          "0x6514|DAT_00406514",
          "0x5050|PTR_GetModuleFileNameA_00405050",
          "0x69C8|g_lpszCommandLine",
          "0x64FC|DAT_004064fc",
          "0xFFFFFFFFFFBFFFF4|",
          "0xFFFFFFFFFFBFFFF8|",
          "0x64E4|DAT_004064e4",
          "0x64E0|DAT_004064e0"
        ],
        "LoD/1.09d": [
          "0x6788|g_fCodePageInitialized",
          "0x6514|DAT_00406514",
          "0x5050|PTR_GetModuleFileNameA_00405050",
          "0x69C8|g_lpszCommandLine",
          "0x64FC|DAT_004064fc",
          "0xFFFFFFFFFFBFFFF4|",
          "0xFFFFFFFFFFBFFFF8|",
          "0x64E4|DAT_004064e4",
          "0x64E0|DAT_004064e0"
        ],
        "LoD/1.10": [
          "0x6788|g_fCodePageInitialized",
          "0x6514|DAT_00406514",
          "0x5050|PTR_GetModuleFileNameA_00405050",
          "0x69C8|DAT_004069c8",
          "0x64FC|DAT_004064fc",
          "0xFFFFFFFFFFBFFFF4|",
          "0xFFFFFFFFFFBFFFF8|",
          "0x64E4|DAT_004064e4",
          "0x64E0|DAT_004064e0"
        ],
        "LoD/1.11": [
          "0x6788|g_fCodePageInitialized",
          "0x6514|DAT_00406514",
          "0x5050|PTR_GetModuleFileNameA_00405050",
          "0x69C8|g_lpszCommandLine",
          "0x64FC|DAT_004064fc",
          "0xFFFFFFFFFFBFFFF4|",
          "0xFFFFFFFFFFBFFFF8|",
          "0x64E4|DAT_004064e4",
          "0x64E0|DAT_004064e0"
        ],
        "LoD/1.11b": [
          "0x6788|g_fCodePageInitialized",
          "0x6514|DAT_00406514",
          "0x5050|PTR_GetModuleFileNameA_00405050",
          "0x69C8|g_lpszCommandLine",
          "0x64FC|DAT_004064fc",
          "0xFFFFFFFFFFBFFFF4|",
          "0xFFFFFFFFFFBFFFF8|",
          "0x64E4|DAT_004064e4",
          "0x64E0|DAT_004064e0"
        ],
        "LoD/1.12a": [
          "0x6788|g_fCodePageInitialized",
          "0x6514|DAT_00406514",
          "0x5050|PTR_GetModuleFileNameA_00405050",
          "0x69C8|g_lpszCommandLine",
          "0x64FC|DAT_004064fc",
          "0xFFFFFFFFFFBFFFF4|",
          "0xFFFFFFFFFFBFFFF8|",
          "0x64E4|DAT_004064e4",
          "0x64E0|DAT_004064e0"
        ],
        "LoD/1.13c": [
          "0x6788|g_fCodePageInitialized",
          "0x6514|DAT_00406514",
          "0x5050|PTR_GetModuleFileNameA_00405050",
          "0x69C8|g_lpszCommandLine",
          "0x64FC|DAT_004064fc",
          "0xFFFFFFFFFFBFFFF4|",
          "0xFFFFFFFFFFBFFFF8|",
          "0x64E4|DAT_004064e4",
          "0x64E0|DAT_004064e0"
        ],
        "LoD/1.13d": [
          "0x6788|g_fCodePageInitialized",
          "0x6514|DAT_00406514",
          "0x5050|PTR_GetModuleFileNameA_00405050",
          "0x69C8|g_lpszCommandLine",
          "0x64FC|DAT_004064fc",
          "0xFFFFFFFFFFBFFFF4|",
          "0xFFFFFFFFFFBFFFF8|",
          "0x64E4|DAT_004064e4",
          "0x64E0|DAT_004064e0"
        ],
        "LoD/1.14a": [
          "0x6788|g_fCodePageInitialized",
          "0x6514|DAT_00406514",
          "0x5050|PTR_GetModuleFileNameA_00405050",
          "0x69C8|g_lpszCommandLine",
          "0x64FC|DAT_004064fc",
          "0xFFFFFFFFFFBFFFF4|",
          "0xFFFFFFFFFFBFFFF8|",
          "0x64E4|DAT_004064e4",
          "0x64E0|DAT_004064e0"
        ],
        "LoD/1.14b": [
          "0x6788|g_fCodePageInitialized",
          "0x6514|DAT_00406514",
          "0x5050|PTR_GetModuleFileNameA_00405050",
          "0x69C8|g_lpszCommandLine",
          "0x64FC|DAT_004064fc",
          "0xFFFFFFFFFFBFFFF4|",
          "0xFFFFFFFFFFBFFFF8|",
          "0x64E4|DAT_004064e4",
          "0x64E0|DAT_004064e0"
        ],
        "LoD/1.14c": [
          "0x6788|g_fCodePageInitialized",
          "0x6514|DAT_00406514",
          "0x5050|PTR_GetModuleFileNameA_00405050",
          "0x69C8|g_lpszCommandLine",
          "0x64FC|DAT_004064fc",
          "0xFFFFFFFFFFBFFFF4|",
          "0xFFFFFFFFFFBFFFF8|",
          "0x64E4|DAT_004064e4",
          "0x64E0|DAT_004064e0"
        ],
        "LoD/1.14d": [
          "0x6788|g_fCodePageInitialized",
          "0x6514|DAT_00406514",
          "0x5050|PTR_GetModuleFileNameA_00405050",
          "0x69C8|g_lpszCommandLine",
          "0x64FC|DAT_004064fc",
          "0xFFFFFFFFFFBFFFF4|",
          "0xFFFFFFFFFFBFFFF8|",
          "0x64E4|DAT_004064e4",
          "0x64E0|DAT_004064e0"
        ]
      }
    },
    "diablo ii.exe_ParseCommandLineArguments": {
      "addresses": {
        "LoD/1.07": "0x004020B0",
        "LoD/1.08": "0x004020B0",
        "LoD/1.09": "0x004020B0",
        "LoD/1.09b": "0x004020B0",
        "LoD/1.09d": "0x004020B0",
        "LoD/1.10": "0x004020B0",
        "LoD/1.11": "0x004020B0",
        "LoD/1.11b": "0x004020B0",
        "LoD/1.12a": "0x004020B0",
        "LoD/1.13c": "0x004020B0",
        "LoD/1.13d": "0x004020B0",
        "LoD/1.14a": "0x004020B0",
        "LoD/1.14b": "0x004020B0",
        "LoD/1.14c": "0x004020B0",
        "LoD/1.14d": "0x004020B0"
      },
      "rvas": {
        "LoD/1.07": "0x20B0",
        "LoD/1.08": "0x20B0",
        "LoD/1.09": "0x20B0",
        "LoD/1.09b": "0x20B0",
        "LoD/1.09d": "0x20B0",
        "LoD/1.10": "0x20B0",
        "LoD/1.11": "0x20B0",
        "LoD/1.11b": "0x20B0",
        "LoD/1.12a": "0x20B0",
        "LoD/1.13c": "0x20B0",
        "LoD/1.13d": "0x20B0",
        "LoD/1.14a": "0x20B0",
        "LoD/1.14b": "0x20B0",
        "LoD/1.14c": "0x20B0",
        "LoD/1.14d": "0x20B0"
      },
      "sizes": {
        "LoD/1.07": 436,
        "LoD/1.08": 436,
        "LoD/1.09": 436,
        "LoD/1.09b": 436,
        "LoD/1.09d": 436,
        "LoD/1.10": 436,
        "LoD/1.11": 436,
        "LoD/1.11b": 436,
        "LoD/1.12a": 436,
        "LoD/1.13c": 436,
        "LoD/1.13d": 436,
        "LoD/1.14a": 436,
        "LoD/1.14b": 436,
        "LoD/1.14c": 436,
        "LoD/1.14d": 436
      },
      "name": "ParseCommandLineArguments",
      "signature": "void ParseCommandLineArguments(char * lpszCmdLine, char * * lpszArgv, char * szOutputBuffer, int * pnArgc, int * pnTotalChars)",
      "calling_convention": "__cdecl",
      "return_type": "void",
      "comment": "Parses command line string into individual arguments with quote and escape handling\n\nAlgorithm:\n1. Initialize output counters: set argc=1, totalChars=0\n2. Store first argument pointer in argv[0] if argv provided\n3. Check if command line starts with quote (0x22):\n   a. If quoted: Parse until closing quote, handle escape sequences\n   b. If unquoted: Parse until space (0x20) or tab (0x09)\n4. Use character lookup table at 0x1003cbc0 bit 4 to identify escapable chars\n5. Skip whitespace between arguments using space/tab delimiters\n6. For each argument found:\n   a. Store argument pointer in argv array if provided\n   b. Increment argc counter\n   c. Handle backslash escape sequences (\\\\ becomes \\)\n   d. Toggle quote mode on unescaped quotes, handle doubled quotes (\"\")\n   e. Copy characters to output buffer if provided\n   f. Null-terminate argument in output buffer\n7. Null-terminate argv array and increment argc for final count\n\nParameters:\n- cmdLine: Input command line string to parse\n- argv: Array to store pointers to parsed arguments (NULL = count only)\n- outputBuffer: Buffer to store null-terminated argument strings (NULL = count only)\n- argc: Pointer to receive argument count (includes program name)\n- totalChars: Pointer to receive total characters needed for all arguments\n\nReturns:\n- void (results returned through output parameters)\n\nSpecial Cases:\n- If argv is NULL: Only counts arguments without storing pointers\n- If outputBuffer is NULL: Only counts characters without copying\n- Empty quotes \"\" create empty argument\n- Backslash at end of line becomes literal backslash\n- Doubled quotes (\"\") inside quoted string become single quote\n\nMagic Numbers Reference:\n- 0x22 (34): Double quote character for argument quoting\n- 0x20 (32): Space character - argument delimiter\n- 0x09 (9): Tab character - argument delimiter  \n- 0x5C (92): Backslash character for escape sequences\n- 0x1003cbc0: Character classification table base address\n- 0x4: Bit mask for escapable character flag in lookup table\n\nCharacter Classification Table:\nThe lookup table at 0x1003cbc0 contains character class flags where\nbit 4 (value 0x4) indicates characters that require escape handling.\nThis typically includes characters like quotes, backslashes, and \nother shell metacharacters that need special processing.",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:50cd6b6fd69b78c0380659763fce7ea0",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "50cd6b6fd69b78c0380659763fce7ea0",
        "CFG": "9a35ab5935fed2f629b2dd9f68e65902",
        "PRO": "298c11e8b7f6fb45479beaa4f4f2c6d3",
        "CAL": null,
        "CON": null,
        "APS": null
      },
      "callers": {
        "LoD/1.07": [
          "InitializeModuleData|0x402017"
        ],
        "LoD/1.08": [
          "InitializeModuleData|0x402017"
        ],
        "LoD/1.09": [
          "InitializeModuleData|0x402017"
        ],
        "LoD/1.09b": [
          "InitializeModuleData|0x402017"
        ],
        "LoD/1.09d": [
          "InitializeModuleData|0x402017"
        ],
        "LoD/1.10": [
          "InitializeModuleData|0x402017"
        ],
        "LoD/1.11": [
          "InitializeModuleData|0x402017"
        ],
        "LoD/1.11b": [
          "InitializeModuleData|0x402017"
        ],
        "LoD/1.12a": [
          "InitializeModuleData|0x402017"
        ],
        "LoD/1.13c": [
          "InitializeModuleData|0x402017"
        ],
        "LoD/1.13d": [
          "InitializeModuleData|0x402017"
        ],
        "LoD/1.14a": [
          "InitializeModuleData|0x402017"
        ],
        "LoD/1.14b": [
          "InitializeModuleData|0x402017"
        ],
        "LoD/1.14c": [
          "InitializeModuleData|0x402017"
        ],
        "LoD/1.14d": [
          "InitializeModuleData|0x402017"
        ]
      },
      "instruction_counts": {
        "LoD/1.07": 187,
        "LoD/1.08": 187,
        "LoD/1.09": 187,
        "LoD/1.09b": 187,
        "LoD/1.09d": 187,
        "LoD/1.10": 187,
        "LoD/1.11": 187,
        "LoD/1.11b": 187,
        "LoD/1.12a": 187,
        "LoD/1.13c": 187,
        "LoD/1.13d": 187,
        "LoD/1.14a": 187,
        "LoD/1.14b": 187,
        "LoD/1.14c": 187,
        "LoD/1.14d": 187
      },
      "stack_frame_sizes": {
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
        "LoD/1.13d": 24,
        "LoD/1.14a": 24,
        "LoD/1.14b": 24,
        "LoD/1.14c": 24,
        "LoD/1.14d": 24
      },
      "basic_block_counts": {
        "LoD/1.07": 71,
        "LoD/1.08": 71,
        "LoD/1.09": 71,
        "LoD/1.09b": 71,
        "LoD/1.09d": 71,
        "LoD/1.10": 71,
        "LoD/1.11": 71,
        "LoD/1.11b": 71,
        "LoD/1.12a": 71,
        "LoD/1.13c": 71,
        "LoD/1.13d": 71,
        "LoD/1.14a": 71,
        "LoD/1.14b": 71,
        "LoD/1.14c": 71,
        "LoD/1.14d": 71
      },
      "loop_counts": {
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
        "LoD/1.13d": 8,
        "LoD/1.14a": 8,
        "LoD/1.14b": 8,
        "LoD/1.14c": 8,
        "LoD/1.14d": 8
      },
      "mnemonic_hashes": {
        "LoD/1.07": "50cd6b6fd69b78c0380659763fce7ea0",
        "LoD/1.08": "50cd6b6fd69b78c0380659763fce7ea0",
        "LoD/1.09": "50cd6b6fd69b78c0380659763fce7ea0",
        "LoD/1.09b": "50cd6b6fd69b78c0380659763fce7ea0",
        "LoD/1.09d": "50cd6b6fd69b78c0380659763fce7ea0",
        "LoD/1.10": "50cd6b6fd69b78c0380659763fce7ea0",
        "LoD/1.11": "50cd6b6fd69b78c0380659763fce7ea0",
        "LoD/1.11b": "50cd6b6fd69b78c0380659763fce7ea0",
        "LoD/1.12a": "50cd6b6fd69b78c0380659763fce7ea0",
        "LoD/1.13c": "50cd6b6fd69b78c0380659763fce7ea0",
        "LoD/1.13d": "50cd6b6fd69b78c0380659763fce7ea0",
        "LoD/1.14a": "50cd6b6fd69b78c0380659763fce7ea0",
        "LoD/1.14b": "50cd6b6fd69b78c0380659763fce7ea0",
        "LoD/1.14c": "50cd6b6fd69b78c0380659763fce7ea0",
        "LoD/1.14d": "50cd6b6fd69b78c0380659763fce7ea0"
      },
      "constants": {
        "LoD/1.07": [
          4221121
        ],
        "LoD/1.08": [
          4221121
        ],
        "LoD/1.09": [
          4221121
        ],
        "LoD/1.09b": [
          4221121
        ],
        "LoD/1.09d": [
          4221121
        ],
        "LoD/1.10": [
          4221121
        ],
        "LoD/1.11": [
          4221121
        ],
        "LoD/1.11b": [
          4221121
        ],
        "LoD/1.12a": [
          4221121
        ],
        "LoD/1.13c": [
          4221121
        ],
        "LoD/1.13d": [
          4221121
        ],
        "LoD/1.14a": [
          4221121
        ],
        "LoD/1.14b": [
          4221121
        ],
        "LoD/1.14c": [
          4221121
        ],
        "LoD/1.14d": [
          4221121
        ]
      },
      "globals": {
        "LoD/1.07": [
          "0xFFFFFFFFFFC00014|",
          "0xFFFFFFFFFFC00010|",
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|",
          "0x68C1|DAT_004068c0+1"
        ],
        "LoD/1.08": [
          "0xFFFFFFFFFFC00014|",
          "0xFFFFFFFFFFC00010|",
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|",
          "0x68C1|DAT_004068c0+1"
        ],
        "LoD/1.09": [
          "0xFFFFFFFFFFC00014|",
          "0xFFFFFFFFFFC00010|",
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|",
          "0x68C1|DAT_004068c0+1"
        ],
        "LoD/1.09b": [
          "0xFFFFFFFFFFC00014|",
          "0xFFFFFFFFFFC00010|",
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|",
          "0x68C1|DAT_004068c0+1"
        ],
        "LoD/1.09d": [
          "0xFFFFFFFFFFC00014|",
          "0xFFFFFFFFFFC00010|",
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|",
          "0x68C1|DAT_004068c0+1"
        ],
        "LoD/1.10": [
          "0xFFFFFFFFFFC00014|",
          "0xFFFFFFFFFFC00010|",
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|",
          "0x68C1|DAT_004068c0+1"
        ],
        "LoD/1.11": [
          "0xFFFFFFFFFFC00014|",
          "0xFFFFFFFFFFC00010|",
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|",
          "0x68C1|DAT_004068c0+1"
        ],
        "LoD/1.11b": [
          "0xFFFFFFFFFFC00014|",
          "0xFFFFFFFFFFC00010|",
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|",
          "0x68C1|DAT_004068c0+1"
        ],
        "LoD/1.12a": [
          "0xFFFFFFFFFFC00014|",
          "0xFFFFFFFFFFC00010|",
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|",
          "0x68C1|DAT_004068c0+1"
        ],
        "LoD/1.13c": [
          "0xFFFFFFFFFFC00014|",
          "0xFFFFFFFFFFC00010|",
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|",
          "0x68C1|DAT_004068c0+1"
        ],
        "LoD/1.13d": [
          "0xFFFFFFFFFFC00014|",
          "0xFFFFFFFFFFC00010|",
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|",
          "0x68C1|DAT_004068c0+1"
        ],
        "LoD/1.14a": [
          "0xFFFFFFFFFFC00014|",
          "0xFFFFFFFFFFC00010|",
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|",
          "0x68C1|DAT_004068c0+1"
        ],
        "LoD/1.14b": [
          "0xFFFFFFFFFFC00014|",
          "0xFFFFFFFFFFC00010|",
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|",
          "0x68C1|DAT_004068c0+1"
        ],
        "LoD/1.14c": [
          "0xFFFFFFFFFFC00014|",
          "0xFFFFFFFFFFC00010|",
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|",
          "0x68C1|DAT_004068c0+1"
        ],
        "LoD/1.14d": [
          "0xFFFFFFFFFFC00014|",
          "0xFFFFFFFFFFC00010|",
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|",
          "0x68C1|DAT_004068c0+1"
        ]
      }
    },
    "diablo ii.exe_GetEnvironmentStringsConverted": {
      "addresses": {
        "LoD/1.07": "0x00402264",
        "LoD/1.08": "0x00402264",
        "LoD/1.09": "0x00402264",
        "LoD/1.09b": "0x00402264",
        "LoD/1.09d": "0x00402264",
        "LoD/1.10": "0x00402264",
        "LoD/1.11": "0x00402264",
        "LoD/1.11b": "0x00402264",
        "LoD/1.12a": "0x00402264",
        "LoD/1.13c": "0x00402264",
        "LoD/1.13d": "0x00402264",
        "LoD/1.14a": "0x00402264",
        "LoD/1.14b": "0x00402264",
        "LoD/1.14c": "0x00402264",
        "LoD/1.14d": "0x00402264"
      },
      "rvas": {
        "LoD/1.07": "0x2264",
        "LoD/1.08": "0x2264",
        "LoD/1.09": "0x2264",
        "LoD/1.09b": "0x2264",
        "LoD/1.09d": "0x2264",
        "LoD/1.10": "0x2264",
        "LoD/1.11": "0x2264",
        "LoD/1.11b": "0x2264",
        "LoD/1.12a": "0x2264",
        "LoD/1.13c": "0x2264",
        "LoD/1.13d": "0x2264",
        "LoD/1.14a": "0x2264",
        "LoD/1.14b": "0x2264",
        "LoD/1.14c": "0x2264",
        "LoD/1.14d": "0x2264"
      },
      "sizes": {
        "LoD/1.07": 306,
        "LoD/1.08": 306,
        "LoD/1.09": 306,
        "LoD/1.09b": 306,
        "LoD/1.09d": 306,
        "LoD/1.10": 306,
        "LoD/1.11": 306,
        "LoD/1.11b": 306,
        "LoD/1.12a": 306,
        "LoD/1.13c": 306,
        "LoD/1.13d": 306,
        "LoD/1.14a": 306,
        "LoD/1.14b": 306,
        "LoD/1.14c": 306,
        "LoD/1.14d": 306
      },
      "name": "GetEnvironmentStringsConverted",
      "signature": "char * GetEnvironmentStringsConverted(void)",
      "calling_convention": "__stdcall",
      "return_type": "char *",
      "comment": "Retrieves and converts environment strings to ANSI format with automatic Unicode/ANSI detection.\n\nAlgorithm:\n1. Check global state flag DAT_1003ca4c for preferred string format\n2. If state is 0 (uninitialized), attempt Unicode path first via GetEnvironmentStringsW()\n3. If Unicode strings available, set state to 1 (Unicode mode) and process wide strings\n4. If Unicode fails, fall back to ANSI path via GetEnvironmentStrings() and set state to 2\n5. For Unicode processing: iterate through null-terminated string array to calculate total length\n6. Convert wide character count to byte count and call WideCharToMultiByte() for size estimation\n7. Allocate buffer using malloc() with required size\n8. Perform actual conversion using WideCharToMultiByte() to allocated buffer\n9. If conversion fails, free buffer and return NULL\n10. For ANSI processing: iterate through ANSI string array to calculate total length\n11. Allocate buffer and copy strings using FUN_100217e0 (memory copy function)\n12. Free original environment strings using appropriate API (W or A version)\n13. Return allocated buffer containing converted environment strings\n\nParameters:\nNone - function takes no parameters\n\nReturns:\nchar * - Pointer to allocated buffer containing environment strings in ANSI format\nNULL - If environment strings unavailable or memory allocation/conversion fails\n\nSpecial Cases:\nState flag values: 0 = uninitialized, 1 = Unicode mode, 2 = ANSI mode\nReturns NULL for invalid state values or API failures\nCaller responsible for freeing returned buffer\n\nMagic Numbers Reference:\n0x1003ca4c - Global state flag for environment string format preference\n0 - Uninitialized state\n1 - Unicode (wide character) mode  \n2 - ANSI (multibyte character) mode\n\nError Handling:\nGetEnvironmentStringsW() failure - Falls back to ANSI mode\nGetEnvironmentStrings() failure - Returns NULL immediately\nmalloc() failure - Returns NULL  \nWideCharToMultiByte() failure - Frees allocated buffer and returns NULL\nInvalid state flag - Returns NULL",
      "name_source": "LoD/1.07",
      "method": "CAL",
      "index": "CAL:12a341814f5760bc3b9f51e07d3e1ebb",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "ee22dcb18299b51eb994a57f32a5df1d",
        "CFG": "601f1d62d94fff45dd3c84d1ec95ae87",
        "PRO": "c7f518b4d872ec71f7909c60ecc4d10e",
        "CAL": "12a341814f5760bc3b9f51e07d3e1ebb",
        "CON": null,
        "APS": null
      },
      "callees": {
        "LoD/1.07": [
          "WideCharToMultiByte|0x18",
          "SmartFree|0x402DCE",
          "GetEnvironmentStringsW|0x1A",
          "FreeEnvironmentStringsW|0x1",
          "OptimizedMemoryMove|0x402F70",
          "GetEnvironmentStrings|0x19",
          "FreeEnvironmentStringsA|0x16",
          "_malloc|0x402EF0"
        ],
        "LoD/1.08": [
          "GetEnvironmentStringsW|0x1A",
          "WideCharToMultiByte|0x18",
          "SmartFree|0x402DCE",
          "FreeEnvironmentStringsW|0x1",
          "GetEnvironmentStrings|0x19",
          "_malloc|0x402EF0",
          "FreeEnvironmentStringsA|0x16",
          "OptimizedMemoryMove|0x402F70"
        ],
        "LoD/1.09": [
          "SmartFree|0x402DCE",
          "OptimizedMemoryMove|0x402F70",
          "GetEnvironmentStringsW|0x1A",
          "WideCharToMultiByte|0x18",
          "FreeEnvironmentStringsW|0x1",
          "FreeEnvironmentStringsA|0x16",
          "GetEnvironmentStrings|0x19",
          "_malloc|0x402EF0"
        ],
        "LoD/1.09b": [
          "SmartFree|0x402DCE",
          "GetEnvironmentStringsW|0x1A",
          "FreeEnvironmentStringsW|0x1",
          "GetEnvironmentStrings|0x19",
          "OptimizedMemoryMove|0x402F70",
          "WideCharToMultiByte|0x18",
          "_malloc|0x402EF0",
          "FreeEnvironmentStringsA|0x16"
        ],
        "LoD/1.09d": [
          "_malloc|0x402EF0",
          "FreeEnvironmentStringsW|0x1",
          "FreeEnvironmentStringsA|0x16",
          "GetEnvironmentStringsW|0x1A",
          "SmartFree|0x402DCE",
          "OptimizedMemoryMove|0x402F70",
          "WideCharToMultiByte|0x18",
          "GetEnvironmentStrings|0x19"
        ],
        "LoD/1.10": [
          "WideCharToMultiByte|0x18",
          "OptimizedMemoryMove|0x402F70",
          "SmartFree|0x402DCE",
          "FreeEnvironmentStringsW|0x1",
          "_malloc|0x402EF0",
          "GetEnvironmentStringsW|0x1A",
          "GetEnvironmentStrings|0x19",
          "FreeEnvironmentStringsA|0x16"
        ],
        "LoD/1.11": [
          "GetEnvironmentStringsW|0x1A",
          "GetEnvironmentStrings|0x19",
          "FreeEnvironmentStringsW|0x1",
          "WideCharToMultiByte|0x18",
          "FreeEnvironmentStringsA|0x16",
          "_malloc|0x402EF0",
          "SmartFree|0x402DCE",
          "OptimizedMemoryMove|0x402F70"
        ],
        "LoD/1.11b": [
          "SmartFree|0x402DCE",
          "FreeEnvironmentStringsW|0x1",
          "OptimizedMemoryMove|0x402F70",
          "GetEnvironmentStringsW|0x1A",
          "WideCharToMultiByte|0x18",
          "FreeEnvironmentStringsA|0x16",
          "_malloc|0x402EF0",
          "GetEnvironmentStrings|0x19"
        ],
        "LoD/1.12a": [
          "SmartFree|0x402DCE",
          "GetEnvironmentStrings|0x19",
          "_malloc|0x402EF0",
          "FreeEnvironmentStringsW|0x1",
          "GetEnvironmentStringsW|0x1A",
          "OptimizedMemoryMove|0x402F70",
          "FreeEnvironmentStringsA|0x16",
          "WideCharToMultiByte|0x18"
        ],
        "LoD/1.13c": [
          "WideCharToMultiByte|0x18",
          "_malloc|0x402EF0",
          "GetEnvironmentStrings|0x19",
          "SmartFree|0x402DCE",
          "FreeEnvironmentStringsW|0x1",
          "FreeEnvironmentStringsA|0x16",
          "GetEnvironmentStringsW|0x1A",
          "OptimizedMemoryMove|0x402F70"
        ],
        "LoD/1.13d": [
          "_malloc|0x402EF0",
          "FreeEnvironmentStringsW|0x1",
          "FreeEnvironmentStringsA|0x16",
          "GetEnvironmentStringsW|0x1A",
          "WideCharToMultiByte|0x18",
          "SmartFree|0x402DCE",
          "OptimizedMemoryMove|0x402F70",
          "GetEnvironmentStrings|0x19"
        ],
        "LoD/1.14a": [
          "FreeEnvironmentStringsW|0x1",
          "GetEnvironmentStringsW|0x1A",
          "_malloc|0x402EF0",
          "WideCharToMultiByte|0x18",
          "OptimizedMemoryMove|0x402F70",
          "FreeEnvironmentStringsA|0x16",
          "GetEnvironmentStrings|0x19",
          "SmartFree|0x402DCE"
        ],
        "LoD/1.14b": [
          "GetEnvironmentStrings|0x19",
          "_malloc|0x402EF0",
          "SmartFree|0x402DCE",
          "GetEnvironmentStringsW|0x1A",
          "OptimizedMemoryMove|0x402F70",
          "WideCharToMultiByte|0x18",
          "FreeEnvironmentStringsA|0x16",
          "FreeEnvironmentStringsW|0x1"
        ],
        "LoD/1.14c": [
          "GetEnvironmentStringsW|0x1A",
          "OptimizedMemoryMove|0x402F70",
          "SmartFree|0x402DCE",
          "FreeEnvironmentStringsA|0x16",
          "_malloc|0x402EF0",
          "WideCharToMultiByte|0x18",
          "GetEnvironmentStrings|0x19",
          "FreeEnvironmentStringsW|0x1"
        ],
        "LoD/1.14d": [
          "FreeEnvironmentStringsA|0x16",
          "_malloc|0x402EF0",
          "SmartFree|0x402DCE",
          "FreeEnvironmentStringsW|0x1",
          "GetEnvironmentStringsW|0x1A",
          "WideCharToMultiByte|0x18",
          "OptimizedMemoryMove|0x402F70",
          "GetEnvironmentStrings|0x19"
        ]
      },
      "callers": {
        "LoD/1.07": [
          "entry|0x4014E3"
        ],
        "LoD/1.08": [
          "entry|0x4014E3"
        ],
        "LoD/1.09": [
          "entry|0x4014E3"
        ],
        "LoD/1.09b": [
          "entry|0x4014E3"
        ],
        "LoD/1.09d": [
          "entry|0x4014E3"
        ],
        "LoD/1.10": [
          "entry|0x4014E3"
        ],
        "LoD/1.11": [
          "entry|0x4014E3"
        ],
        "LoD/1.11b": [
          "entry|0x4014E3"
        ],
        "LoD/1.12a": [
          "entry|0x4014E3"
        ],
        "LoD/1.13c": [
          "entry|0x4014E3"
        ],
        "LoD/1.13d": [
          "entry|0x4014E3"
        ],
        "LoD/1.14a": [
          "entry|0x4014E3"
        ],
        "LoD/1.14b": [
          "entry|0x4014E3"
        ],
        "LoD/1.14c": [
          "entry|0x4014E3"
        ],
        "LoD/1.14d": [
          "entry|0x4014E3"
        ]
      },
      "instruction_counts": {
        "LoD/1.07": 132,
        "LoD/1.08": 132,
        "LoD/1.09": 132,
        "LoD/1.09b": 132,
        "LoD/1.09d": 132,
        "LoD/1.10": 132,
        "LoD/1.11": 132,
        "LoD/1.11b": 132,
        "LoD/1.12a": 132,
        "LoD/1.13c": 132,
        "LoD/1.13d": 132,
        "LoD/1.14a": 132,
        "LoD/1.14b": 132,
        "LoD/1.14c": 132,
        "LoD/1.14d": 132
      },
      "stack_frame_sizes": {
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
        "LoD/1.13d": 12,
        "LoD/1.14a": 12,
        "LoD/1.14b": 12,
        "LoD/1.14c": 12,
        "LoD/1.14d": 12
      },
      "basic_block_counts": {
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
        "LoD/1.13d": 29,
        "LoD/1.14a": 29,
        "LoD/1.14b": 29,
        "LoD/1.14c": 29,
        "LoD/1.14d": 29
      },
      "loop_counts": {
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
        "LoD/1.13d": 4,
        "LoD/1.14a": 4,
        "LoD/1.14b": 4,
        "LoD/1.14c": 4,
        "LoD/1.14d": 4
      },
      "mnemonic_hashes": {
        "LoD/1.07": "ee22dcb18299b51eb994a57f32a5df1d",
        "LoD/1.08": "ee22dcb18299b51eb994a57f32a5df1d",
        "LoD/1.09": "ee22dcb18299b51eb994a57f32a5df1d",
        "LoD/1.09b": "ee22dcb18299b51eb994a57f32a5df1d",
        "LoD/1.09d": "ee22dcb18299b51eb994a57f32a5df1d",
        "LoD/1.10": "ee22dcb18299b51eb994a57f32a5df1d",
        "LoD/1.11": "ee22dcb18299b51eb994a57f32a5df1d",
        "LoD/1.11b": "ee22dcb18299b51eb994a57f32a5df1d",
        "LoD/1.12a": "ee22dcb18299b51eb994a57f32a5df1d",
        "LoD/1.13c": "ee22dcb18299b51eb994a57f32a5df1d",
        "LoD/1.13d": "ee22dcb18299b51eb994a57f32a5df1d",
        "LoD/1.14a": "ee22dcb18299b51eb994a57f32a5df1d",
        "LoD/1.14b": "ee22dcb18299b51eb994a57f32a5df1d",
        "LoD/1.14c": "ee22dcb18299b51eb994a57f32a5df1d",
        "LoD/1.14d": "ee22dcb18299b51eb994a57f32a5df1d"
      },
      "globals": {
        "LoD/1.07": [
          "0x6618|DAT_00406618",
          "0x5064|PTR_GetEnvironmentStringsW_00405064",
          "0x5060|PTR_GetEnvironmentStrings_00405060",
          "0x505C|PTR_WideCharToMultiByte_0040505c",
          "0xFFFFFFFFFFBFFFFC|",
          "0xFFFFFFFFFFBFFFF8|",
          "0x5000|PTR_FreeEnvironmentStringsW_00405000",
          "0x5054|PTR_FreeEnvironmentStringsA_00405054"
        ],
        "LoD/1.08": [
          "0x6618|DAT_00406618",
          "0x5064|PTR_GetEnvironmentStringsW_00405064",
          "0x5060|PTR_GetEnvironmentStrings_00405060",
          "0x505C|PTR_WideCharToMultiByte_0040505c",
          "0xFFFFFFFFFFBFFFFC|",
          "0xFFFFFFFFFFBFFFF8|",
          "0x5000|PTR_FreeEnvironmentStringsW_00405000",
          "0x5054|PTR_FreeEnvironmentStringsA_00405054"
        ],
        "LoD/1.09": [
          "0x6618|DAT_00406618",
          "0x5064|PTR_GetEnvironmentStringsW_00405064",
          "0x5060|PTR_GetEnvironmentStrings_00405060",
          "0x505C|PTR_WideCharToMultiByte_0040505c",
          "0xFFFFFFFFFFBFFFFC|",
          "0xFFFFFFFFFFBFFFF8|",
          "0x5000|PTR_FreeEnvironmentStringsW_00405000",
          "0x5054|PTR_FreeEnvironmentStringsA_00405054"
        ],
        "LoD/1.09b": [
          "0x6618|DAT_00406618",
          "0x5064|PTR_GetEnvironmentStringsW_00405064",
          "0x5060|PTR_GetEnvironmentStrings_00405060",
          "0x505C|PTR_WideCharToMultiByte_0040505c",
          "0xFFFFFFFFFFBFFFFC|",
          "0xFFFFFFFFFFBFFFF8|",
          "0x5000|PTR_FreeEnvironmentStringsW_00405000",
          "0x5054|PTR_FreeEnvironmentStringsA_00405054"
        ],
        "LoD/1.09d": [
          "0x6618|DAT_00406618",
          "0x5064|PTR_GetEnvironmentStringsW_00405064",
          "0x5060|PTR_GetEnvironmentStrings_00405060",
          "0x505C|PTR_WideCharToMultiByte_0040505c",
          "0xFFFFFFFFFFBFFFFC|",
          "0xFFFFFFFFFFBFFFF8|",
          "0x5000|PTR_FreeEnvironmentStringsW_00405000",
          "0x5054|PTR_FreeEnvironmentStringsA_00405054"
        ],
        "LoD/1.10": [
          "0x6618|DAT_00406618",
          "0x5064|PTR_GetEnvironmentStringsW_00405064",
          "0x5060|PTR_GetEnvironmentStrings_00405060",
          "0x505C|PTR_WideCharToMultiByte_0040505c",
          "0xFFFFFFFFFFBFFFFC|",
          "0xFFFFFFFFFFBFFFF8|",
          "0x5000|PTR_FreeEnvironmentStringsW_00405000",
          "0x5054|PTR_FreeEnvironmentStringsA_00405054"
        ],
        "LoD/1.11": [
          "0x6618|DAT_00406618",
          "0x5064|PTR_GetEnvironmentStringsW_00405064",
          "0x5060|PTR_GetEnvironmentStrings_00405060",
          "0x505C|PTR_WideCharToMultiByte_0040505c",
          "0xFFFFFFFFFFBFFFFC|",
          "0xFFFFFFFFFFBFFFF8|",
          "0x5000|PTR_FreeEnvironmentStringsW_00405000",
          "0x5054|PTR_FreeEnvironmentStringsA_00405054"
        ],
        "LoD/1.11b": [
          "0x6618|DAT_00406618",
          "0x5064|PTR_GetEnvironmentStringsW_00405064",
          "0x5060|PTR_GetEnvironmentStrings_00405060",
          "0x505C|PTR_WideCharToMultiByte_0040505c",
          "0xFFFFFFFFFFBFFFFC|",
          "0xFFFFFFFFFFBFFFF8|",
          "0x5000|PTR_FreeEnvironmentStringsW_00405000",
          "0x5054|PTR_FreeEnvironmentStringsA_00405054"
        ],
        "LoD/1.12a": [
          "0x6618|DAT_00406618",
          "0x5064|PTR_GetEnvironmentStringsW_00405064",
          "0x5060|PTR_GetEnvironmentStrings_00405060",
          "0x505C|PTR_WideCharToMultiByte_0040505c",
          "0xFFFFFFFFFFBFFFFC|",
          "0xFFFFFFFFFFBFFFF8|",
          "0x5000|PTR_FreeEnvironmentStringsW_00405000",
          "0x5054|PTR_FreeEnvironmentStringsA_00405054"
        ],
        "LoD/1.13c": [
          "0x6618|DAT_00406618",
          "0x5064|PTR_GetEnvironmentStringsW_00405064",
          "0x5060|PTR_GetEnvironmentStrings_00405060",
          "0x505C|PTR_WideCharToMultiByte_0040505c",
          "0xFFFFFFFFFFBFFFFC|",
          "0xFFFFFFFFFFBFFFF8|",
          "0x5000|PTR_FreeEnvironmentStringsW_00405000",
          "0x5054|PTR_FreeEnvironmentStringsA_00405054"
        ],
        "LoD/1.13d": [
          "0x6618|DAT_00406618",
          "0x5064|PTR_GetEnvironmentStringsW_00405064",
          "0x5060|PTR_GetEnvironmentStrings_00405060",
          "0x505C|PTR_WideCharToMultiByte_0040505c",
          "0xFFFFFFFFFFBFFFFC|",
          "0xFFFFFFFFFFBFFFF8|",
          "0x5000|PTR_FreeEnvironmentStringsW_00405000",
          "0x5054|PTR_FreeEnvironmentStringsA_00405054"
        ],
        "LoD/1.14a": [
          "0x6618|DAT_00406618",
          "0x5064|PTR_GetEnvironmentStringsW_00405064",
          "0x5060|PTR_GetEnvironmentStrings_00405060",
          "0x505C|PTR_WideCharToMultiByte_0040505c",
          "0xFFFFFFFFFFBFFFFC|",
          "0xFFFFFFFFFFBFFFF8|",
          "0x5000|PTR_FreeEnvironmentStringsW_00405000",
          "0x5054|PTR_FreeEnvironmentStringsA_00405054"
        ],
        "LoD/1.14b": [
          "0x6618|DAT_00406618",
          "0x5064|PTR_GetEnvironmentStringsW_00405064",
          "0x5060|PTR_GetEnvironmentStrings_00405060",
          "0x505C|PTR_WideCharToMultiByte_0040505c",
          "0xFFFFFFFFFFBFFFFC|",
          "0xFFFFFFFFFFBFFFF8|",
          "0x5000|PTR_FreeEnvironmentStringsW_00405000",
          "0x5054|PTR_FreeEnvironmentStringsA_00405054"
        ],
        "LoD/1.14c": [
          "0x6618|DAT_00406618",
          "0x5064|PTR_GetEnvironmentStringsW_00405064",
          "0x5060|PTR_GetEnvironmentStrings_00405060",
          "0x505C|PTR_WideCharToMultiByte_0040505c",
          "0xFFFFFFFFFFBFFFFC|",
          "0xFFFFFFFFFFBFFFF8|",
          "0x5000|PTR_FreeEnvironmentStringsW_00405000",
          "0x5054|PTR_FreeEnvironmentStringsA_00405054"
        ],
        "LoD/1.14d": [
          "0x6618|DAT_00406618",
          "0x5064|PTR_GetEnvironmentStringsW_00405064",
          "0x5060|PTR_GetEnvironmentStrings_00405060",
          "0x505C|PTR_WideCharToMultiByte_0040505c",
          "0xFFFFFFFFFFBFFFFC|",
          "0xFFFFFFFFFFBFFFF8|",
          "0x5000|PTR_FreeEnvironmentStringsW_00405000",
          "0x5054|PTR_FreeEnvironmentStringsA_00405054"
        ]
      }
    },
    "diablo ii.exe_InitializeFileDescriptors": {
      "addresses": {
        "LoD/1.07": "0x00402396",
        "LoD/1.08": "0x00402396",
        "LoD/1.09": "0x00402396",
        "LoD/1.09b": "0x00402396",
        "LoD/1.09d": "0x00402396",
        "LoD/1.10": "0x00402396",
        "LoD/1.11": "0x00402396",
        "LoD/1.11b": "0x00402396",
        "LoD/1.12a": "0x00402396",
        "LoD/1.13c": "0x00402396",
        "LoD/1.13d": "0x00402396",
        "LoD/1.14a": "0x00402396",
        "LoD/1.14b": "0x00402396",
        "LoD/1.14c": "0x00402396",
        "LoD/1.14d": "0x00402396"
      },
      "rvas": {
        "LoD/1.07": "0x2396",
        "LoD/1.08": "0x2396",
        "LoD/1.09": "0x2396",
        "LoD/1.09b": "0x2396",
        "LoD/1.09d": "0x2396",
        "LoD/1.10": "0x2396",
        "LoD/1.11": "0x2396",
        "LoD/1.11b": "0x2396",
        "LoD/1.12a": "0x2396",
        "LoD/1.13c": "0x2396",
        "LoD/1.13d": "0x2396",
        "LoD/1.14a": "0x2396",
        "LoD/1.14b": "0x2396",
        "LoD/1.14c": "0x2396",
        "LoD/1.14d": "0x2396"
      },
      "sizes": {
        "LoD/1.07": 427,
        "LoD/1.08": 427,
        "LoD/1.09": 427,
        "LoD/1.09b": 427,
        "LoD/1.09d": 427,
        "LoD/1.10": 427,
        "LoD/1.11": 427,
        "LoD/1.11b": 427,
        "LoD/1.12a": 427,
        "LoD/1.13c": 427,
        "LoD/1.13d": 427,
        "LoD/1.14a": 427,
        "LoD/1.14b": 427,
        "LoD/1.14c": 427,
        "LoD/1.14d": 427
      },
      "name": "InitializeFileDescriptors",
      "signature": "void InitializeFileDescriptors(void)",
      "calling_convention": "__stdcall",
      "return_type": "void",
      "comment": "Initialize C Runtime Library file descriptor table and standard handles (stdin/stdout/stderr).\n\nAlgorithm:\n1. Allocate initial file descriptor array (32 entries) with 0x100 bytes\n2. Initialize all entries with INVALID_HANDLE_VALUE (0xFFFFFFFF) and default flags\n3. Set line buffering mode (0x0A) for all entries\n4. Retrieve startup information to check for inherited handles\n5. If inherited handles present, expand descriptor table to accommodate them\n6. Process inherited handle array from startup info:\n   - Validate each handle is not INVALID_HANDLE_VALUE\n   - Check handle has FOPEN flag (0x01) set\n   - Verify handle is device or has valid file type\n   - Copy valid handles to appropriate descriptor table entries\n7. Initialize standard handles (stdin=0, stdout=1, stderr=2):\n   - Set INUSE flag (0x81) for uninitialized standard slots\n   - Get standard handle using GetStdHandle with appropriate STD_*_HANDLE\n   - Set file type flags based on GetFileType result:\n     - FILE_TYPE_CHAR (0x02): Set TEXT flag (0x40)\n     - FILE_TYPE_PIPE (0x03): Set PIPE flag (0x08)\n   - Mark inherited handles with INHERIT flag (0x80)\n8. Call SetHandleCount to inform system of maximum handle count\n\nParameters:\nNone - function takes no parameters\n\nReturns:\nvoid - no return value, exits process on allocation failure\n\nSpecial Cases:\n- If malloc fails during initial allocation, calls AmsgExit(0x1b) to terminate\n- If inherited handle count exceeds 2047 (0x7FF), caps at 2048 (0x800)\n- Handles file descriptor table expansion by allocating additional 256-byte blocks\n- Process handles bucket addressing: slot = (index >> 5), offset = (index & 0x1F) * 8\n\nStructure Layout:\nFileDescriptor (8 bytes):\nOffset | Size | Field Name | Type | Description\n-------|------|------------|------|------------\n0x00   | 4    | hFile      | void*| File handle or INVALID_HANDLE_VALUE\n0x04   | 1    | bFlags     | byte | File flags (FOPEN=0x01, PIPE=0x08, TEXT=0x40, INUSE=0x81)\n0x05   | 1    | bLineMode  | byte | Line buffering mode (0x0A = LF)\n0x06   | 2    | bPadding   | byte[2] | Padding bytes\n\nFlag Bits:\n0x01 - FOPEN: File is open and available\n0x08 - PIPE: File is a pipe device\n0x40 - TEXT: Character device (console)\n0x80 - INHERIT: Handle inherited from parent process\n\nMagic Numbers:\n0x100 - Allocation size for each file descriptor block (256 bytes)\n0x20 - Number of file descriptors per allocation (32 entries)\n0x1b - Exit code for memory allocation failure\n0x7FF - Maximum inherited handle count before capping (2047)\n0xFFFFFFF6 - STD_INPUT_HANDLE constant (-10)\n0xFFFFFFF5 - STD_OUTPUT_HANDLE constant (-11)\n0xFFFFFFF4 - STD_ERROR_HANDLE constant (-12)",
      "name_source": "LoD/1.07",
      "method": "CAL",
      "index": "CAL:68a952c693b04d3c38904829c3ef7fc7",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "b09f16c0e6a5014f6b150653e76f58a2",
        "CFG": "410276ec43c579f745f5acf89ebdff97",
        "PRO": "6c41876e91c62a56cd32f233706cb037",
        "CAL": "68a952c693b04d3c38904829c3ef7fc7",
        "CON": "385422e42769e8600293ee953a814751",
        "APS": null
      },
      "callees": {
        "LoD/1.07": [
          "GetStdHandle|0x9",
          "AmsgExit|0x4015D9",
          "SetHandleCount|0x8",
          "GetFileType|0x1C",
          "GetStartupInfoA|0xC",
          "_malloc|0x402EF0"
        ],
        "LoD/1.08": [
          "GetStartupInfoA|0xC",
          "GetFileType|0x1C",
          "SetHandleCount|0x8",
          "_malloc|0x402EF0",
          "GetStdHandle|0x9",
          "AmsgExit|0x4015D9"
        ],
        "LoD/1.09": [
          "AmsgExit|0x4015D9",
          "GetFileType|0x1C",
          "GetStdHandle|0x9",
          "GetStartupInfoA|0xC",
          "SetHandleCount|0x8",
          "_malloc|0x402EF0"
        ],
        "LoD/1.09b": [
          "GetFileType|0x1C",
          "SetHandleCount|0x8",
          "_malloc|0x402EF0",
          "GetStdHandle|0x9",
          "AmsgExit|0x4015D9",
          "GetStartupInfoA|0xC"
        ],
        "LoD/1.09d": [
          "_malloc|0x402EF0",
          "GetFileType|0x1C",
          "SetHandleCount|0x8",
          "GetStdHandle|0x9",
          "AmsgExit|0x4015D9",
          "GetStartupInfoA|0xC"
        ],
        "LoD/1.10": [
          "SetHandleCount|0x8",
          "AmsgExit|0x4015D9",
          "GetStartupInfoA|0xC",
          "GetStdHandle|0x9",
          "GetFileType|0x1C",
          "_malloc|0x402EF0"
        ],
        "LoD/1.11": [
          "_malloc|0x402EF0",
          "GetStdHandle|0x9",
          "SetHandleCount|0x8",
          "GetStartupInfoA|0xC",
          "GetFileType|0x1C",
          "AmsgExit|0x4015D9"
        ],
        "LoD/1.11b": [
          "GetStartupInfoA|0xC",
          "GetStdHandle|0x9",
          "GetFileType|0x1C",
          "AmsgExit|0x4015D9",
          "_malloc|0x402EF0",
          "SetHandleCount|0x8"
        ],
        "LoD/1.12a": [
          "GetStartupInfoA|0xC",
          "GetStdHandle|0x9",
          "_malloc|0x402EF0",
          "AmsgExit|0x4015D9",
          "GetFileType|0x1C",
          "SetHandleCount|0x8"
        ],
        "LoD/1.13c": [
          "_malloc|0x402EF0",
          "GetStdHandle|0x9",
          "SetHandleCount|0x8",
          "GetStartupInfoA|0xC",
          "AmsgExit|0x4015D9",
          "GetFileType|0x1C"
        ],
        "LoD/1.13d": [
          "_malloc|0x402EF0",
          "GetStartupInfoA|0xC",
          "AmsgExit|0x4015D9",
          "SetHandleCount|0x8",
          "GetFileType|0x1C",
          "GetStdHandle|0x9"
        ],
        "LoD/1.14a": [
          "SetHandleCount|0x8",
          "AmsgExit|0x4015D9",
          "GetStdHandle|0x9",
          "_malloc|0x402EF0",
          "GetFileType|0x1C",
          "GetStartupInfoA|0xC"
        ],
        "LoD/1.14b": [
          "_malloc|0x402EF0",
          "GetStartupInfoA|0xC",
          "SetHandleCount|0x8",
          "AmsgExit|0x4015D9",
          "GetFileType|0x1C",
          "GetStdHandle|0x9"
        ],
        "LoD/1.14c": [
          "GetFileType|0x1C",
          "SetHandleCount|0x8",
          "GetStartupInfoA|0xC",
          "_malloc|0x402EF0",
          "AmsgExit|0x4015D9",
          "GetStdHandle|0x9"
        ],
        "LoD/1.14d": [
          "_malloc|0x402EF0",
          "GetStartupInfoA|0xC",
          "GetStdHandle|0x9",
          "SetHandleCount|0x8",
          "AmsgExit|0x4015D9",
          "GetFileType|0x1C"
        ]
      },
      "callers": {
        "LoD/1.07": [
          "entry|0x4014E3"
        ],
        "LoD/1.08": [
          "entry|0x4014E3"
        ],
        "LoD/1.09": [
          "entry|0x4014E3"
        ],
        "LoD/1.09b": [
          "entry|0x4014E3"
        ],
        "LoD/1.09d": [
          "entry|0x4014E3"
        ],
        "LoD/1.10": [
          "entry|0x4014E3"
        ],
        "LoD/1.11": [
          "entry|0x4014E3"
        ],
        "LoD/1.11b": [
          "entry|0x4014E3"
        ],
        "LoD/1.12a": [
          "entry|0x4014E3"
        ],
        "LoD/1.13c": [
          "entry|0x4014E3"
        ],
        "LoD/1.13d": [
          "entry|0x4014E3"
        ],
        "LoD/1.14a": [
          "entry|0x4014E3"
        ],
        "LoD/1.14b": [
          "entry|0x4014E3"
        ],
        "LoD/1.14c": [
          "entry|0x4014E3"
        ],
        "LoD/1.14d": [
          "entry|0x4014E3"
        ]
      },
      "instruction_counts": {
        "LoD/1.07": 143,
        "LoD/1.08": 143,
        "LoD/1.09": 143,
        "LoD/1.09b": 143,
        "LoD/1.09d": 143,
        "LoD/1.10": 143,
        "LoD/1.11": 143,
        "LoD/1.11b": 143,
        "LoD/1.12a": 143,
        "LoD/1.13c": 143,
        "LoD/1.13d": 143,
        "LoD/1.14a": 143,
        "LoD/1.14b": 143,
        "LoD/1.14c": 143,
        "LoD/1.14d": 143
      },
      "stack_frame_sizes": {
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
        "LoD/1.13d": 72,
        "LoD/1.14a": 72,
        "LoD/1.14b": 72,
        "LoD/1.14c": 72,
        "LoD/1.14d": 72
      },
      "basic_block_counts": {
        "LoD/1.07": 39,
        "LoD/1.08": 39,
        "LoD/1.09": 39,
        "LoD/1.09b": 39,
        "LoD/1.09d": 39,
        "LoD/1.10": 39,
        "LoD/1.11": 39,
        "LoD/1.11b": 39,
        "LoD/1.12a": 39,
        "LoD/1.13c": 39,
        "LoD/1.13d": 39,
        "LoD/1.14a": 39,
        "LoD/1.14b": 39,
        "LoD/1.14c": 39,
        "LoD/1.14d": 39
      },
      "loop_counts": {
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
        "LoD/1.13d": 5,
        "LoD/1.14a": 5,
        "LoD/1.14b": 5,
        "LoD/1.14c": 5,
        "LoD/1.14d": 5
      },
      "mnemonic_hashes": {
        "LoD/1.07": "b09f16c0e6a5014f6b150653e76f58a2",
        "LoD/1.08": "b09f16c0e6a5014f6b150653e76f58a2",
        "LoD/1.09": "b09f16c0e6a5014f6b150653e76f58a2",
        "LoD/1.09b": "b09f16c0e6a5014f6b150653e76f58a2",
        "LoD/1.09d": "b09f16c0e6a5014f6b150653e76f58a2",
        "LoD/1.10": "b09f16c0e6a5014f6b150653e76f58a2",
        "LoD/1.11": "b09f16c0e6a5014f6b150653e76f58a2",
        "LoD/1.11b": "b09f16c0e6a5014f6b150653e76f58a2",
        "LoD/1.12a": "b09f16c0e6a5014f6b150653e76f58a2",
        "LoD/1.13c": "b09f16c0e6a5014f6b150653e76f58a2",
        "LoD/1.13d": "b09f16c0e6a5014f6b150653e76f58a2",
        "LoD/1.14a": "b09f16c0e6a5014f6b150653e76f58a2",
        "LoD/1.14b": "b09f16c0e6a5014f6b150653e76f58a2",
        "LoD/1.14c": "b09f16c0e6a5014f6b150653e76f58a2",
        "LoD/1.14d": "b09f16c0e6a5014f6b150653e76f58a2"
      },
      "constants": {
        "LoD/1.07": [
          256,
          2048,
          4220544,
          4220548
        ],
        "LoD/1.08": [
          256,
          2048,
          4220544,
          4220548
        ],
        "LoD/1.09": [
          256,
          2048,
          4220544,
          4220548
        ],
        "LoD/1.09b": [
          256,
          2048,
          4220544,
          4220548
        ],
        "LoD/1.09d": [
          256,
          2048,
          4220544,
          4220548
        ],
        "LoD/1.10": [
          256,
          2048,
          4220544,
          4220548
        ],
        "LoD/1.11": [
          256,
          2048,
          4220544,
          4220548
        ],
        "LoD/1.11b": [
          256,
          2048,
          4220544,
          4220548
        ],
        "LoD/1.12a": [
          256,
          2048,
          4220544,
          4220548
        ],
        "LoD/1.13c": [
          256,
          2048,
          4220544,
          4220548
        ],
        "LoD/1.13d": [
          256,
          2048,
          4220544,
          4220548
        ],
        "LoD/1.14a": [
          256,
          2048,
          4220544,
          4220548
        ],
        "LoD/1.14b": [
          256,
          2048,
          4220544,
          4220548
        ],
        "LoD/1.14c": [
          256,
          2048,
          4220544,
          4220548
        ],
        "LoD/1.14d": [
          256,
          2048,
          4220544,
          4220548
        ]
      },
      "globals": {
        "LoD/1.07": [
          "0x6680|g_apFileDescriptorTable",
          "0x6780|DAT_00406780",
          "0xFFFFFFFFFFBFFFBC|",
          "0x502C|PTR_GetStartupInfoA_0040502c",
          "0x6684|DAT_00406684",
          "0x506C|PTR_GetFileType_0040506c",
          "0x5020|PTR_GetStdHandle_00405020",
          "0x501C|PTR_SetHandleCount_0040501c"
        ],
        "LoD/1.08": [
          "0x6680|g_apFileDescriptorTable",
          "0x6780|DAT_00406780",
          "0xFFFFFFFFFFBFFFBC|",
          "0x502C|PTR_GetStartupInfoA_0040502c",
          "0x6684|DAT_00406684",
          "0x506C|PTR_GetFileType_0040506c",
          "0x5020|PTR_GetStdHandle_00405020",
          "0x501C|PTR_SetHandleCount_0040501c"
        ],
        "LoD/1.09": [
          "0x6680|g_apFileDescriptorTable",
          "0x6780|DAT_00406780",
          "0xFFFFFFFFFFBFFFBC|",
          "0x502C|PTR_GetStartupInfoA_0040502c",
          "0x6684|DAT_00406684",
          "0x506C|PTR_GetFileType_0040506c",
          "0x5020|PTR_GetStdHandle_00405020",
          "0x501C|PTR_SetHandleCount_0040501c"
        ],
        "LoD/1.09b": [
          "0x6680|g_apFileDescriptorTable",
          "0x6780|DAT_00406780",
          "0xFFFFFFFFFFBFFFBC|",
          "0x502C|PTR_GetStartupInfoA_0040502c",
          "0x6684|DAT_00406684",
          "0x506C|PTR_GetFileType_0040506c",
          "0x5020|PTR_GetStdHandle_00405020",
          "0x501C|PTR_SetHandleCount_0040501c"
        ],
        "LoD/1.09d": [
          "0x6680|g_apFileDescriptorTable",
          "0x6780|DAT_00406780",
          "0xFFFFFFFFFFBFFFBC|",
          "0x502C|PTR_GetStartupInfoA_0040502c",
          "0x6684|DAT_00406684",
          "0x506C|PTR_GetFileType_0040506c",
          "0x5020|PTR_GetStdHandle_00405020",
          "0x501C|PTR_SetHandleCount_0040501c"
        ],
        "LoD/1.10": [
          "0x6680|g_apFileDescriptorTable",
          "0x6780|DAT_00406780",
          "0xFFFFFFFFFFBFFFBC|",
          "0x502C|PTR_GetStartupInfoA_0040502c",
          "0x6684|DAT_00406684",
          "0x506C|PTR_GetFileType_0040506c",
          "0x5020|PTR_GetStdHandle_00405020",
          "0x501C|PTR_SetHandleCount_0040501c"
        ],
        "LoD/1.11": [
          "0x6680|g_apFileDescriptorTable",
          "0x6780|DAT_00406780",
          "0xFFFFFFFFFFBFFFBC|",
          "0x502C|PTR_GetStartupInfoA_0040502c",
          "0x6684|DAT_00406684",
          "0x506C|PTR_GetFileType_0040506c",
          "0x5020|PTR_GetStdHandle_00405020",
          "0x501C|PTR_SetHandleCount_0040501c"
        ],
        "LoD/1.11b": [
          "0x6680|g_apFileDescriptorTable",
          "0x6780|DAT_00406780",
          "0xFFFFFFFFFFBFFFBC|",
          "0x502C|PTR_GetStartupInfoA_0040502c",
          "0x6684|DAT_00406684",
          "0x506C|PTR_GetFileType_0040506c",
          "0x5020|PTR_GetStdHandle_00405020",
          "0x501C|PTR_SetHandleCount_0040501c"
        ],
        "LoD/1.12a": [
          "0x6680|g_apFileDescriptorTable",
          "0x6780|DAT_00406780",
          "0xFFFFFFFFFFBFFFBC|",
          "0x502C|PTR_GetStartupInfoA_0040502c",
          "0x6684|DAT_00406684",
          "0x506C|PTR_GetFileType_0040506c",
          "0x5020|PTR_GetStdHandle_00405020",
          "0x501C|PTR_SetHandleCount_0040501c"
        ],
        "LoD/1.13c": [
          "0x6680|g_apFileDescriptorTable",
          "0x6780|DAT_00406780",
          "0xFFFFFFFFFFBFFFBC|",
          "0x502C|PTR_GetStartupInfoA_0040502c",
          "0x6684|DAT_00406684",
          "0x506C|PTR_GetFileType_0040506c",
          "0x5020|PTR_GetStdHandle_00405020",
          "0x501C|PTR_SetHandleCount_0040501c"
        ],
        "LoD/1.13d": [
          "0x6680|g_apFileDescriptorTable",
          "0x6780|DAT_00406780",
          "0xFFFFFFFFFFBFFFBC|",
          "0x502C|PTR_GetStartupInfoA_0040502c",
          "0x6684|DAT_00406684",
          "0x506C|PTR_GetFileType_0040506c",
          "0x5020|PTR_GetStdHandle_00405020",
          "0x501C|PTR_SetHandleCount_0040501c"
        ],
        "LoD/1.14a": [
          "0x6680|g_apFileDescriptorTable",
          "0x6780|DAT_00406780",
          "0xFFFFFFFFFFBFFFBC|",
          "0x502C|PTR_GetStartupInfoA_0040502c",
          "0x6684|DAT_00406684",
          "0x506C|PTR_GetFileType_0040506c",
          "0x5020|PTR_GetStdHandle_00405020",
          "0x501C|PTR_SetHandleCount_0040501c"
        ],
        "LoD/1.14b": [
          "0x6680|g_apFileDescriptorTable",
          "0x6780|DAT_00406780",
          "0xFFFFFFFFFFBFFFBC|",
          "0x502C|PTR_GetStartupInfoA_0040502c",
          "0x6684|DAT_00406684",
          "0x506C|PTR_GetFileType_0040506c",
          "0x5020|PTR_GetStdHandle_00405020",
          "0x501C|PTR_SetHandleCount_0040501c"
        ],
        "LoD/1.14c": [
          "0x6680|g_apFileDescriptorTable",
          "0x6780|DAT_00406780",
          "0xFFFFFFFFFFBFFFBC|",
          "0x502C|PTR_GetStartupInfoA_0040502c",
          "0x6684|DAT_00406684",
          "0x506C|PTR_GetFileType_0040506c",
          "0x5020|PTR_GetStdHandle_00405020",
          "0x501C|PTR_SetHandleCount_0040501c"
        ],
        "LoD/1.14d": [
          "0x6680|g_apFileDescriptorTable",
          "0x6780|DAT_00406780",
          "0xFFFFFFFFFFBFFFBC|",
          "0x502C|PTR_GetStartupInfoA_0040502c",
          "0x6684|DAT_00406684",
          "0x506C|PTR_GetFileType_0040506c",
          "0x5020|PTR_GetStdHandle_00405020",
          "0x501C|PTR_SetHandleCount_0040501c"
        ]
      }
    },
    "diablo ii.exe_InitializeDllHeapAndResources": {
      "addresses": {
        "LoD/1.07": "0x00402541",
        "LoD/1.08": "0x00402541",
        "LoD/1.09": "0x00402541",
        "LoD/1.09b": "0x00402541",
        "LoD/1.09d": "0x00402541",
        "LoD/1.10": "0x00402541",
        "LoD/1.11": "0x00402541",
        "LoD/1.11b": "0x00402541",
        "LoD/1.12a": "0x00402541",
        "LoD/1.13c": "0x00402541",
        "LoD/1.13d": "0x00402541",
        "LoD/1.14a": "0x00402541",
        "LoD/1.14b": "0x00402541",
        "LoD/1.14c": "0x00402541",
        "LoD/1.14d": "0x00402541"
      },
      "rvas": {
        "LoD/1.07": "0x2541",
        "LoD/1.08": "0x2541",
        "LoD/1.09": "0x2541",
        "LoD/1.09b": "0x2541",
        "LoD/1.09d": "0x2541",
        "LoD/1.10": "0x2541",
        "LoD/1.11": "0x2541",
        "LoD/1.11b": "0x2541",
        "LoD/1.12a": "0x2541",
        "LoD/1.13c": "0x2541",
        "LoD/1.13d": "0x2541",
        "LoD/1.14a": "0x2541",
        "LoD/1.14b": "0x2541",
        "LoD/1.14c": "0x2541",
        "LoD/1.14d": "0x2541"
      },
      "sizes": {
        "LoD/1.07": 60,
        "LoD/1.08": 60,
        "LoD/1.09": 60,
        "LoD/1.09b": 60,
        "LoD/1.09d": 60,
        "LoD/1.10": 60,
        "LoD/1.11": 60,
        "LoD/1.11b": 60,
        "LoD/1.12a": 60,
        "LoD/1.13c": 60,
        "LoD/1.13d": 60,
        "LoD/1.14a": 60,
        "LoD/1.14b": 60,
        "LoD/1.14c": 60,
        "LoD/1.14d": 60
      },
      "name": "InitializeDllHeapAndResources",
      "signature": "int InitializeDllHeapAndResources(int nSerializationFlag)",
      "calling_convention": "__cdecl",
      "return_type": "int",
      "comment": "Initialize DLL heap and core resources during process attachment.\n\nAlgorithm:\n1. Create global heap with serialization based on attachment context\n2. Configure heap flags: serialized if nSerializationFlag is 0, non-serialized otherwise  \n3. Set initial heap size to 4096 bytes (0x1000) with unlimited growth\n4. Store heap handle in global variable g_hHeap for DLL lifetime management\n5. Call initialization function FUN_1001d4d1() to set up additional resources\n6. On initialization failure, clean up by destroying the created heap\n7. Return success (1) only if both heap creation and resource initialization succeed\n\nParameters:\nnSerializationFlag (int): Process attachment context flag\n  - 0: Enable heap serialization for thread-safe access\n  - Non-zero: Disable serialization for single-threaded or externally synchronized access\n\nReturns:\n1: Successfully created heap and initialized all DLL resources\n0: Failure in heap creation or resource initialization\n\nSpecial Cases:\n- If HeapCreate fails, immediately returns 0 without cleanup\n- If FUN_1001d4d1() fails, destroys heap before returning 0\n- Global g_hHeap remains NULL on any failure path\n\nMagic Numbers Reference:\n0x1000 (4096): Initial heap size in bytes, allows small initial allocations\n0: Unlimited maximum heap size, heap can grow as needed",
      "name_source": "LoD/1.07",
      "method": "CAL",
      "index": "CAL:bc2b52fbed2a111d882dea2cfa9a0dab",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "e33a4c6c562d51a2fcc8e07bee94f1d6",
        "CFG": "a45e81226b7499c95fa78cf99e84c814",
        "PRO": "16847fa79110f65f85652b26f0a066ad",
        "CAL": "bc2b52fbed2a111d882dea2cfa9a0dab",
        "CON": null,
        "APS": null
      },
      "callees": {
        "LoD/1.07": [
          "InitializeBufferManager|0x4032A5",
          "HeapCreate|0x1E",
          "HeapDestroy|0x1D"
        ],
        "LoD/1.08": [
          "HeapCreate|0x1E",
          "InitializeBufferManager|0x4032A5",
          "HeapDestroy|0x1D"
        ],
        "LoD/1.09": [
          "HeapCreate|0x1E",
          "InitializeBufferManager|0x4032A5",
          "HeapDestroy|0x1D"
        ],
        "LoD/1.09b": [
          "HeapCreate|0x1E",
          "HeapDestroy|0x1D",
          "InitializeBufferManager|0x4032A5"
        ],
        "LoD/1.09d": [
          "InitializeBufferManager|0x4032A5",
          "HeapDestroy|0x1D",
          "HeapCreate|0x1E"
        ],
        "LoD/1.10": [
          "InitializeBufferManager|0x4032A5",
          "HeapDestroy|0x1D",
          "HeapCreate|0x1E"
        ],
        "LoD/1.11": [
          "InitializeBufferManager|0x4032A5",
          "HeapCreate|0x1E",
          "HeapDestroy|0x1D"
        ],
        "LoD/1.11b": [
          "InitializeBufferManager|0x4032A5",
          "HeapDestroy|0x1D",
          "HeapCreate|0x1E"
        ],
        "LoD/1.12a": [
          "HeapDestroy|0x1D",
          "InitializeBufferManager|0x4032A5",
          "HeapCreate|0x1E"
        ],
        "LoD/1.13c": [
          "HeapDestroy|0x1D",
          "InitializeBufferManager|0x4032A5",
          "HeapCreate|0x1E"
        ],
        "LoD/1.13d": [
          "InitializeBufferManager|0x4032A5",
          "HeapDestroy|0x1D",
          "HeapCreate|0x1E"
        ],
        "LoD/1.14a": [
          "HeapCreate|0x1E",
          "HeapDestroy|0x1D",
          "InitializeBufferManager|0x4032A5"
        ],
        "LoD/1.14b": [
          "HeapCreate|0x1E",
          "HeapDestroy|0x1D",
          "InitializeBufferManager|0x4032A5"
        ],
        "LoD/1.14c": [
          "HeapDestroy|0x1D",
          "InitializeBufferManager|0x4032A5",
          "HeapCreate|0x1E"
        ],
        "LoD/1.14d": [
          "HeapCreate|0x1E",
          "HeapDestroy|0x1D",
          "InitializeBufferManager|0x4032A5"
        ]
      },
      "callers": {
        "LoD/1.07": [
          "entry|0x4014E3"
        ],
        "LoD/1.08": [
          "entry|0x4014E3"
        ],
        "LoD/1.09": [
          "entry|0x4014E3"
        ],
        "LoD/1.09b": [
          "entry|0x4014E3"
        ],
        "LoD/1.09d": [
          "entry|0x4014E3"
        ],
        "LoD/1.10": [
          "entry|0x4014E3"
        ],
        "LoD/1.11": [
          "entry|0x4014E3"
        ],
        "LoD/1.11b": [
          "entry|0x4014E3"
        ],
        "LoD/1.12a": [
          "entry|0x4014E3"
        ],
        "LoD/1.13c": [
          "entry|0x4014E3"
        ],
        "LoD/1.13d": [
          "entry|0x4014E3"
        ],
        "LoD/1.14a": [
          "entry|0x4014E3"
        ],
        "LoD/1.14b": [
          "entry|0x4014E3"
        ],
        "LoD/1.14c": [
          "entry|0x4014E3"
        ],
        "LoD/1.14d": [
          "entry|0x4014E3"
        ]
      },
      "instruction_counts": {
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
        "LoD/1.13d": 20,
        "LoD/1.14a": 20,
        "LoD/1.14b": 20,
        "LoD/1.14c": 20,
        "LoD/1.14d": 20
      },
      "stack_frame_sizes": {
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
        "LoD/1.13d": 8,
        "LoD/1.14a": 8,
        "LoD/1.14b": 8,
        "LoD/1.14c": 8,
        "LoD/1.14d": 8
      },
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
        "LoD/1.13d": 5,
        "LoD/1.14a": 5,
        "LoD/1.14b": 5,
        "LoD/1.14c": 5,
        "LoD/1.14d": 5
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
        "LoD/1.13d": 0,
        "LoD/1.14a": 0,
        "LoD/1.14b": 0,
        "LoD/1.14c": 0,
        "LoD/1.14d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "e33a4c6c562d51a2fcc8e07bee94f1d6",
        "LoD/1.08": "e33a4c6c562d51a2fcc8e07bee94f1d6",
        "LoD/1.09": "e33a4c6c562d51a2fcc8e07bee94f1d6",
        "LoD/1.09b": "e33a4c6c562d51a2fcc8e07bee94f1d6",
        "LoD/1.09d": "e33a4c6c562d51a2fcc8e07bee94f1d6",
        "LoD/1.10": "e33a4c6c562d51a2fcc8e07bee94f1d6",
        "LoD/1.11": "e33a4c6c562d51a2fcc8e07bee94f1d6",
        "LoD/1.11b": "e33a4c6c562d51a2fcc8e07bee94f1d6",
        "LoD/1.12a": "e33a4c6c562d51a2fcc8e07bee94f1d6",
        "LoD/1.13c": "e33a4c6c562d51a2fcc8e07bee94f1d6",
        "LoD/1.13d": "e33a4c6c562d51a2fcc8e07bee94f1d6",
        "LoD/1.14a": "e33a4c6c562d51a2fcc8e07bee94f1d6",
        "LoD/1.14b": "e33a4c6c562d51a2fcc8e07bee94f1d6",
        "LoD/1.14c": "e33a4c6c562d51a2fcc8e07bee94f1d6",
        "LoD/1.14d": "e33a4c6c562d51a2fcc8e07bee94f1d6"
      },
      "constants": {
        "LoD/1.07": [
          4096
        ],
        "LoD/1.08": [
          4096
        ],
        "LoD/1.09": [
          4096
        ],
        "LoD/1.09b": [
          4096
        ],
        "LoD/1.09d": [
          4096
        ],
        "LoD/1.10": [
          4096
        ],
        "LoD/1.11": [
          4096
        ],
        "LoD/1.11b": [
          4096
        ],
        "LoD/1.12a": [
          4096
        ],
        "LoD/1.13c": [
          4096
        ],
        "LoD/1.13d": [
          4096
        ],
        "LoD/1.14a": [
          4096
        ],
        "LoD/1.14b": [
          4096
        ],
        "LoD/1.14c": [
          4096
        ],
        "LoD/1.14d": [
          4096
        ]
      },
      "globals": {
        "LoD/1.07": [
          "0xFFFFFFFFFFC00004|",
          "0x5074|PTR_HeapCreate_00405074",
          "0x6674|g_hHeapHandle",
          "0x5070|PTR_HeapDestroy_00405070"
        ],
        "LoD/1.08": [
          "0xFFFFFFFFFFC00004|",
          "0x5074|PTR_HeapCreate_00405074",
          "0x6674|g_hHeapHandle",
          "0x5070|PTR_HeapDestroy_00405070"
        ],
        "LoD/1.09": [
          "0xFFFFFFFFFFC00004|",
          "0x5074|PTR_HeapCreate_00405074",
          "0x6674|g_hHeapHandle",
          "0x5070|PTR_HeapDestroy_00405070"
        ],
        "LoD/1.09b": [
          "0xFFFFFFFFFFC00004|",
          "0x5074|PTR_HeapCreate_00405074",
          "0x6674|g_hHeapHandle",
          "0x5070|PTR_HeapDestroy_00405070"
        ],
        "LoD/1.09d": [
          "0xFFFFFFFFFFC00004|",
          "0x5074|PTR_HeapCreate_00405074",
          "0x6674|g_hHeapHandle",
          "0x5070|PTR_HeapDestroy_00405070"
        ],
        "LoD/1.10": [
          "0xFFFFFFFFFFC00004|",
          "0x5074|PTR_HeapCreate_00405074",
          "0x6674|g_hHeap",
          "0x5070|PTR_HeapDestroy_00405070"
        ],
        "LoD/1.11": [
          "0xFFFFFFFFFFC00004|",
          "0x5074|PTR_HeapCreate_00405074",
          "0x6674|g_hHeapHandle",
          "0x5070|PTR_HeapDestroy_00405070"
        ],
        "LoD/1.11b": [
          "0xFFFFFFFFFFC00004|",
          "0x5074|PTR_HeapCreate_00405074",
          "0x6674|g_hHeapHandle",
          "0x5070|PTR_HeapDestroy_00405070"
        ],
        "LoD/1.12a": [
          "0xFFFFFFFFFFC00004|",
          "0x5074|PTR_HeapCreate_00405074",
          "0x6674|g_hHeapHandle",
          "0x5070|PTR_HeapDestroy_00405070"
        ],
        "LoD/1.13c": [
          "0xFFFFFFFFFFC00004|",
          "0x5074|PTR_HeapCreate_00405074",
          "0x6674|g_hHeapHandle",
          "0x5070|PTR_HeapDestroy_00405070"
        ],
        "LoD/1.13d": [
          "0xFFFFFFFFFFC00004|",
          "0x5074|PTR_HeapCreate_00405074",
          "0x6674|g_hHeapHandle",
          "0x5070|PTR_HeapDestroy_00405070"
        ],
        "LoD/1.14a": [
          "0xFFFFFFFFFFC00004|",
          "0x5074|PTR_HeapCreate_00405074",
          "0x6674|g_hHeapHandle",
          "0x5070|PTR_HeapDestroy_00405070"
        ],
        "LoD/1.14b": [
          "0xFFFFFFFFFFC00004|",
          "0x5074|PTR_HeapCreate_00405074",
          "0x6674|g_hHeapHandle",
          "0x5070|PTR_HeapDestroy_00405070"
        ],
        "LoD/1.14c": [
          "0xFFFFFFFFFFC00004|",
          "0x5074|PTR_HeapCreate_00405074",
          "0x6674|g_hHeapHandle",
          "0x5070|PTR_HeapDestroy_00405070"
        ],
        "LoD/1.14d": [
          "0xFFFFFFFFFFC00004|",
          "0x5074|PTR_HeapCreate_00405074",
          "0x6674|g_hHeapHandle",
          "0x5070|PTR_HeapDestroy_00405070"
        ]
      }
    },
    "diablo ii.exe_GlobalUnwind2": {
      "addresses": {
        "LoD/1.07": "0x00402580",
        "LoD/1.08": "0x00402580",
        "LoD/1.09": "0x00402580",
        "LoD/1.09b": "0x00402580",
        "LoD/1.09d": "0x00402580",
        "LoD/1.10": "0x00402580",
        "LoD/1.11": "0x00402580",
        "LoD/1.11b": "0x00402580",
        "LoD/1.12a": "0x00402580",
        "LoD/1.13c": "0x00402580",
        "LoD/1.13d": "0x00402580",
        "LoD/1.14a": "0x00402580",
        "LoD/1.14b": "0x00402580",
        "LoD/1.14c": "0x00402580",
        "LoD/1.14d": "0x00402580"
      },
      "rvas": {
        "LoD/1.07": "0x2580",
        "LoD/1.08": "0x2580",
        "LoD/1.09": "0x2580",
        "LoD/1.09b": "0x2580",
        "LoD/1.09d": "0x2580",
        "LoD/1.10": "0x2580",
        "LoD/1.11": "0x2580",
        "LoD/1.11b": "0x2580",
        "LoD/1.12a": "0x2580",
        "LoD/1.13c": "0x2580",
        "LoD/1.13d": "0x2580",
        "LoD/1.14a": "0x2580",
        "LoD/1.14b": "0x2580",
        "LoD/1.14c": "0x2580",
        "LoD/1.14d": "0x2580"
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
        "LoD/1.13d": 32,
        "LoD/1.14a": 32,
        "LoD/1.14b": 32,
        "LoD/1.14c": 32,
        "LoD/1.14d": 32
      },
      "name": "GlobalUnwind2",
      "signature": "void GlobalUnwind2(void * pTargetFrame)",
      "calling_convention": "__cdecl",
      "return_type": "void",
      "comment": "Performs global stack unwinding to a specified frame using Windows RtlUnwind API.\n\nAlgorithm:\n1. Validate input parameter (target frame pointer)\n2. Save all non-volatile registers (EBX, ESI, EDI, EBP) to preserve caller state\n3. Prepare RtlUnwind parameters:\n   - TargetFrame: Caller-specified frame to unwind to\n   - TargetIp: Fixed continuation address (0x1001cdf0) for post-unwind execution\n   - ExceptionRecord: NULL (no exception context)\n   - ReturnValue: NULL (no specific return value)\n4. Call Windows RtlUnwind API to perform structured exception unwinding\n5. Restore all saved registers maintaining calling convention\n6. Return to caller with stack properly unwound\n\nParameters:\npTargetFrame (void*): Target stack frame pointer to unwind to. Must be valid frame \n                     pointer from current call chain. NULL terminates unwinding at \n                     top-level exception handler.\n\nReturns:\nvoid: Function does not return value. Unwind operation modifies stack state and \n      control flow continues at TargetIp (0x1001cdf0) after unwinding completes.\n\nSpecial Cases:\n- Magic Number 0x1001cdf0: Hardcoded continuation address where execution resumes \n  after unwinding. Points to register restoration sequence (POP EBP instruction).\n- NULL pTargetFrame: Unwinds entire stack to process termination handler\n- Invalid frame pointer: RtlUnwind handles validation and may terminate process\n\nError Handling:\nRtlUnwind handles all error conditions including invalid frame pointers, corrupted \nstack, and access violations. Function acts as thin wrapper without additional \nvalidation or error recovery.",
      "name_source": "LoD/1.07",
      "method": "API",
      "index": "API:671dff5ace8aa8c39bead14f6d282075",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": "671dff5ace8aa8c39bead14f6d282075",
        "MNE": "059e9bb2efc1de93bfe21089d0ad96d3",
        "CFG": "62dd7eecce7740c82c988187e13c22fe",
        "PRO": "56b2c198681b74637b7f6d69d46bf35f",
        "CAL": null,
        "CON": null,
        "APS": null
      },
      "callees": {
        "LoD/1.07": [
          "RtlUnwind|0x404066"
        ],
        "LoD/1.08": [
          "RtlUnwind|0x404066"
        ],
        "LoD/1.09": [
          "RtlUnwind|0x404066"
        ],
        "LoD/1.09b": [
          "RtlUnwind|0x404066"
        ],
        "LoD/1.09d": [
          "RtlUnwind|0x404066"
        ],
        "LoD/1.10": [
          "RtlUnwind|0x404066"
        ],
        "LoD/1.11": [
          "RtlUnwind|0x404066"
        ],
        "LoD/1.11b": [
          "RtlUnwind|0x404066"
        ],
        "LoD/1.12a": [
          "RtlUnwind|0x404066"
        ],
        "LoD/1.13c": [
          "RtlUnwind|0x404066"
        ],
        "LoD/1.13d": [
          "RtlUnwind|0x404066"
        ],
        "LoD/1.14a": [
          "RtlUnwind|0x404066"
        ],
        "LoD/1.14b": [
          "RtlUnwind|0x404066"
        ],
        "LoD/1.14c": [
          "RtlUnwind|0x404066"
        ],
        "LoD/1.14d": [
          "RtlUnwind|0x404066"
        ]
      },
      "instruction_counts": {
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
        "LoD/1.13d": 18,
        "LoD/1.14a": 18,
        "LoD/1.14b": 18,
        "LoD/1.14c": 18,
        "LoD/1.14d": 18
      },
      "stack_frame_sizes": {
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
        "LoD/1.13d": 8,
        "LoD/1.14a": 8,
        "LoD/1.14b": 8,
        "LoD/1.14c": 8,
        "LoD/1.14d": 8
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
        "LoD/1.13d": 1,
        "LoD/1.14a": 1,
        "LoD/1.14b": 1,
        "LoD/1.14c": 1,
        "LoD/1.14d": 1
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
        "LoD/1.13d": 0,
        "LoD/1.14a": 0,
        "LoD/1.14b": 0,
        "LoD/1.14c": 0,
        "LoD/1.14d": 0
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
        "LoD/1.13d": "059e9bb2efc1de93bfe21089d0ad96d3",
        "LoD/1.14a": "059e9bb2efc1de93bfe21089d0ad96d3",
        "LoD/1.14b": "059e9bb2efc1de93bfe21089d0ad96d3",
        "LoD/1.14c": "059e9bb2efc1de93bfe21089d0ad96d3",
        "LoD/1.14d": "059e9bb2efc1de93bfe21089d0ad96d3"
      },
      "constants": {
        "LoD/1.07": [
          4203928
        ],
        "LoD/1.08": [
          4203928
        ],
        "LoD/1.09": [
          4203928
        ],
        "LoD/1.09b": [
          4203928
        ],
        "LoD/1.09d": [
          4203928
        ],
        "LoD/1.10": [
          4203928
        ],
        "LoD/1.11": [
          4203928
        ],
        "LoD/1.11b": [
          4203928
        ],
        "LoD/1.12a": [
          4203928
        ],
        "LoD/1.13c": [
          4203928
        ],
        "LoD/1.13d": [
          4203928
        ],
        "LoD/1.14a": [
          4203928
        ],
        "LoD/1.14b": [
          4203928
        ],
        "LoD/1.14c": [
          4203928
        ],
        "LoD/1.14d": [
          4203928
        ]
      },
      "globals": {
        "LoD/1.07": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.08": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.09": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.09b": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.09d": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.10": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.11": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.11b": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.12a": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.13c": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.13d": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.14a": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.14b": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.14c": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.14d": [
          "0xFFFFFFFFFFC00004|"
        ]
      }
    },
    "diablo ii.exe_LocalUnwindTwo": {
      "addresses": {
        "LoD/1.07": "0x004025C2",
        "LoD/1.08": "0x004025C2",
        "LoD/1.09": "0x004025C2",
        "LoD/1.09b": "0x004025C2",
        "LoD/1.09d": "0x004025C2",
        "LoD/1.10": "0x004025C2",
        "LoD/1.11": "0x004025C2",
        "LoD/1.11b": "0x004025C2",
        "LoD/1.12a": "0x004025C2",
        "LoD/1.13c": "0x004025C2",
        "LoD/1.13d": "0x004025C2",
        "LoD/1.14a": "0x004025C2",
        "LoD/1.14b": "0x004025C2",
        "LoD/1.14c": "0x004025C2",
        "LoD/1.14d": "0x004025C2"
      },
      "rvas": {
        "LoD/1.07": "0x25C2",
        "LoD/1.08": "0x25C2",
        "LoD/1.09": "0x25C2",
        "LoD/1.09b": "0x25C2",
        "LoD/1.09d": "0x25C2",
        "LoD/1.10": "0x25C2",
        "LoD/1.11": "0x25C2",
        "LoD/1.11b": "0x25C2",
        "LoD/1.12a": "0x25C2",
        "LoD/1.13c": "0x25C2",
        "LoD/1.13d": "0x25C2",
        "LoD/1.14a": "0x25C2",
        "LoD/1.14b": "0x25C2",
        "LoD/1.14c": "0x25C2",
        "LoD/1.14d": "0x25C2"
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
        "LoD/1.13d": 104,
        "LoD/1.14a": 104,
        "LoD/1.14b": 104,
        "LoD/1.14c": 104,
        "LoD/1.14d": 104
      },
      "name": "LocalUnwindTwo",
      "signature": "void LocalUnwindTwo(SehFrame * pSehFrame, int nTargetLevel)",
      "calling_convention": "__cdecl",
      "return_type": "void",
      "comment": "Performs structured exception handling (SEH) local unwinding to a target level.\n\nAlgorithm:\n1. Setup exception registration frame with current exception list\n2. Enter loop to process each unwind level from current to target\n3. Load unwind table pointer from SEH frame at offset +8\n4. Load current level from SEH frame at offset +12  \n5. Check termination conditions: level -1 (end) or target level reached\n6. Calculate unwind record index using current level * 12 bytes\n7. Load previous level from unwind table entry at offset +0\n8. Update SEH frame current level to previous level\n9. Check exception filter flag at unwind table offset +4\n10. If filter flag is 0, call exception filter function and cleanup handler\n11. Continue loop until target level or end reached\n12. Restore previous exception list and return\n\nParameters:\npSehFrame (SehFrame *): Pointer to SEH frame containing unwind table and current level\nnTargetLevel (int): Target unwind level to stop unwinding at (-1 means unwind all)\n\nReturns:\nvoid: No return value, modifies SEH frame state directly\n\nSpecial Cases:\n- If current level is -1, unwinding is already complete\n- If target level equals current level, no unwinding needed  \n- Filter flag 0x00000000 indicates active exception handler that needs cleanup\n\nStructure Layout:\nSehFrame (16 bytes):\nOffset Size Field Name      Type              Description\n0x00   4    pExceptionRecord void*            Pointer to exception record\n0x04   4    dwCurrentLevel   uint             Current exception nesting level  \n0x08   4    pUnwindTable     SehUnwindRecord* Pointer to unwind table array\n0x0C   4    dwTryLevel       uint             Current try block level\n\nSehUnwindRecord (12 bytes):\nOffset Size Field Name      Type              Description  \n0x00   4    dwPrevLevel     uint             Previous exception level in chain\n0x04   4    dwFlags         uint             Exception filter flags (0=active)\n0x08   4    pfnHandler      void*            Exception handler function pointer\n\nMagic Numbers Reference:\n0x08 (8): Offset to unwind table pointer in SEH frame\n0x0C (12): Offset to current level in SEH frame, also stride of unwind records\n0x04 (4): Offset to flags field in unwind record\n0x08 (8): Offset to handler function in unwind record\n0xFFFFFFFF (-1): End-of-chain marker for exception levels",
      "name_source": "LoD/1.07",
      "method": "CON",
      "index": "CON:24530866f964f891172a0f266c75de54",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "cd4ab8e23ed6997cd2e2434b8d375458",
        "CFG": "d54d0bf1b3435e560f9567fde0a425c3",
        "PRO": "6119d20752442d876f4a746c02156711",
        "CAL": null,
        "CON": "24530866f964f891172a0f266c75de54",
        "APS": null
      },
      "callees": {
        "LoD/1.07": [
          "StoreSehContext|0x402656"
        ],
        "LoD/1.08": [
          "StoreSehContext|0x402656"
        ],
        "LoD/1.09": [
          "StoreSehContext|0x402656"
        ],
        "LoD/1.09b": [
          "StoreSehContext|0x402656"
        ],
        "LoD/1.09d": [
          "StoreSehContext|0x402656"
        ],
        "LoD/1.10": [
          "StoreSehContext|0x402656"
        ],
        "LoD/1.11": [
          "StoreSehContext|0x402656"
        ],
        "LoD/1.11b": [
          "StoreSehContext|0x402656"
        ],
        "LoD/1.12a": [
          "StoreSehContext|0x402656"
        ],
        "LoD/1.13c": [
          "StoreSehContext|0x402656"
        ],
        "LoD/1.13d": [
          "StoreSehContext|0x402656"
        ],
        "LoD/1.14a": [
          "StoreSehContext|0x402656"
        ],
        "LoD/1.14b": [
          "StoreSehContext|0x402656"
        ],
        "LoD/1.14c": [
          "StoreSehContext|0x402656"
        ],
        "LoD/1.14d": [
          "StoreSehContext|0x402656"
        ]
      },
      "callers": {
        "LoD/1.07": [
          "__seh_longjmp_unwind@4|0x402735"
        ],
        "LoD/1.08": [
          "__seh_longjmp_unwind@4|0x402735"
        ],
        "LoD/1.09": [
          "__seh_longjmp_unwind@4|0x402735"
        ],
        "LoD/1.09b": [
          "__seh_longjmp_unwind@4|0x402735"
        ],
        "LoD/1.09d": [
          "__seh_longjmp_unwind@4|0x402735"
        ],
        "LoD/1.10": [
          "__seh_longjmp_unwind@4|0x402735"
        ],
        "LoD/1.11": [
          "__seh_longjmp_unwind@4|0x402735"
        ],
        "LoD/1.11b": [
          "__seh_longjmp_unwind@4|0x402735"
        ],
        "LoD/1.12a": [
          "__seh_longjmp_unwind@4|0x402735"
        ],
        "LoD/1.13c": [
          "__seh_longjmp_unwind@4|0x402735"
        ],
        "LoD/1.13d": [
          "__seh_longjmp_unwind@4|0x402735"
        ],
        "LoD/1.14a": [
          "__seh_longjmp_unwind@4|0x402735"
        ],
        "LoD/1.14b": [
          "__seh_longjmp_unwind@4|0x402735"
        ],
        "LoD/1.14c": [
          "__seh_longjmp_unwind@4|0x402735"
        ],
        "LoD/1.14d": [
          "__seh_longjmp_unwind@4|0x402735"
        ]
      },
      "instruction_counts": {
        "LoD/1.07": 33,
        "LoD/1.08": 33,
        "LoD/1.09": 33,
        "LoD/1.09b": 33,
        "LoD/1.09d": 33,
        "LoD/1.10": 33,
        "LoD/1.11": 33,
        "LoD/1.11b": 33,
        "LoD/1.12a": 33,
        "LoD/1.13c": 33,
        "LoD/1.13d": 33,
        "LoD/1.14a": 33,
        "LoD/1.14b": 33,
        "LoD/1.14c": 33,
        "LoD/1.14d": 33
      },
      "stack_frame_sizes": {
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
        "LoD/1.13d": 32,
        "LoD/1.14a": 32,
        "LoD/1.14b": 32,
        "LoD/1.14c": 32,
        "LoD/1.14d": 32
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
        "LoD/1.13d": 7,
        "LoD/1.14a": 7,
        "LoD/1.14b": 7,
        "LoD/1.14c": 7,
        "LoD/1.14d": 7
      },
      "loop_counts": {
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
        "LoD/1.13d": 1,
        "LoD/1.14a": 1,
        "LoD/1.14b": 1,
        "LoD/1.14c": 1,
        "LoD/1.14d": 1
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
        "LoD/1.13d": "cd4ab8e23ed6997cd2e2434b8d375458",
        "LoD/1.14a": "cd4ab8e23ed6997cd2e2434b8d375458",
        "LoD/1.14b": "cd4ab8e23ed6997cd2e2434b8d375458",
        "LoD/1.14c": "cd4ab8e23ed6997cd2e2434b8d375458",
        "LoD/1.14d": "cd4ab8e23ed6997cd2e2434b8d375458"
      },
      "constants": {
        "LoD/1.07": [
          257,
          4203936
        ],
        "LoD/1.08": [
          257,
          4203936
        ],
        "LoD/1.09": [
          257,
          4203936
        ],
        "LoD/1.09b": [
          257,
          4203936
        ],
        "LoD/1.09d": [
          257,
          4203936
        ],
        "LoD/1.10": [
          257,
          4203936
        ],
        "LoD/1.11": [
          257,
          4203936
        ],
        "LoD/1.11b": [
          257,
          4203936
        ],
        "LoD/1.12a": [
          257,
          4203936
        ],
        "LoD/1.13c": [
          257,
          4203936
        ],
        "LoD/1.13d": [
          257,
          4203936
        ],
        "LoD/1.14a": [
          257,
          4203936
        ],
        "LoD/1.14b": [
          257,
          4203936
        ],
        "LoD/1.14c": [
          257,
          4203936
        ],
        "LoD/1.14d": [
          257,
          4203936
        ]
      },
      "globals": {
        "LoD/1.07": [
          "0xFFFFFFFFFFC00004|",
          "0x25A0|LAB_004025a0",
          "0xFF9FF000|ExceptionList",
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFBFFFEC|"
        ],
        "LoD/1.08": [
          "0xFFFFFFFFFFC00004|",
          "0x25A0|LAB_004025a0",
          "0xFF9FF000|ExceptionList",
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFBFFFEC|"
        ],
        "LoD/1.09": [
          "0xFFFFFFFFFFC00004|",
          "0x25A0|LAB_004025a0",
          "0xFF9FF000|ExceptionList",
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFBFFFEC|"
        ],
        "LoD/1.09b": [
          "0xFFFFFFFFFFC00004|",
          "0x25A0|LAB_004025a0",
          "0xFF9FF000|ExceptionList",
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFBFFFEC|"
        ],
        "LoD/1.09d": [
          "0xFFFFFFFFFFC00004|",
          "0x25A0|LAB_004025a0",
          "0xFF9FF000|ExceptionList",
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFBFFFEC|"
        ],
        "LoD/1.10": [
          "0xFFFFFFFFFFC00004|",
          "0x25A0|LAB_004025a0",
          "0xFF9FF000|ExceptionList",
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFBFFFEC|"
        ],
        "LoD/1.11": [
          "0xFFFFFFFFFFC00004|",
          "0x25A0|LAB_004025a0",
          "0xFF9FF000|ExceptionList",
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFBFFFEC|"
        ],
        "LoD/1.11b": [
          "0xFFFFFFFFFFC00004|",
          "0x25A0|LAB_004025a0",
          "0xFF9FF000|ExceptionList",
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFBFFFEC|"
        ],
        "LoD/1.12a": [
          "0xFFFFFFFFFFC00004|",
          "0x25A0|LAB_004025a0",
          "0xFF9FF000|ExceptionList",
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFBFFFEC|"
        ],
        "LoD/1.13c": [
          "0xFFFFFFFFFFC00004|",
          "0x25A0|LAB_004025a0",
          "0xFF9FF000|ExceptionList",
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFBFFFEC|"
        ],
        "LoD/1.13d": [
          "0xFFFFFFFFFFC00004|",
          "0x25A0|LAB_004025a0",
          "0xFF9FF000|ExceptionList",
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFBFFFEC|"
        ],
        "LoD/1.14a": [
          "0xFFFFFFFFFFC00004|",
          "0x25A0|LAB_004025a0",
          "0xFF9FF000|ExceptionList",
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFBFFFEC|"
        ],
        "LoD/1.14b": [
          "0xFFFFFFFFFFC00004|",
          "0x25A0|LAB_004025a0",
          "0xFF9FF000|ExceptionList",
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFBFFFEC|"
        ],
        "LoD/1.14c": [
          "0xFFFFFFFFFFC00004|",
          "0x25A0|LAB_004025a0",
          "0xFF9FF000|ExceptionList",
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFBFFFEC|"
        ],
        "LoD/1.14d": [
          "0xFFFFFFFFFFC00004|",
          "0x25A0|LAB_004025a0",
          "0xFF9FF000|ExceptionList",
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFBFFFEC|"
        ]
      }
    },
    "diablo ii.exe_StoreSehContext": {
      "addresses": {
        "LoD/1.07": "0x00402656",
        "LoD/1.08": "0x00402656",
        "LoD/1.09": "0x00402656",
        "LoD/1.09b": "0x00402656",
        "LoD/1.09d": "0x00402656",
        "LoD/1.10": "0x00402656",
        "LoD/1.11": "0x00402656",
        "LoD/1.11b": "0x00402656",
        "LoD/1.12a": "0x00402656",
        "LoD/1.13c": "0x00402656",
        "LoD/1.13d": "0x00402656",
        "LoD/1.14a": "0x00402656",
        "LoD/1.14b": "0x00402656",
        "LoD/1.14c": "0x00402656",
        "LoD/1.14d": "0x00402656"
      },
      "rvas": {
        "LoD/1.07": "0x2656",
        "LoD/1.08": "0x2656",
        "LoD/1.09": "0x2656",
        "LoD/1.09b": "0x2656",
        "LoD/1.09d": "0x2656",
        "LoD/1.10": "0x2656",
        "LoD/1.11": "0x2656",
        "LoD/1.11b": "0x2656",
        "LoD/1.12a": "0x2656",
        "LoD/1.13c": "0x2656",
        "LoD/1.13d": "0x2656",
        "LoD/1.14a": "0x2656",
        "LoD/1.14b": "0x2656",
        "LoD/1.14c": "0x2656",
        "LoD/1.14d": "0x2656"
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
        "LoD/1.13d": 24,
        "LoD/1.14a": 24,
        "LoD/1.14b": 24,
        "LoD/1.14c": 24,
        "LoD/1.14d": 24
      },
      "name": "StoreSehContext",
      "signature": "void StoreSehContext(void)",
      "calling_convention": "__stdcall",
      "return_type": "void",
      "comment": "Stores exception handling context for SEH frame setup.\n\nAlgorithm:\n1. Load static exception frame structure pointer into EBX\n2. Write return address from stack [EBP+8] to frame offset +8\n3. Write exception context (EAX) to frame offset +4\n4. Write current frame pointer (EBP) to frame offset +C (12)\n5. Return with stack cleanup (RET 0x4)\n\nParameters:\n- dwExceptionContext (EAX): Exception context value to store\n\nReturns:\n- void\n\nRelated Functions:\n- Called by __local_unwind2 exception unwinding handler",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:ed17ad9d511f6e330c2b6a62378d83cf",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "ed17ad9d511f6e330c2b6a62378d83cf",
        "CFG": "8bed5312de6328769ba92aea43d25c3f",
        "PRO": "63222adeb34f4a3aa53c9dd3f54ccff5",
        "CAL": null,
        "CON": null,
        "APS": null
      },
      "callers": {
        "LoD/1.07": [
          "LocalUnwindTwo|0x4025C2"
        ],
        "LoD/1.08": [
          "LocalUnwindTwo|0x4025C2"
        ],
        "LoD/1.09": [
          "LocalUnwindTwo|0x4025C2"
        ],
        "LoD/1.09b": [
          "LocalUnwindTwo|0x4025C2"
        ],
        "LoD/1.09d": [
          "LocalUnwindTwo|0x4025C2"
        ],
        "LoD/1.10": [
          "LocalUnwindTwo|0x4025C2"
        ],
        "LoD/1.11": [
          "LocalUnwindTwo|0x4025C2"
        ],
        "LoD/1.11b": [
          "LocalUnwindTwo|0x4025C2"
        ],
        "LoD/1.12a": [
          "LocalUnwindTwo|0x4025C2"
        ],
        "LoD/1.13c": [
          "LocalUnwindTwo|0x4025C2"
        ],
        "LoD/1.13d": [
          "LocalUnwindTwo|0x4025C2"
        ],
        "LoD/1.14a": [
          "LocalUnwindTwo|0x4025C2"
        ],
        "LoD/1.14b": [
          "LocalUnwindTwo|0x4025C2"
        ],
        "LoD/1.14c": [
          "LocalUnwindTwo|0x4025C2"
        ],
        "LoD/1.14d": [
          "LocalUnwindTwo|0x4025C2"
        ]
      },
      "instruction_counts": {
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
        "LoD/1.13d": 10,
        "LoD/1.14a": 10,
        "LoD/1.14b": 10,
        "LoD/1.14c": 10,
        "LoD/1.14d": 10
      },
      "stack_frame_sizes": {
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
        "LoD/1.13d": 4,
        "LoD/1.14a": 4,
        "LoD/1.14b": 4,
        "LoD/1.14c": 4,
        "LoD/1.14d": 4
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
        "LoD/1.13d": 1,
        "LoD/1.14a": 1,
        "LoD/1.14b": 1,
        "LoD/1.14c": 1,
        "LoD/1.14d": 1
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
        "LoD/1.13d": 0,
        "LoD/1.14a": 0,
        "LoD/1.14b": 0,
        "LoD/1.14c": 0,
        "LoD/1.14d": 0
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
        "LoD/1.13d": "ed17ad9d511f6e330c2b6a62378d83cf",
        "LoD/1.14a": "ed17ad9d511f6e330c2b6a62378d83cf",
        "LoD/1.14b": "ed17ad9d511f6e330c2b6a62378d83cf",
        "LoD/1.14c": "ed17ad9d511f6e330c2b6a62378d83cf",
        "LoD/1.14d": "ed17ad9d511f6e330c2b6a62378d83cf"
      },
      "constants": {
        "LoD/1.07": [
          4219364
        ],
        "LoD/1.08": [
          4219364
        ],
        "LoD/1.09": [
          4219364
        ],
        "LoD/1.09b": [
          4219364
        ],
        "LoD/1.09d": [
          4219364
        ],
        "LoD/1.10": [
          4219364
        ],
        "LoD/1.11": [
          4219364
        ],
        "LoD/1.11b": [
          4219364
        ],
        "LoD/1.12a": [
          4219364
        ],
        "LoD/1.13c": [
          4219364
        ],
        "LoD/1.13d": [
          4219364
        ],
        "LoD/1.14a": [
          4219364
        ],
        "LoD/1.14b": [
          4219364
        ],
        "LoD/1.14c": [
          4219364
        ],
        "LoD/1.14d": [
          4219364
        ]
      },
      "globals": {
        "LoD/1.07": [
          "0x61E4|DAT_004061e4",
          "0x61EC|DAT_004061ec",
          "0x61E8|DAT_004061e8",
          "0x61F0|DAT_004061f0"
        ],
        "LoD/1.08": [
          "0x61E4|DAT_004061e4",
          "0x61EC|DAT_004061ec",
          "0x61E8|DAT_004061e8",
          "0x61F0|DAT_004061f0"
        ],
        "LoD/1.09": [
          "0x61E4|DAT_004061e4",
          "0x61EC|DAT_004061ec",
          "0x61E8|DAT_004061e8",
          "0x61F0|DAT_004061f0"
        ],
        "LoD/1.09b": [
          "0x61E4|DAT_004061e4",
          "0x61EC|DAT_004061ec",
          "0x61E8|DAT_004061e8",
          "0x61F0|DAT_004061f0"
        ],
        "LoD/1.09d": [
          "0x61E4|DAT_004061e4",
          "0x61EC|DAT_004061ec",
          "0x61E8|DAT_004061e8",
          "0x61F0|DAT_004061f0"
        ],
        "LoD/1.10": [
          "0x61E4|DAT_004061e4",
          "0x61EC|DAT_004061ec",
          "0x61E8|DAT_004061e8",
          "0x61F0|DAT_004061f0"
        ],
        "LoD/1.11": [
          "0x61E4|DAT_004061e4",
          "0x61EC|DAT_004061ec",
          "0x61E8|DAT_004061e8",
          "0x61F0|DAT_004061f0"
        ],
        "LoD/1.11b": [
          "0x61E4|DAT_004061e4",
          "0x61EC|DAT_004061ec",
          "0x61E8|DAT_004061e8",
          "0x61F0|DAT_004061f0"
        ],
        "LoD/1.12a": [
          "0x61E4|DAT_004061e4",
          "0x61EC|DAT_004061ec",
          "0x61E8|DAT_004061e8",
          "0x61F0|DAT_004061f0"
        ],
        "LoD/1.13c": [
          "0x61E4|DAT_004061e4",
          "0x61EC|DAT_004061ec",
          "0x61E8|DAT_004061e8",
          "0x61F0|DAT_004061f0"
        ],
        "LoD/1.13d": [
          "0x61E4|DAT_004061e4",
          "0x61EC|DAT_004061ec",
          "0x61E8|DAT_004061e8",
          "0x61F0|DAT_004061f0"
        ],
        "LoD/1.14a": [
          "0x61E4|DAT_004061e4",
          "0x61EC|DAT_004061ec",
          "0x61E8|DAT_004061e8",
          "0x61F0|DAT_004061f0"
        ],
        "LoD/1.14b": [
          "0x61E4|DAT_004061e4",
          "0x61EC|DAT_004061ec",
          "0x61E8|DAT_004061e8",
          "0x61F0|DAT_004061f0"
        ],
        "LoD/1.14c": [
          "0x61E4|DAT_004061e4",
          "0x61EC|DAT_004061ec",
          "0x61E8|DAT_004061e8",
          "0x61F0|DAT_004061f0"
        ],
        "LoD/1.14d": [
          "0x61E4|DAT_004061e4",
          "0x61EC|DAT_004061ec",
          "0x61E8|DAT_004061e8",
          "0x61F0|DAT_004061f0"
        ]
      }
    },
    "diablo ii.exe___seh_longjmp_unwind@4": {
      "addresses": {
        "LoD/1.07": "0x00402735",
        "LoD/1.08": "0x00402735",
        "LoD/1.09": "0x00402735",
        "LoD/1.09b": "0x00402735",
        "LoD/1.09d": "0x00402735",
        "LoD/1.10": "0x00402735",
        "LoD/1.11": "0x00402735",
        "LoD/1.11b": "0x00402735",
        "LoD/1.12a": "0x00402735",
        "LoD/1.13c": "0x00402735",
        "LoD/1.13d": "0x00402735",
        "LoD/1.14a": "0x00402735",
        "LoD/1.14b": "0x00402735",
        "LoD/1.14c": "0x00402735",
        "LoD/1.14d": "0x00402735"
      },
      "rvas": {
        "LoD/1.07": "0x2735",
        "LoD/1.08": "0x2735",
        "LoD/1.09": "0x2735",
        "LoD/1.09b": "0x2735",
        "LoD/1.09d": "0x2735",
        "LoD/1.10": "0x2735",
        "LoD/1.11": "0x2735",
        "LoD/1.11b": "0x2735",
        "LoD/1.12a": "0x2735",
        "LoD/1.13c": "0x2735",
        "LoD/1.13d": "0x2735",
        "LoD/1.14a": "0x2735",
        "LoD/1.14b": "0x2735",
        "LoD/1.14c": "0x2735",
        "LoD/1.14d": "0x2735"
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
        "LoD/1.13d": 27,
        "LoD/1.14a": 27,
        "LoD/1.14b": 27,
        "LoD/1.14c": 27,
        "LoD/1.14d": 27
      },
      "name": "__seh_longjmp_unwind@4",
      "signature": "void __seh_longjmp_unwind@4(SehFrame * pSehFrame)",
      "calling_convention": "__stdcall",
      "return_type": "void",
      "comment": "Performs structured exception handling longjmp stack unwinding operations.\n\nAlgorithm:\n1. Extract the target SEH frame pointer from pSehFrame->pNext (offset 0x18)\n2. Extract the target instruction offset from pSehFrame->dwTargetOffset (offset 0x1c) \n3. Call LocalUnwindTwo to perform actual stack unwinding with extracted parameters\n4. Return after unwinding completes\n\nParameters:\npSehFrame (SehFrame *): Pointer to SEH frame containing unwinding parameters\n  - Offset 0x18: pNext - Target SEH frame for unwinding\n  - Offset 0x1c: dwTargetOffset - Target instruction offset for longjmp\n\nReturns:\nvoid - Function performs unwinding and returns to caller\n\nSpecial Cases:\nThis function is a thin wrapper around LocalUnwindTwo for longjmp operations.\nCalled during structured exception handling when executing longjmp.",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:89d1b619054116ad559c7c543db397fd",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "89d1b619054116ad559c7c543db397fd",
        "CFG": "120fb0f85a7ee6388ee2ce7c9790ef93",
        "PRO": "204649768cb6aa7c9bb671be8e047b74",
        "CAL": null,
        "CON": null,
        "APS": null
      },
      "callees": {
        "LoD/1.07": [
          "LocalUnwindTwo|0x4025C2"
        ],
        "LoD/1.08": [
          "LocalUnwindTwo|0x4025C2"
        ],
        "LoD/1.09": [
          "LocalUnwindTwo|0x4025C2"
        ],
        "LoD/1.09b": [
          "LocalUnwindTwo|0x4025C2"
        ],
        "LoD/1.09d": [
          "LocalUnwindTwo|0x4025C2"
        ],
        "LoD/1.10": [
          "LocalUnwindTwo|0x4025C2"
        ],
        "LoD/1.11": [
          "LocalUnwindTwo|0x4025C2"
        ],
        "LoD/1.11b": [
          "LocalUnwindTwo|0x4025C2"
        ],
        "LoD/1.12a": [
          "LocalUnwindTwo|0x4025C2"
        ],
        "LoD/1.13c": [
          "LocalUnwindTwo|0x4025C2"
        ],
        "LoD/1.13d": [
          "LocalUnwindTwo|0x4025C2"
        ],
        "LoD/1.14a": [
          "LocalUnwindTwo|0x4025C2"
        ],
        "LoD/1.14b": [
          "LocalUnwindTwo|0x4025C2"
        ],
        "LoD/1.14c": [
          "LocalUnwindTwo|0x4025C2"
        ],
        "LoD/1.14d": [
          "LocalUnwindTwo|0x4025C2"
        ]
      },
      "instruction_counts": {
        "LoD/1.07": 11,
        "LoD/1.08": 11,
        "LoD/1.09": 11,
        "LoD/1.09b": 11,
        "LoD/1.09d": 11,
        "LoD/1.10": 11,
        "LoD/1.11": 11,
        "LoD/1.11b": 11,
        "LoD/1.12a": 11,
        "LoD/1.13c": 11,
        "LoD/1.13d": 11,
        "LoD/1.14a": 11,
        "LoD/1.14b": 11,
        "LoD/1.14c": 11,
        "LoD/1.14d": 11
      },
      "stack_frame_sizes": {
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
        "LoD/1.13d": 8,
        "LoD/1.14a": 8,
        "LoD/1.14b": 8,
        "LoD/1.14c": 8,
        "LoD/1.14d": 8
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
        "LoD/1.13d": 1,
        "LoD/1.14a": 1,
        "LoD/1.14b": 1,
        "LoD/1.14c": 1,
        "LoD/1.14d": 1
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
        "LoD/1.13d": 0,
        "LoD/1.14a": 0,
        "LoD/1.14b": 0,
        "LoD/1.14c": 0,
        "LoD/1.14d": 0
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
        "LoD/1.13d": "89d1b619054116ad559c7c543db397fd",
        "LoD/1.14a": "89d1b619054116ad559c7c543db397fd",
        "LoD/1.14b": "89d1b619054116ad559c7c543db397fd",
        "LoD/1.14c": "89d1b619054116ad559c7c543db397fd",
        "LoD/1.14d": "89d1b619054116ad559c7c543db397fd"
      },
      "globals": {
        "LoD/1.07": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.08": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.09": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.09b": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.09d": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.10": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.11": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.11b": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.12a": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.13c": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.13d": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.14a": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.14b": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.14c": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.14d": [
          "0xFFFFFFFFFFC00004|"
        ]
      }
    },
    "diablo ii.exe_CleanupConsoleOutput": {
      "addresses": {
        "LoD/1.07": "0x00402750",
        "LoD/1.08": "0x00402750",
        "LoD/1.09": "0x00402750",
        "LoD/1.09b": "0x00402750",
        "LoD/1.09d": "0x00402750",
        "LoD/1.10": "0x00402750",
        "LoD/1.11": "0x00402750",
        "LoD/1.11b": "0x00402750",
        "LoD/1.12a": "0x00402750",
        "LoD/1.13c": "0x00402750",
        "LoD/1.13d": "0x00402750",
        "LoD/1.14a": "0x00402750",
        "LoD/1.14b": "0x00402750",
        "LoD/1.14c": "0x00402750",
        "LoD/1.14d": "0x00402750"
      },
      "rvas": {
        "LoD/1.07": "0x2750",
        "LoD/1.08": "0x2750",
        "LoD/1.09": "0x2750",
        "LoD/1.09b": "0x2750",
        "LoD/1.09d": "0x2750",
        "LoD/1.10": "0x2750",
        "LoD/1.11": "0x2750",
        "LoD/1.11b": "0x2750",
        "LoD/1.12a": "0x2750",
        "LoD/1.13c": "0x2750",
        "LoD/1.13d": "0x2750",
        "LoD/1.14a": "0x2750",
        "LoD/1.14b": "0x2750",
        "LoD/1.14c": "0x2750",
        "LoD/1.14d": "0x2750"
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
        "LoD/1.13d": 57,
        "LoD/1.14a": 57,
        "LoD/1.14b": 57,
        "LoD/1.14c": 57,
        "LoD/1.14d": 57
      },
      "name": "CleanupConsoleOutput",
      "signature": "void CleanupConsoleOutput(void)",
      "calling_convention": "__stdcall",
      "return_type": "void",
      "comment": "Performs console output cleanup and shutdown operations based on display flags.\n\nAlgorithm:\n\n1. Check if console display is enabled (g_dwConsoleDisplayFlag == 1)\n2. OR if display flag is disabled but debug flag is set (g_dwConsoleDisplayFlag == 0 AND g_dwConsoleDebugFlag == 1)\n3. If either condition true, execute cleanup sequence:\n   - Send pre-cleanup signal via FUN_1001f820(0xFC)\n   - Call registered cleanup callback if available (g_pfnCleanupCallback)\n   - Send final cleanup signal via FUN_1001f820(0xFF)\n4. Return to caller\n\nParameters:\nNone\n\nReturns:\nvoid - No return value\n\nSpecial Cases:\nIf neither console display nor debug mode are active, function exits immediately without cleanup\n\nMagic Numbers Reference:\n0xFC (252) - Pre-cleanup signal code passed to FUN_1001f820\n0xFF (255) - Final cleanup signal code passed to FUN_1001f820",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:9765460a30498931557fab10cfc0be00",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "9765460a30498931557fab10cfc0be00",
        "CFG": "5cb358a801ea502a7e4f33583ed88bc5",
        "PRO": "cd7946af48d94ccd57eeabbf5a2f87ba",
        "CAL": null,
        "CON": null,
        "APS": null
      },
      "callees": {
        "LoD/1.07": [
          "DisplayRuntimeError|0x402789"
        ],
        "LoD/1.08": [
          "DisplayRuntimeError|0x402789"
        ],
        "LoD/1.09": [
          "DisplayRuntimeError|0x402789"
        ],
        "LoD/1.09b": [
          "DisplayRuntimeError|0x402789"
        ],
        "LoD/1.09d": [
          "DisplayRuntimeError|0x402789"
        ],
        "LoD/1.10": [
          "DisplayRuntimeError|0x402789"
        ],
        "LoD/1.11": [
          "DisplayRuntimeError|0x402789"
        ],
        "LoD/1.11b": [
          "DisplayRuntimeError|0x402789"
        ],
        "LoD/1.12a": [
          "DisplayRuntimeError|0x402789"
        ],
        "LoD/1.13c": [
          "DisplayRuntimeError|0x402789"
        ],
        "LoD/1.13d": [
          "DisplayRuntimeError|0x402789"
        ],
        "LoD/1.14a": [
          "DisplayRuntimeError|0x402789"
        ],
        "LoD/1.14b": [
          "DisplayRuntimeError|0x402789"
        ],
        "LoD/1.14c": [
          "DisplayRuntimeError|0x402789"
        ],
        "LoD/1.14d": [
          "DisplayRuntimeError|0x402789"
        ]
      },
      "callers": {
        "LoD/1.07": [
          "AmsgExit|0x4015D9",
          "FUN_004015fe|0x4015FE"
        ],
        "LoD/1.08": [
          "AmsgExit|0x4015D9",
          "FUN_004015fe|0x4015FE"
        ],
        "LoD/1.09": [
          "AmsgExit|0x4015D9",
          "FUN_004015fe|0x4015FE"
        ],
        "LoD/1.09b": [
          "FUN_004015fe|0x4015FE",
          "AmsgExit|0x4015D9"
        ],
        "LoD/1.09d": [
          "FUN_004015fe|0x4015FE",
          "AmsgExit|0x4015D9"
        ],
        "LoD/1.10": [
          "AmsgExit|0x4015D9",
          "FUN_004015fe|0x4015FE"
        ],
        "LoD/1.11": [
          "FUN_004015fe|0x4015FE",
          "AmsgExit|0x4015D9"
        ],
        "LoD/1.11b": [
          "AmsgExit|0x4015D9",
          "FUN_004015fe|0x4015FE"
        ],
        "LoD/1.12a": [
          "AmsgExit|0x4015D9",
          "FUN_004015fe|0x4015FE"
        ],
        "LoD/1.13c": [
          "AmsgExit|0x4015D9",
          "FUN_004015fe|0x4015FE"
        ],
        "LoD/1.13d": [
          "FUN_004015fe|0x4015FE",
          "AmsgExit|0x4015D9"
        ],
        "LoD/1.14a": [
          "AmsgExit|0x4015D9",
          "FUN_004015fe|0x4015FE"
        ],
        "LoD/1.14b": [
          "AmsgExit|0x4015D9",
          "FUN_004015fe|0x4015FE"
        ],
        "LoD/1.14c": [
          "FUN_004015fe|0x4015FE",
          "AmsgExit|0x4015D9"
        ],
        "LoD/1.14d": [
          "AmsgExit|0x4015D9",
          "FUN_004015fe|0x4015FE"
        ]
      },
      "instruction_counts": {
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
        "LoD/1.13d": 18,
        "LoD/1.14a": 18,
        "LoD/1.14b": 18,
        "LoD/1.14c": 18,
        "LoD/1.14d": 18
      },
      "stack_frame_sizes": {
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
        "LoD/1.13d": 4,
        "LoD/1.14a": 4,
        "LoD/1.14b": 4,
        "LoD/1.14c": 4,
        "LoD/1.14d": 4
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
        "LoD/1.13d": 7,
        "LoD/1.14a": 7,
        "LoD/1.14b": 7,
        "LoD/1.14c": 7,
        "LoD/1.14d": 7
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
        "LoD/1.13d": 0,
        "LoD/1.14a": 0,
        "LoD/1.14b": 0,
        "LoD/1.14c": 0,
        "LoD/1.14d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "9765460a30498931557fab10cfc0be00",
        "LoD/1.08": "9765460a30498931557fab10cfc0be00",
        "LoD/1.09": "9765460a30498931557fab10cfc0be00",
        "LoD/1.09b": "9765460a30498931557fab10cfc0be00",
        "LoD/1.09d": "9765460a30498931557fab10cfc0be00",
        "LoD/1.10": "9765460a30498931557fab10cfc0be00",
        "LoD/1.11": "9765460a30498931557fab10cfc0be00",
        "LoD/1.11b": "9765460a30498931557fab10cfc0be00",
        "LoD/1.12a": "9765460a30498931557fab10cfc0be00",
        "LoD/1.13c": "9765460a30498931557fab10cfc0be00",
        "LoD/1.13d": "9765460a30498931557fab10cfc0be00",
        "LoD/1.14a": "9765460a30498931557fab10cfc0be00",
        "LoD/1.14b": "9765460a30498931557fab10cfc0be00",
        "LoD/1.14c": "9765460a30498931557fab10cfc0be00",
        "LoD/1.14d": "9765460a30498931557fab10cfc0be00"
      },
      "globals": {
        "LoD/1.07": [
          "0x64BC|g_dwConsoleDisplayFlag",
          "0x604C|g_dwConsoleDebugFlag",
          "0x661C|g_pfnCleanupCallback"
        ],
        "LoD/1.08": [
          "0x64BC|g_dwConsoleDisplayFlag",
          "0x604C|g_dwConsoleDebugFlag",
          "0x661C|g_pfnCleanupCallback"
        ],
        "LoD/1.09": [
          "0x64BC|g_dwConsoleDisplayFlag",
          "0x604C|g_dwConsoleDebugFlag",
          "0x661C|g_pfnCleanupCallback"
        ],
        "LoD/1.09b": [
          "0x64BC|g_dwConsoleDisplayFlag",
          "0x604C|g_dwConsoleDebugFlag",
          "0x661C|g_pfnCleanupCallback"
        ],
        "LoD/1.09d": [
          "0x64BC|g_dwConsoleDisplayFlag",
          "0x604C|g_dwConsoleDebugFlag",
          "0x661C|g_pfnCleanupCallback"
        ],
        "LoD/1.10": [
          "0x64BC|g_dwConsoleDisplayFlag",
          "0x604C|g_dwConsoleDebugFlag",
          "0x661C|g_pfnCleanupCallback"
        ],
        "LoD/1.11": [
          "0x64BC|g_dwConsoleDisplayFlag",
          "0x604C|g_dwConsoleDebugFlag",
          "0x661C|g_pfnCleanupCallback"
        ],
        "LoD/1.11b": [
          "0x64BC|g_dwConsoleDisplayFlag",
          "0x604C|g_dwConsoleDebugFlag",
          "0x661C|g_pfnCleanupCallback"
        ],
        "LoD/1.12a": [
          "0x64BC|g_dwConsoleDisplayFlag",
          "0x604C|g_dwConsoleDebugFlag",
          "0x661C|g_pfnCleanupCallback"
        ],
        "LoD/1.13c": [
          "0x64BC|g_dwConsoleDisplayFlag",
          "0x604C|g_dwConsoleDebugFlag",
          "0x661C|g_pfnCleanupCallback"
        ],
        "LoD/1.13d": [
          "0x64BC|g_dwConsoleDisplayFlag",
          "0x604C|g_dwConsoleDebugFlag",
          "0x661C|g_pfnCleanupCallback"
        ],
        "LoD/1.14a": [
          "0x64BC|g_dwConsoleDisplayFlag",
          "0x604C|g_dwConsoleDebugFlag",
          "0x661C|g_pfnCleanupCallback"
        ],
        "LoD/1.14b": [
          "0x64BC|g_dwConsoleDisplayFlag",
          "0x604C|g_dwConsoleDebugFlag",
          "0x661C|g_pfnCleanupCallback"
        ],
        "LoD/1.14c": [
          "0x64BC|g_dwConsoleDisplayFlag",
          "0x604C|g_dwConsoleDebugFlag",
          "0x661C|g_pfnCleanupCallback"
        ],
        "LoD/1.14d": [
          "0x64BC|g_dwConsoleDisplayFlag",
          "0x604C|g_dwConsoleDebugFlag",
          "0x661C|g_pfnCleanupCallback"
        ]
      }
    },
    "diablo ii.exe_DisplayRuntimeError": {
      "addresses": {
        "LoD/1.07": "0x00402789",
        "LoD/1.08": "0x00402789",
        "LoD/1.09": "0x00402789",
        "LoD/1.09b": "0x00402789",
        "LoD/1.09d": "0x00402789",
        "LoD/1.10": "0x00402789",
        "LoD/1.11": "0x00402789",
        "LoD/1.11b": "0x00402789",
        "LoD/1.12a": "0x00402789",
        "LoD/1.13c": "0x00402789",
        "LoD/1.13d": "0x00402789",
        "LoD/1.14a": "0x00402789",
        "LoD/1.14b": "0x00402789",
        "LoD/1.14c": "0x00402789",
        "LoD/1.14d": "0x00402789"
      },
      "rvas": {
        "LoD/1.07": "0x2789",
        "LoD/1.08": "0x2789",
        "LoD/1.09": "0x2789",
        "LoD/1.09b": "0x2789",
        "LoD/1.09d": "0x2789",
        "LoD/1.10": "0x2789",
        "LoD/1.11": "0x2789",
        "LoD/1.11b": "0x2789",
        "LoD/1.12a": "0x2789",
        "LoD/1.13c": "0x2789",
        "LoD/1.13d": "0x2789",
        "LoD/1.14a": "0x2789",
        "LoD/1.14b": "0x2789",
        "LoD/1.14c": "0x2789",
        "LoD/1.14d": "0x2789"
      },
      "sizes": {
        "LoD/1.07": 339,
        "LoD/1.08": 339,
        "LoD/1.09": 339,
        "LoD/1.09b": 339,
        "LoD/1.09d": 339,
        "LoD/1.10": 339,
        "LoD/1.11": 339,
        "LoD/1.11b": 339,
        "LoD/1.12a": 339,
        "LoD/1.13c": 339,
        "LoD/1.13d": 339,
        "LoD/1.14a": 339,
        "LoD/1.14b": 339,
        "LoD/1.14c": 339,
        "LoD/1.14d": 339
      },
      "name": "DisplayRuntimeError",
      "signature": "void DisplayRuntimeError(uint dwErrorCode)",
      "calling_convention": "__cdecl",
      "return_type": "void",
      "comment": "Displays runtime error messages either to console or as message box dialog\n\nAlgorithm:\n1. Search error lookup table at 0x1002e678 for matching error code\n2. Iterate through (error_code, string_pointer) pairs until match found or table end (0x1002e708)\n3. If error code found in table, determine display method:\n   a. If console display enabled (g_dwConsoleDisplayFlag == 1), write to stdout\n   b. If console disabled but alternate flag set (DAT_1003c8c0 == 1), write to stdout  \n   c. Otherwise show message box (except for error code 0xfc which is suppressed)\n4. For console output: Get error message string, write to stdout handle using WriteFile\n5. For message box: Build formatted error message with program name and error text\n6. Get module filename using GetModuleFileNameA, truncate if longer than 60 characters\n7. Concatenate \"Runtime Error!\" + program name + newlines + error message text\n8. Display message box using Microsoft Visual C++ Runtime Library title\n\nParameters:\ndwErrorCode - Runtime error code to display (DWORD values from error table)\n\nReturns:\nvoid - No return value\n\nSpecial Cases:\n- Error code 0xfc is suppressed (no dialog or console output)\n- Module name truncated with \"...\" if path exceeds 60 characters\n- Falls back to \"<program name unknown>\" if GetModuleFileNameA fails\n- Console output bypasses message box formatting\n\nMagic Numbers Reference:\n0x1002e678 - Base address of error lookup table (error_code, string_pointer pairs)\n0x1002e708 - End address of error lookup table \n0x1002e67c - Base address of error message string pointers (offset +4 from codes)\n0xfc - Special error code that suppresses all output\n0xfffffff4 - STD_OUTPUT_HANDLE constant for GetStdHandle\n0x12010 - Message box flags (MB_ICONHAND | MB_SETFOREGROUND | MB_TASKMODAL)\n0x3c - Maximum characters (60) before truncating program name\n0x104 - Buffer size (260) for module filename\n60 - Character limit for program name display\n\nError Handling:\n- GetModuleFileNameA failure: Use fallback \"<program name unknown>\"\n- String length overflow: Truncate with \"...\" suffix\n- Table search failure: Function returns without action\n\nStructure Layout:\nError Table Entry (8 bytes):\nOffset | Size | Field Name    | Type | Description\n0x00   | 4    | dwErrorCode   | uint | Runtime error identifier  \n0x04   | 4    | pszMessage    | char*| Pointer to error message string",
      "name_source": "LoD/1.07",
      "method": "STR",
      "index": "STR:ff7880d11813b11bf7ac9bc241be5c60",
      "indexes": {
        "EXP": null,
        "STR": "ff7880d11813b11bf7ac9bc241be5c60",
        "API": null,
        "MNE": "6bfb7faf8650903f50cd7e2ef7eba7fe",
        "CFG": "b077751f218736f0020a07f48c1fade3",
        "PRO": "a25d5a579a50e7c9f3f039e8e97080f6",
        "CAL": "b4938612b45a8006afe991fc98f65440",
        "CON": "dc96ec6a0dc5bde19e01214d7740553f",
        "APS": null
      },
      "callees": {
        "LoD/1.07": [
          "GetStdHandle|0x9",
          "ShowMessageBoxWithActiveWindow|0x403AEE",
          "CopyStringOptimized|0x402E00",
          "_strncpy|0x403B80",
          "_strlen|0x401B80",
          "OptimizedStringCopy|0x402E10",
          "GetModuleFileNameA|0x15",
          "WriteFile|0x22"
        ],
        "LoD/1.08": [
          "WriteFile|0x22",
          "CopyStringOptimized|0x402E00",
          "ShowMessageBoxWithActiveWindow|0x403AEE",
          "GetModuleFileNameA|0x15",
          "_strlen|0x401B80",
          "GetStdHandle|0x9",
          "_strncpy|0x403B80",
          "OptimizedStringCopy|0x402E10"
        ],
        "LoD/1.09": [
          "_strlen|0x401B80",
          "_strncpy|0x403B80",
          "CopyStringOptimized|0x402E00",
          "GetModuleFileNameA|0x15",
          "GetStdHandle|0x9",
          "ShowMessageBoxWithActiveWindow|0x403AEE",
          "OptimizedStringCopy|0x402E10",
          "WriteFile|0x22"
        ],
        "LoD/1.09b": [
          "WriteFile|0x22",
          "OptimizedStringCopy|0x402E10",
          "CopyStringOptimized|0x402E00",
          "_strlen|0x401B80",
          "_strncpy|0x403B80",
          "ShowMessageBoxWithActiveWindow|0x403AEE",
          "GetModuleFileNameA|0x15",
          "GetStdHandle|0x9"
        ],
        "LoD/1.09d": [
          "WriteFile|0x22",
          "_strlen|0x401B80",
          "GetStdHandle|0x9",
          "OptimizedStringCopy|0x402E10",
          "_strncpy|0x403B80",
          "GetModuleFileNameA|0x15",
          "ShowMessageBoxWithActiveWindow|0x403AEE",
          "CopyStringOptimized|0x402E00"
        ],
        "LoD/1.10": [
          "CopyStringOptimized|0x402E00",
          "GetModuleFileNameA|0x15",
          "ShowMessageBoxWithActiveWindow|0x403AEE",
          "WriteFile|0x22",
          "_strncpy|0x403B80",
          "OptimizedStringCopy|0x402E10",
          "GetStdHandle|0x9",
          "_strlen|0x401B80"
        ],
        "LoD/1.11": [
          "GetModuleFileNameA|0x15",
          "OptimizedStringCopy|0x402E10",
          "_strncpy|0x403B80",
          "ShowMessageBoxWithActiveWindow|0x403AEE",
          "GetStdHandle|0x9",
          "CopyStringOptimized|0x402E00",
          "_strlen|0x401B80",
          "WriteFile|0x22"
        ],
        "LoD/1.11b": [
          "_strncpy|0x403B80",
          "_strlen|0x401B80",
          "WriteFile|0x22",
          "OptimizedStringCopy|0x402E10",
          "GetStdHandle|0x9",
          "ShowMessageBoxWithActiveWindow|0x403AEE",
          "CopyStringOptimized|0x402E00",
          "GetModuleFileNameA|0x15"
        ],
        "LoD/1.12a": [
          "CopyStringOptimized|0x402E00",
          "_strlen|0x401B80",
          "GetModuleFileNameA|0x15",
          "GetStdHandle|0x9",
          "_strncpy|0x403B80",
          "OptimizedStringCopy|0x402E10",
          "ShowMessageBoxWithActiveWindow|0x403AEE",
          "WriteFile|0x22"
        ],
        "LoD/1.13c": [
          "GetModuleFileNameA|0x15",
          "GetStdHandle|0x9",
          "CopyStringOptimized|0x402E00",
          "_strlen|0x401B80",
          "_strncpy|0x403B80",
          "WriteFile|0x22",
          "OptimizedStringCopy|0x402E10",
          "ShowMessageBoxWithActiveWindow|0x403AEE"
        ],
        "LoD/1.13d": [
          "CopyStringOptimized|0x402E00",
          "_strlen|0x401B80",
          "GetModuleFileNameA|0x15",
          "WriteFile|0x22",
          "OptimizedStringCopy|0x402E10",
          "_strncpy|0x403B80",
          "GetStdHandle|0x9",
          "ShowMessageBoxWithActiveWindow|0x403AEE"
        ],
        "LoD/1.14a": [
          "CopyStringOptimized|0x402E00",
          "WriteFile|0x22",
          "OptimizedStringCopy|0x402E10",
          "GetStdHandle|0x9",
          "ShowMessageBoxWithActiveWindow|0x403AEE",
          "GetModuleFileNameA|0x15",
          "_strlen|0x401B80",
          "_strncpy|0x403B80"
        ],
        "LoD/1.14b": [
          "_strncpy|0x403B80",
          "OptimizedStringCopy|0x402E10",
          "CopyStringOptimized|0x402E00",
          "WriteFile|0x22",
          "ShowMessageBoxWithActiveWindow|0x403AEE",
          "GetStdHandle|0x9",
          "GetModuleFileNameA|0x15",
          "_strlen|0x401B80"
        ],
        "LoD/1.14c": [
          "_strlen|0x401B80",
          "OptimizedStringCopy|0x402E10",
          "GetModuleFileNameA|0x15",
          "_strncpy|0x403B80",
          "CopyStringOptimized|0x402E00",
          "ShowMessageBoxWithActiveWindow|0x403AEE",
          "GetStdHandle|0x9",
          "WriteFile|0x22"
        ],
        "LoD/1.14d": [
          "ShowMessageBoxWithActiveWindow|0x403AEE",
          "GetModuleFileNameA|0x15",
          "OptimizedStringCopy|0x402E10",
          "GetStdHandle|0x9",
          "CopyStringOptimized|0x402E00",
          "WriteFile|0x22",
          "_strlen|0x401B80",
          "_strncpy|0x403B80"
        ]
      },
      "callers": {
        "LoD/1.07": [
          "AmsgExit|0x4015D9",
          "FUN_004015fe|0x4015FE",
          "CleanupConsoleOutput|0x402750"
        ],
        "LoD/1.08": [
          "AmsgExit|0x4015D9",
          "CleanupConsoleOutput|0x402750",
          "FUN_004015fe|0x4015FE"
        ],
        "LoD/1.09": [
          "AmsgExit|0x4015D9",
          "CleanupConsoleOutput|0x402750",
          "FUN_004015fe|0x4015FE"
        ],
        "LoD/1.09b": [
          "FUN_004015fe|0x4015FE",
          "AmsgExit|0x4015D9",
          "CleanupConsoleOutput|0x402750"
        ],
        "LoD/1.09d": [
          "FUN_004015fe|0x4015FE",
          "AmsgExit|0x4015D9",
          "CleanupConsoleOutput|0x402750"
        ],
        "LoD/1.10": [
          "AmsgExit|0x4015D9",
          "FUN_004015fe|0x4015FE",
          "CleanupConsoleOutput|0x402750"
        ],
        "LoD/1.11": [
          "CleanupConsoleOutput|0x402750",
          "FUN_004015fe|0x4015FE",
          "AmsgExit|0x4015D9"
        ],
        "LoD/1.11b": [
          "CleanupConsoleOutput|0x402750",
          "AmsgExit|0x4015D9",
          "FUN_004015fe|0x4015FE"
        ],
        "LoD/1.12a": [
          "AmsgExit|0x4015D9",
          "CleanupConsoleOutput|0x402750",
          "FUN_004015fe|0x4015FE"
        ],
        "LoD/1.13c": [
          "AmsgExit|0x4015D9",
          "FUN_004015fe|0x4015FE",
          "CleanupConsoleOutput|0x402750"
        ],
        "LoD/1.13d": [
          "FUN_004015fe|0x4015FE",
          "AmsgExit|0x4015D9",
          "CleanupConsoleOutput|0x402750"
        ],
        "LoD/1.14a": [
          "CleanupConsoleOutput|0x402750",
          "AmsgExit|0x4015D9",
          "FUN_004015fe|0x4015FE"
        ],
        "LoD/1.14b": [
          "CleanupConsoleOutput|0x402750",
          "AmsgExit|0x4015D9",
          "FUN_004015fe|0x4015FE"
        ],
        "LoD/1.14c": [
          "FUN_004015fe|0x4015FE",
          "AmsgExit|0x4015D9",
          "CleanupConsoleOutput|0x402750"
        ],
        "LoD/1.14d": [
          "CleanupConsoleOutput|0x402750",
          "AmsgExit|0x4015D9",
          "FUN_004015fe|0x4015FE"
        ]
      },
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
        ],
        "LoD/1.14a": [
          "\"Runtime Error!\\n\\nProgram: \"",
          "\"Microsoft Visual C++ Runtime Library\"",
          "\"R6009\\r\\n- not enough space for environment\\r\\n\"",
          "\"<program name unknown>\""
        ],
        "LoD/1.14b": [
          "\"Runtime Error!\\n\\nProgram: \"",
          "\"Microsoft Visual C++ Runtime Library\"",
          "\"R6009\\r\\n- not enough space for environment\\r\\n\"",
          "\"<program name unknown>\""
        ],
        "LoD/1.14c": [
          "\"Runtime Error!\\n\\nProgram: \"",
          "\"Microsoft Visual C++ Runtime Library\"",
          "\"R6009\\r\\n- not enough space for environment\\r\\n\"",
          "\"<program name unknown>\""
        ],
        "LoD/1.14d": [
          "\"Runtime Error!\\n\\nProgram: \"",
          "\"Microsoft Visual C++ Runtime Library\"",
          "\"R6009\\r\\n- not enough space for environment\\r\\n\"",
          "\"<program name unknown>\""
        ]
      },
      "instruction_counts": {
        "LoD/1.07": 100,
        "LoD/1.08": 100,
        "LoD/1.09": 100,
        "LoD/1.09b": 100,
        "LoD/1.09d": 100,
        "LoD/1.10": 100,
        "LoD/1.11": 100,
        "LoD/1.11b": 100,
        "LoD/1.12a": 100,
        "LoD/1.13c": 100,
        "LoD/1.13d": 100,
        "LoD/1.14a": 100,
        "LoD/1.14b": 100,
        "LoD/1.14c": 100,
        "LoD/1.14d": 100
      },
      "stack_frame_sizes": {
        "LoD/1.07": 432,
        "LoD/1.08": 432,
        "LoD/1.09": 432,
        "LoD/1.09b": 432,
        "LoD/1.09d": 432,
        "LoD/1.10": 432,
        "LoD/1.11": 432,
        "LoD/1.11b": 432,
        "LoD/1.12a": 432,
        "LoD/1.13c": 432,
        "LoD/1.13d": 432,
        "LoD/1.14a": 432,
        "LoD/1.14b": 432,
        "LoD/1.14c": 432,
        "LoD/1.14d": 432
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
        "LoD/1.13d": 15,
        "LoD/1.14a": 15,
        "LoD/1.14b": 15,
        "LoD/1.14c": 15,
        "LoD/1.14d": 15
      },
      "loop_counts": {
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
        "LoD/1.13d": 1,
        "LoD/1.14a": 1,
        "LoD/1.14b": 1,
        "LoD/1.14c": 1,
        "LoD/1.14d": 1
      },
      "mnemonic_hashes": {
        "LoD/1.07": "6bfb7faf8650903f50cd7e2ef7eba7fe",
        "LoD/1.08": "6bfb7faf8650903f50cd7e2ef7eba7fe",
        "LoD/1.09": "6bfb7faf8650903f50cd7e2ef7eba7fe",
        "LoD/1.09b": "6bfb7faf8650903f50cd7e2ef7eba7fe",
        "LoD/1.09d": "6bfb7faf8650903f50cd7e2ef7eba7fe",
        "LoD/1.10": "6bfb7faf8650903f50cd7e2ef7eba7fe",
        "LoD/1.11": "6bfb7faf8650903f50cd7e2ef7eba7fe",
        "LoD/1.11b": "6bfb7faf8650903f50cd7e2ef7eba7fe",
        "LoD/1.12a": "6bfb7faf8650903f50cd7e2ef7eba7fe",
        "LoD/1.13c": "6bfb7faf8650903f50cd7e2ef7eba7fe",
        "LoD/1.13d": "6bfb7faf8650903f50cd7e2ef7eba7fe",
        "LoD/1.14a": "6bfb7faf8650903f50cd7e2ef7eba7fe",
        "LoD/1.14b": "6bfb7faf8650903f50cd7e2ef7eba7fe",
        "LoD/1.14c": "6bfb7faf8650903f50cd7e2ef7eba7fe",
        "LoD/1.14d": "6bfb7faf8650903f50cd7e2ef7eba7fe"
      },
      "constants": {
        "LoD/1.07": [
          260,
          420,
          73744,
          4215632,
          4215672,
          4215676,
          4215704,
          4215708,
          4219384,
          4219388
        ],
        "LoD/1.08": [
          260,
          420,
          73744,
          4215632,
          4215672,
          4215676,
          4215704,
          4215708,
          4219384,
          4219388
        ],
        "LoD/1.09": [
          260,
          420,
          73744,
          4215632,
          4215672,
          4215676,
          4215704,
          4215708,
          4219384,
          4219388
        ],
        "LoD/1.09b": [
          260,
          420,
          73744,
          4215632,
          4215672,
          4215676,
          4215704,
          4215708,
          4219384,
          4219388
        ],
        "LoD/1.09d": [
          260,
          420,
          73744,
          4215632,
          4215672,
          4215676,
          4215704,
          4215708,
          4219384,
          4219388
        ],
        "LoD/1.10": [
          260,
          420,
          73744,
          4215632,
          4215672,
          4215676,
          4215704,
          4215708,
          4219384,
          4219388
        ],
        "LoD/1.11": [
          260,
          420,
          73744,
          4215632,
          4215672,
          4215676,
          4215704,
          4215708,
          4219384,
          4219388
        ],
        "LoD/1.11b": [
          260,
          420,
          73744,
          4215632,
          4215672,
          4215676,
          4215704,
          4215708,
          4219384,
          4219388
        ],
        "LoD/1.12a": [
          260,
          420,
          73744,
          4215632,
          4215672,
          4215676,
          4215704,
          4215708,
          4219384,
          4219388
        ],
        "LoD/1.13c": [
          260,
          420,
          73744,
          4215632,
          4215672,
          4215676,
          4215704,
          4215708,
          4219384,
          4219388
        ],
        "LoD/1.13d": [
          260,
          420,
          73744,
          4215632,
          4215672,
          4215676,
          4215704,
          4215708,
          4219384,
          4219388
        ],
        "LoD/1.14a": [
          260,
          420,
          73744,
          4215632,
          4215672,
          4215676,
          4215704,
          4215708,
          4219384,
          4219388
        ],
        "LoD/1.14b": [
          260,
          420,
          73744,
          4215632,
          4215672,
          4215676,
          4215704,
          4215708,
          4219384,
          4219388
        ],
        "LoD/1.14c": [
          260,
          420,
          73744,
          4215632,
          4215672,
          4215676,
          4215704,
          4215708,
          4219384,
          4219388
        ],
        "LoD/1.14d": [
          260,
          420,
          73744,
          4215632,
          4215672,
          4215676,
          4215704,
          4215708,
          4219384,
          4219388
        ]
      },
      "globals": {
        "LoD/1.07": [
          "0xFFFFFFFFFFC00004|",
          "0x61F8|DAT_004061f8",
          "0x6200|DAT_00406200",
          "0x6208|DAT_00406208",
          "0x6288|DAT_00406288",
          "0x64BC|g_dwConsoleDisplayFlag",
          "0x604C|g_dwConsoleDebugFlag",
          "0xFFFFFFFFFFBFFE58|",
          "0x5050|PTR_GetModuleFileNameA_00405050",
          "0x539C|s_<program_name_unknown>_0040539c"
        ],
        "LoD/1.08": [
          "0xFFFFFFFFFFC00004|",
          "0x61F8|DAT_004061f8",
          "0x6200|DAT_00406200",
          "0x6208|DAT_00406208",
          "0x6288|DAT_00406288",
          "0x64BC|g_dwConsoleDisplayFlag",
          "0x604C|g_dwConsoleDebugFlag",
          "0xFFFFFFFFFFBFFE58|",
          "0x5050|PTR_GetModuleFileNameA_00405050",
          "0x539C|s_<program_name_unknown>_0040539c"
        ],
        "LoD/1.09": [
          "0xFFFFFFFFFFC00004|",
          "0x61F8|DAT_004061f8",
          "0x6200|DAT_00406200",
          "0x6208|DAT_00406208",
          "0x6288|DAT_00406288",
          "0x64BC|g_dwConsoleDisplayFlag",
          "0x604C|g_dwConsoleDebugFlag",
          "0xFFFFFFFFFFBFFE58|",
          "0x5050|PTR_GetModuleFileNameA_00405050",
          "0x539C|s_<program_name_unknown>_0040539c"
        ],
        "LoD/1.09b": [
          "0xFFFFFFFFFFC00004|",
          "0x61F8|DAT_004061f8",
          "0x6200|DAT_00406200",
          "0x6208|DAT_00406208",
          "0x6288|DAT_00406288",
          "0x64BC|g_dwConsoleDisplayFlag",
          "0x604C|g_dwConsoleDebugFlag",
          "0xFFFFFFFFFFBFFE58|",
          "0x5050|PTR_GetModuleFileNameA_00405050",
          "0x539C|s_<program_name_unknown>_0040539c"
        ],
        "LoD/1.09d": [
          "0xFFFFFFFFFFC00004|",
          "0x61F8|DAT_004061f8",
          "0x6200|DAT_00406200",
          "0x6208|DAT_00406208",
          "0x6288|DAT_00406288",
          "0x64BC|g_dwConsoleDisplayFlag",
          "0x604C|g_dwConsoleDebugFlag",
          "0xFFFFFFFFFFBFFE58|",
          "0x5050|PTR_GetModuleFileNameA_00405050",
          "0x539C|s_<program_name_unknown>_0040539c"
        ],
        "LoD/1.10": [
          "0xFFFFFFFFFFC00004|",
          "0x61F8|DAT_004061f8",
          "0x6200|DAT_00406200",
          "0x6208|DAT_00406208",
          "0x6288|DAT_00406288",
          "0x64BC|g_dwConsoleDisplayFlag",
          "0x604C|g_dwConsoleDebugFlag",
          "0xFFFFFFFFFFBFFE58|",
          "0x5050|PTR_GetModuleFileNameA_00405050",
          "0x539C|s_<program_name_unknown>_0040539c"
        ],
        "LoD/1.11": [
          "0xFFFFFFFFFFC00004|",
          "0x61F8|DAT_004061f8",
          "0x6200|DAT_00406200",
          "0x6208|DAT_00406208",
          "0x6288|DAT_00406288",
          "0x64BC|g_dwConsoleDisplayFlag",
          "0x604C|g_dwConsoleDebugFlag",
          "0xFFFFFFFFFFBFFE58|",
          "0x5050|PTR_GetModuleFileNameA_00405050",
          "0x539C|s_<program_name_unknown>_0040539c"
        ],
        "LoD/1.11b": [
          "0xFFFFFFFFFFC00004|",
          "0x61F8|DAT_004061f8",
          "0x6200|DAT_00406200",
          "0x6208|DAT_00406208",
          "0x6288|DAT_00406288",
          "0x64BC|g_dwConsoleDisplayFlag",
          "0x604C|g_dwConsoleDebugFlag",
          "0xFFFFFFFFFFBFFE58|",
          "0x5050|PTR_GetModuleFileNameA_00405050",
          "0x539C|s_<program_name_unknown>_0040539c"
        ],
        "LoD/1.12a": [
          "0xFFFFFFFFFFC00004|",
          "0x61F8|DAT_004061f8",
          "0x6200|DAT_00406200",
          "0x6208|DAT_00406208",
          "0x6288|DAT_00406288",
          "0x64BC|g_dwConsoleDisplayFlag",
          "0x604C|g_dwConsoleDebugFlag",
          "0xFFFFFFFFFFBFFE58|",
          "0x5050|PTR_GetModuleFileNameA_00405050",
          "0x539C|s_<program_name_unknown>_0040539c"
        ],
        "LoD/1.13c": [
          "0xFFFFFFFFFFC00004|",
          "0x61F8|DAT_004061f8",
          "0x6200|DAT_00406200",
          "0x6208|DAT_00406208",
          "0x6288|DAT_00406288",
          "0x64BC|g_dwConsoleDisplayFlag",
          "0x604C|g_dwConsoleDebugFlag",
          "0xFFFFFFFFFFBFFE58|",
          "0x5050|PTR_GetModuleFileNameA_00405050",
          "0x539C|s_<program_name_unknown>_0040539c"
        ],
        "LoD/1.13d": [
          "0xFFFFFFFFFFC00004|",
          "0x61F8|DAT_004061f8",
          "0x6200|DAT_00406200",
          "0x6208|DAT_00406208",
          "0x6288|DAT_00406288",
          "0x64BC|g_dwConsoleDisplayFlag",
          "0x604C|g_dwConsoleDebugFlag",
          "0xFFFFFFFFFFBFFE58|",
          "0x5050|PTR_GetModuleFileNameA_00405050",
          "0x539C|s_<program_name_unknown>_0040539c"
        ],
        "LoD/1.14a": [
          "0xFFFFFFFFFFC00004|",
          "0x61F8|DAT_004061f8",
          "0x6200|DAT_00406200",
          "0x6208|DAT_00406208",
          "0x6288|DAT_00406288",
          "0x64BC|g_dwConsoleDisplayFlag",
          "0x604C|g_dwConsoleDebugFlag",
          "0xFFFFFFFFFFBFFE58|",
          "0x5050|PTR_GetModuleFileNameA_00405050",
          "0x539C|s_<program_name_unknown>_0040539c"
        ],
        "LoD/1.14b": [
          "0xFFFFFFFFFFC00004|",
          "0x61F8|DAT_004061f8",
          "0x6200|DAT_00406200",
          "0x6208|DAT_00406208",
          "0x6288|DAT_00406288",
          "0x64BC|g_dwConsoleDisplayFlag",
          "0x604C|g_dwConsoleDebugFlag",
          "0xFFFFFFFFFFBFFE58|",
          "0x5050|PTR_GetModuleFileNameA_00405050",
          "0x539C|s_<program_name_unknown>_0040539c"
        ],
        "LoD/1.14c": [
          "0xFFFFFFFFFFC00004|",
          "0x61F8|DAT_004061f8",
          "0x6200|DAT_00406200",
          "0x6208|DAT_00406208",
          "0x6288|DAT_00406288",
          "0x64BC|g_dwConsoleDisplayFlag",
          "0x604C|g_dwConsoleDebugFlag",
          "0xFFFFFFFFFFBFFE58|",
          "0x5050|PTR_GetModuleFileNameA_00405050",
          "0x539C|s_<program_name_unknown>_0040539c"
        ],
        "LoD/1.14d": [
          "0xFFFFFFFFFFC00004|",
          "0x61F8|DAT_004061f8",
          "0x6200|DAT_00406200",
          "0x6208|DAT_00406208",
          "0x6288|DAT_00406288",
          "0x64BC|g_dwConsoleDisplayFlag",
          "0x604C|g_dwConsoleDebugFlag",
          "0xFFFFFFFFFFBFFE58|",
          "0x5050|PTR_GetModuleFileNameA_00405050",
          "0x539C|s_<program_name_unknown>_0040539c"
        ]
      }
    },
    "diablo ii.exe_LocaleMapStringWithConversion": {
      "addresses": {
        "LoD/1.07": "0x004028DC",
        "LoD/1.08": "0x004028DC",
        "LoD/1.09": "0x004028DC",
        "LoD/1.09b": "0x004028DC",
        "LoD/1.09d": "0x004028DC",
        "LoD/1.10": "0x004028DC",
        "LoD/1.11": "0x004028DC",
        "LoD/1.11b": "0x004028DC",
        "LoD/1.12a": "0x004028DC",
        "LoD/1.13c": "0x004028DC",
        "LoD/1.13d": "0x004028DC",
        "LoD/1.14a": "0x004028DC",
        "LoD/1.14b": "0x004028DC",
        "LoD/1.14c": "0x004028DC",
        "LoD/1.14d": "0x004028DC"
      },
      "rvas": {
        "LoD/1.07": "0x28DC",
        "LoD/1.08": "0x28DC",
        "LoD/1.09": "0x28DC",
        "LoD/1.09b": "0x28DC",
        "LoD/1.09d": "0x28DC",
        "LoD/1.10": "0x28DC",
        "LoD/1.11": "0x28DC",
        "LoD/1.11b": "0x28DC",
        "LoD/1.12a": "0x28DC",
        "LoD/1.13c": "0x28DC",
        "LoD/1.13d": "0x28DC",
        "LoD/1.14a": "0x28DC",
        "LoD/1.14b": "0x28DC",
        "LoD/1.14c": "0x28DC",
        "LoD/1.14d": "0x28DC"
      },
      "sizes": {
        "LoD/1.07": 511,
        "LoD/1.08": 511,
        "LoD/1.09": 511,
        "LoD/1.09b": 511,
        "LoD/1.09d": 511,
        "LoD/1.10": 511,
        "LoD/1.11": 511,
        "LoD/1.11b": 511,
        "LoD/1.12a": 511,
        "LoD/1.13c": 511,
        "LoD/1.13d": 511,
        "LoD/1.14a": 511,
        "LoD/1.14b": 511,
        "LoD/1.14c": 511,
        "LoD/1.14d": 511
      },
      "name": "LocaleMapStringWithConversion",
      "signature": "int LocaleMapStringWithConversion(uint dwLcid, uint dwMapFlags, char * lpszSrcStr, int nSrcLen, char * lpszDestStr, int nDestLen, uint dwCodePage, int nFlags)",
      "calling_convention": "__cdecl",
      "return_type": "int",
      "comment": "Performs locale-aware string mapping with automatic character encoding conversion.\n\nAlgorithm:\n1. Set up structured exception handling (SEH) frame\n2. Initialize Unicode support detection if not already done\n   a. Test LCMapStringW with empty string to detect Unicode support\n   b. If Unicode fails, test LCMapStringA for ANSI support\n   c. Set global flag (1=Unicode, 2=ANSI) based on results\n3. Validate source string length using FUN_1001fb97 if positive length\n4. Branch based on detected encoding support:\n   - If ANSI mode (flag=2): Call LCMapStringA directly and return result\n   - If Unicode mode (flag=1): Perform conversion sequence\n5. Unicode conversion sequence:\n   a. Use default code page if dwCodePage is 0\n   b. Calculate required wide character buffer size with MultiByteToWideChar\n   c. Allocate stack space for wide character conversion buffer\n   d. Convert source string from multibyte to wide character\n   e. Get required output buffer size with LCMapStringW\n   f. If LCMAP_SORTKEY flag (0x400) is set:\n      - Return required size if output buffer is NULL\n      - Validate output buffer size and perform mapping directly\n   g. If normal mapping:\n      - Allocate second stack buffer for wide character output\n      - Perform LCMapStringW mapping to wide character buffer\n      - Convert result back to multibyte using WideCharToMultiByte\n6. Clean up SEH frame and return result\n\nParameters:\ndwLcid (uint): Locale identifier for mapping operation\ndwMapFlags (uint): Mapping flags controlling case conversion and sorting\nlpszSrcStr (char *): Source string in multibyte encoding\nnSrcLen (int): Length of source string (-1 for null-terminated)\nlpszDestStr (char *): Output buffer for mapped string\nnDestLen (int): Size of output buffer in characters\ndwCodePage (uint): Code page for character conversion (0 = default)\nnFlags (int): Additional conversion flags for MultiByteToWideChar\n\nReturns:\nNumber of characters written to output buffer on success\n0 on failure (insufficient buffer, conversion error, or unsupported operation)\n\nSpecial Cases:\nIf lpszDestStr is NULL, returns required buffer size\nLCMAP_SORTKEY flag (0x400) returns sort key instead of mapped string\nAutomatic fallback from Unicode to ANSI if Unicode APIs unavailable\n\nMagic Numbers Reference:\n0x100 - LCMAP_LOWERCASE flag for case conversion test\n0x400 - LCMAP_SORTKEY flag for sort key generation\n0x220 - WC_NO_BEST_FIT_CHARS | WC_COMPOSITECHECK flags\n0x1003ca54 - Global Unicode support flag (1=Unicode, 2=ANSI)\n0x1003c8e4 - Default code page storage\n\nError Handling:\nReturns 0 for all error conditions including:\n- Unsupported locale or mapping flags\n- Insufficient output buffer space\n- Character conversion failures\n- Stack allocation failures",
      "name_source": "LoD/1.07",
      "method": "CAL",
      "index": "CAL:981867b0970223dac828e5ddf508c9bd",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "c1d05e132bc8c3bc87e7a971916e9b9b",
        "CFG": "6cc88f3c6036b07006695d5cf644d042",
        "PRO": "8cdd37d52b857df0da76bdb271ca9544",
        "CAL": "981867b0970223dac828e5ddf508c9bd",
        "CON": "9fe1522e2870415d91409e2b7960b311",
        "APS": null
      },
      "callees": {
        "LoD/1.07": [
          "LCMapStringW|0x25",
          "WideCharToMultiByte|0x18",
          "LCMapStringA|0x24",
          "MultiByteToWideChar|0x23",
          "AllocateStackSpace|0x403C80",
          "CalculateStringLengthWithLimit|0x402B00"
        ],
        "LoD/1.08": [
          "MultiByteToWideChar|0x23",
          "LCMapStringW|0x25",
          "WideCharToMultiByte|0x18",
          "CalculateStringLengthWithLimit|0x402B00",
          "AllocateStackSpace|0x403C80",
          "LCMapStringA|0x24"
        ],
        "LoD/1.09": [
          "AllocateStackSpace|0x403C80",
          "LCMapStringA|0x24",
          "WideCharToMultiByte|0x18",
          "MultiByteToWideChar|0x23",
          "CalculateStringLengthWithLimit|0x402B00",
          "LCMapStringW|0x25"
        ],
        "LoD/1.09b": [
          "AllocateStackSpace|0x403C80",
          "LCMapStringA|0x24",
          "LCMapStringW|0x25",
          "WideCharToMultiByte|0x18",
          "CalculateStringLengthWithLimit|0x402B00",
          "MultiByteToWideChar|0x23"
        ],
        "LoD/1.09d": [
          "AllocateStackSpace|0x403C80",
          "CalculateStringLengthWithLimit|0x402B00",
          "LCMapStringW|0x25",
          "LCMapStringA|0x24",
          "MultiByteToWideChar|0x23",
          "WideCharToMultiByte|0x18"
        ],
        "LoD/1.10": [
          "LCMapStringW|0x25",
          "WideCharToMultiByte|0x18",
          "AllocateStackSpace|0x403C80",
          "CalculateStringLengthWithLimit|0x402B00",
          "MultiByteToWideChar|0x23",
          "LCMapStringA|0x24"
        ],
        "LoD/1.11": [
          "LCMapStringW|0x25",
          "LCMapStringA|0x24",
          "WideCharToMultiByte|0x18",
          "MultiByteToWideChar|0x23",
          "CalculateStringLengthWithLimit|0x402B00",
          "AllocateStackSpace|0x403C80"
        ],
        "LoD/1.11b": [
          "LCMapStringA|0x24",
          "MultiByteToWideChar|0x23",
          "CalculateStringLengthWithLimit|0x402B00",
          "WideCharToMultiByte|0x18",
          "LCMapStringW|0x25",
          "AllocateStackSpace|0x403C80"
        ],
        "LoD/1.12a": [
          "CalculateStringLengthWithLimit|0x402B00",
          "AllocateStackSpace|0x403C80",
          "LCMapStringW|0x25",
          "MultiByteToWideChar|0x23",
          "WideCharToMultiByte|0x18",
          "LCMapStringA|0x24"
        ],
        "LoD/1.13c": [
          "WideCharToMultiByte|0x18",
          "LCMapStringW|0x25",
          "LCMapStringA|0x24",
          "MultiByteToWideChar|0x23",
          "AllocateStackSpace|0x403C80",
          "CalculateStringLengthWithLimit|0x402B00"
        ],
        "LoD/1.13d": [
          "AllocateStackSpace|0x403C80",
          "WideCharToMultiByte|0x18",
          "LCMapStringA|0x24",
          "CalculateStringLengthWithLimit|0x402B00",
          "LCMapStringW|0x25",
          "MultiByteToWideChar|0x23"
        ],
        "LoD/1.14a": [
          "LCMapStringW|0x25",
          "AllocateStackSpace|0x403C80",
          "LCMapStringA|0x24",
          "WideCharToMultiByte|0x18",
          "CalculateStringLengthWithLimit|0x402B00",
          "MultiByteToWideChar|0x23"
        ],
        "LoD/1.14b": [
          "AllocateStackSpace|0x403C80",
          "MultiByteToWideChar|0x23",
          "LCMapStringA|0x24",
          "CalculateStringLengthWithLimit|0x402B00",
          "WideCharToMultiByte|0x18",
          "LCMapStringW|0x25"
        ],
        "LoD/1.14c": [
          "LCMapStringW|0x25",
          "MultiByteToWideChar|0x23",
          "LCMapStringA|0x24",
          "AllocateStackSpace|0x403C80",
          "WideCharToMultiByte|0x18",
          "CalculateStringLengthWithLimit|0x402B00"
        ],
        "LoD/1.14d": [
          "LCMapStringA|0x24",
          "AllocateStackSpace|0x403C80",
          "LCMapStringW|0x25",
          "MultiByteToWideChar|0x23",
          "WideCharToMultiByte|0x18",
          "CalculateStringLengthWithLimit|0x402B00"
        ]
      },
      "callers": {
        "LoD/1.07": [
          "InitializeCharacterTables|0x401861"
        ],
        "LoD/1.08": [
          "InitializeCharacterTables|0x401861"
        ],
        "LoD/1.09": [
          "InitializeCharacterTables|0x401861"
        ],
        "LoD/1.09b": [
          "InitializeCharacterTables|0x401861"
        ],
        "LoD/1.09d": [
          "InitializeCharacterTables|0x401861"
        ],
        "LoD/1.10": [
          "InitializeCharacterTables|0x401861"
        ],
        "LoD/1.11": [
          "InitializeCharacterTables|0x401861"
        ],
        "LoD/1.11b": [
          "InitializeCharacterTables|0x401861"
        ],
        "LoD/1.12a": [
          "InitializeCharacterTables|0x401861"
        ],
        "LoD/1.13c": [
          "InitializeCharacterTables|0x401861"
        ],
        "LoD/1.13d": [
          "InitializeCharacterTables|0x401861"
        ],
        "LoD/1.14a": [
          "InitializeCharacterTables|0x401861"
        ],
        "LoD/1.14b": [
          "InitializeCharacterTables|0x401861"
        ],
        "LoD/1.14c": [
          "InitializeCharacterTables|0x401861"
        ],
        "LoD/1.14d": [
          "InitializeCharacterTables|0x401861"
        ]
      },
      "instruction_counts": {
        "LoD/1.07": 177,
        "LoD/1.08": 177,
        "LoD/1.09": 177,
        "LoD/1.09b": 177,
        "LoD/1.09d": 177,
        "LoD/1.10": 177,
        "LoD/1.11": 177,
        "LoD/1.11b": 177,
        "LoD/1.12a": 177,
        "LoD/1.13c": 177,
        "LoD/1.13d": 177,
        "LoD/1.14a": 177,
        "LoD/1.14b": 177,
        "LoD/1.14c": 177,
        "LoD/1.14d": 177
      },
      "stack_frame_sizes": {
        "LoD/1.07": 96,
        "LoD/1.08": 96,
        "LoD/1.09": 96,
        "LoD/1.09b": 96,
        "LoD/1.09d": 96,
        "LoD/1.10": 96,
        "LoD/1.11": 96,
        "LoD/1.11b": 96,
        "LoD/1.12a": 96,
        "LoD/1.13c": 96,
        "LoD/1.13d": 96,
        "LoD/1.14a": 96,
        "LoD/1.14b": 96,
        "LoD/1.14c": 96,
        "LoD/1.14d": 96
      },
      "basic_block_counts": {
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
        "LoD/1.13d": 31,
        "LoD/1.14a": 31,
        "LoD/1.14b": 31,
        "LoD/1.14c": 31,
        "LoD/1.14d": 31
      },
      "loop_counts": {
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
        "LoD/1.13d": 4,
        "LoD/1.14a": 4,
        "LoD/1.14b": 4,
        "LoD/1.14c": 4,
        "LoD/1.14d": 4
      },
      "mnemonic_hashes": {
        "LoD/1.07": "c1d05e132bc8c3bc87e7a971916e9b9b",
        "LoD/1.08": "c1d05e132bc8c3bc87e7a971916e9b9b",
        "LoD/1.09": "c1d05e132bc8c3bc87e7a971916e9b9b",
        "LoD/1.09b": "c1d05e132bc8c3bc87e7a971916e9b9b",
        "LoD/1.09d": "c1d05e132bc8c3bc87e7a971916e9b9b",
        "LoD/1.10": "c1d05e132bc8c3bc87e7a971916e9b9b",
        "LoD/1.11": "c1d05e132bc8c3bc87e7a971916e9b9b",
        "LoD/1.11b": "c1d05e132bc8c3bc87e7a971916e9b9b",
        "LoD/1.12a": "c1d05e132bc8c3bc87e7a971916e9b9b",
        "LoD/1.13c": "c1d05e132bc8c3bc87e7a971916e9b9b",
        "LoD/1.13d": "c1d05e132bc8c3bc87e7a971916e9b9b",
        "LoD/1.14a": "c1d05e132bc8c3bc87e7a971916e9b9b",
        "LoD/1.14b": "c1d05e132bc8c3bc87e7a971916e9b9b",
        "LoD/1.14c": "c1d05e132bc8c3bc87e7a971916e9b9b",
        "LoD/1.14d": "c1d05e132bc8c3bc87e7a971916e9b9b"
      },
      "constants": {
        "LoD/1.07": [
          256,
          544,
          4204152,
          4215732,
          4215736,
          4215744
        ],
        "LoD/1.08": [
          256,
          544,
          4204152,
          4215732,
          4215736,
          4215744
        ],
        "LoD/1.09": [
          256,
          544,
          4204152,
          4215732,
          4215736,
          4215744
        ],
        "LoD/1.09b": [
          256,
          544,
          4204152,
          4215732,
          4215736,
          4215744
        ],
        "LoD/1.09d": [
          256,
          544,
          4204152,
          4215732,
          4215736,
          4215744
        ],
        "LoD/1.10": [
          256,
          544,
          4204152,
          4215732,
          4215736,
          4215744
        ],
        "LoD/1.11": [
          256,
          544,
          4204152,
          4215732,
          4215736,
          4215744
        ],
        "LoD/1.11b": [
          256,
          544,
          4204152,
          4215732,
          4215736,
          4215744
        ],
        "LoD/1.12a": [
          256,
          544,
          4204152,
          4215732,
          4215736,
          4215744
        ],
        "LoD/1.13c": [
          256,
          544,
          4204152,
          4215732,
          4215736,
          4215744
        ],
        "LoD/1.13d": [
          256,
          544,
          4204152,
          4215732,
          4215736,
          4215744
        ],
        "LoD/1.14a": [
          256,
          544,
          4204152,
          4215732,
          4215736,
          4215744
        ],
        "LoD/1.14b": [
          256,
          544,
          4204152,
          4215732,
          4215736,
          4215744
        ],
        "LoD/1.14c": [
          256,
          544,
          4204152,
          4215732,
          4215736,
          4215744
        ],
        "LoD/1.14d": [
          256,
          544,
          4204152,
          4215732,
          4215736,
          4215744
        ]
      },
      "globals": {
        "LoD/1.07": [
          "0x53C0|DAT_004053c0",
          "0x2678|LAB_00402678",
          "0xFF9FF000|ExceptionList",
          "0xFFFFFFFFFFBFFFE4|",
          "0x6640|DAT_00406640",
          "0x53B8|DAT_004053b8",
          "0x5090|PTR_LCMapStringW_00405090",
          "0x53B4|DAT_004053b4",
          "0x508C|PTR_LCMapStringA_0040508c",
          "0xFFFFFFFFFFC00010|"
        ],
        "LoD/1.08": [
          "0x53C0|DAT_004053c0",
          "0x2678|LAB_00402678",
          "0xFF9FF000|ExceptionList",
          "0xFFFFFFFFFFBFFFE4|",
          "0x6640|DAT_00406640",
          "0x53B8|DAT_004053b8",
          "0x5090|PTR_LCMapStringW_00405090",
          "0x53B4|DAT_004053b4",
          "0x508C|PTR_LCMapStringA_0040508c",
          "0xFFFFFFFFFFC00010|"
        ],
        "LoD/1.09": [
          "0x53C0|DAT_004053c0",
          "0x2678|LAB_00402678",
          "0xFF9FF000|ExceptionList",
          "0xFFFFFFFFFFBFFFE4|",
          "0x6640|DAT_00406640",
          "0x53B8|DAT_004053b8",
          "0x5090|PTR_LCMapStringW_00405090",
          "0x53B4|DAT_004053b4",
          "0x508C|PTR_LCMapStringA_0040508c",
          "0xFFFFFFFFFFC00010|"
        ],
        "LoD/1.09b": [
          "0x53C0|DAT_004053c0",
          "0x2678|LAB_00402678",
          "0xFF9FF000|ExceptionList",
          "0xFFFFFFFFFFBFFFE4|",
          "0x6640|DAT_00406640",
          "0x53B8|DAT_004053b8",
          "0x5090|PTR_LCMapStringW_00405090",
          "0x53B4|DAT_004053b4",
          "0x508C|PTR_LCMapStringA_0040508c",
          "0xFFFFFFFFFFC00010|"
        ],
        "LoD/1.09d": [
          "0x53C0|DAT_004053c0",
          "0x2678|LAB_00402678",
          "0xFF9FF000|ExceptionList",
          "0xFFFFFFFFFFBFFFE4|",
          "0x6640|DAT_00406640",
          "0x53B8|DAT_004053b8",
          "0x5090|PTR_LCMapStringW_00405090",
          "0x53B4|DAT_004053b4",
          "0x508C|PTR_LCMapStringA_0040508c",
          "0xFFFFFFFFFFC00010|"
        ],
        "LoD/1.10": [
          "0x53C0|DAT_004053c0",
          "0x2678|LAB_00402678",
          "0xFF9FF000|ExceptionList",
          "0xFFFFFFFFFFBFFFE4|",
          "0x6640|DAT_00406640",
          "0x53B8|DAT_004053b8",
          "0x5090|PTR_LCMapStringW_00405090",
          "0x53B4|DAT_004053b4",
          "0x508C|PTR_LCMapStringA_0040508c",
          "0xFFFFFFFFFFC00010|"
        ],
        "LoD/1.11": [
          "0x53C0|DAT_004053c0",
          "0x2678|LAB_00402678",
          "0xFF9FF000|ExceptionList",
          "0xFFFFFFFFFFBFFFE4|",
          "0x6640|DAT_00406640",
          "0x53B8|DAT_004053b8",
          "0x5090|PTR_LCMapStringW_00405090",
          "0x53B4|DAT_004053b4",
          "0x508C|PTR_LCMapStringA_0040508c",
          "0xFFFFFFFFFFC00010|"
        ],
        "LoD/1.11b": [
          "0x53C0|DAT_004053c0",
          "0x2678|LAB_00402678",
          "0xFF9FF000|ExceptionList",
          "0xFFFFFFFFFFBFFFE4|",
          "0x6640|DAT_00406640",
          "0x53B8|DAT_004053b8",
          "0x5090|PTR_LCMapStringW_00405090",
          "0x53B4|DAT_004053b4",
          "0x508C|PTR_LCMapStringA_0040508c",
          "0xFFFFFFFFFFC00010|"
        ],
        "LoD/1.12a": [
          "0x53C0|DAT_004053c0",
          "0x2678|LAB_00402678",
          "0xFF9FF000|ExceptionList",
          "0xFFFFFFFFFFBFFFE4|",
          "0x6640|DAT_00406640",
          "0x53B8|DAT_004053b8",
          "0x5090|PTR_LCMapStringW_00405090",
          "0x53B4|DAT_004053b4",
          "0x508C|PTR_LCMapStringA_0040508c",
          "0xFFFFFFFFFFC00010|"
        ],
        "LoD/1.13c": [
          "0x53C0|DAT_004053c0",
          "0x2678|LAB_00402678",
          "0xFF9FF000|ExceptionList",
          "0xFFFFFFFFFFBFFFE4|",
          "0x6640|DAT_00406640",
          "0x53B8|DAT_004053b8",
          "0x5090|PTR_LCMapStringW_00405090",
          "0x53B4|DAT_004053b4",
          "0x508C|PTR_LCMapStringA_0040508c",
          "0xFFFFFFFFFFC00010|"
        ],
        "LoD/1.13d": [
          "0x53C0|DAT_004053c0",
          "0x2678|LAB_00402678",
          "0xFF9FF000|ExceptionList",
          "0xFFFFFFFFFFBFFFE4|",
          "0x6640|DAT_00406640",
          "0x53B8|DAT_004053b8",
          "0x5090|PTR_LCMapStringW_00405090",
          "0x53B4|DAT_004053b4",
          "0x508C|PTR_LCMapStringA_0040508c",
          "0xFFFFFFFFFFC00010|"
        ],
        "LoD/1.14a": [
          "0x53C0|DAT_004053c0",
          "0x2678|LAB_00402678",
          "0xFF9FF000|ExceptionList",
          "0xFFFFFFFFFFBFFFE4|",
          "0x6640|DAT_00406640",
          "0x53B8|DAT_004053b8",
          "0x5090|PTR_LCMapStringW_00405090",
          "0x53B4|DAT_004053b4",
          "0x508C|PTR_LCMapStringA_0040508c",
          "0xFFFFFFFFFFC00010|"
        ],
        "LoD/1.14b": [
          "0x53C0|DAT_004053c0",
          "0x2678|LAB_00402678",
          "0xFF9FF000|ExceptionList",
          "0xFFFFFFFFFFBFFFE4|",
          "0x6640|DAT_00406640",
          "0x53B8|DAT_004053b8",
          "0x5090|PTR_LCMapStringW_00405090",
          "0x53B4|DAT_004053b4",
          "0x508C|PTR_LCMapStringA_0040508c",
          "0xFFFFFFFFFFC00010|"
        ],
        "LoD/1.14c": [
          "0x53C0|DAT_004053c0",
          "0x2678|LAB_00402678",
          "0xFF9FF000|ExceptionList",
          "0xFFFFFFFFFFBFFFE4|",
          "0x6640|DAT_00406640",
          "0x53B8|DAT_004053b8",
          "0x5090|PTR_LCMapStringW_00405090",
          "0x53B4|DAT_004053b4",
          "0x508C|PTR_LCMapStringA_0040508c",
          "0xFFFFFFFFFFC00010|"
        ],
        "LoD/1.14d": [
          "0x53C0|DAT_004053c0",
          "0x2678|LAB_00402678",
          "0xFF9FF000|ExceptionList",
          "0xFFFFFFFFFFBFFFE4|",
          "0x6640|DAT_00406640",
          "0x53B8|DAT_004053b8",
          "0x5090|PTR_LCMapStringW_00405090",
          "0x53B4|DAT_004053b4",
          "0x508C|PTR_LCMapStringA_0040508c",
          "0xFFFFFFFFFFC00010|"
        ]
      }
    },
    "diablo ii.exe_CalculateStringLengthWithLimit": {
      "addresses": {
        "LoD/1.07": "0x00402B00",
        "LoD/1.08": "0x00402B00",
        "LoD/1.09": "0x00402B00",
        "LoD/1.09b": "0x00402B00",
        "LoD/1.09d": "0x00402B00",
        "LoD/1.10": "0x00402B00",
        "LoD/1.11": "0x00402B00",
        "LoD/1.11b": "0x00402B00",
        "LoD/1.12a": "0x00402B00",
        "LoD/1.13c": "0x00402B00",
        "LoD/1.13d": "0x00402B00",
        "LoD/1.14a": "0x00402B00",
        "LoD/1.14b": "0x00402B00",
        "LoD/1.14c": "0x00402B00",
        "LoD/1.14d": "0x00402B00"
      },
      "rvas": {
        "LoD/1.07": "0x2B00",
        "LoD/1.08": "0x2B00",
        "LoD/1.09": "0x2B00",
        "LoD/1.09b": "0x2B00",
        "LoD/1.09d": "0x2B00",
        "LoD/1.10": "0x2B00",
        "LoD/1.11": "0x2B00",
        "LoD/1.11b": "0x2B00",
        "LoD/1.12a": "0x2B00",
        "LoD/1.13c": "0x2B00",
        "LoD/1.13d": "0x2B00",
        "LoD/1.14a": "0x2B00",
        "LoD/1.14b": "0x2B00",
        "LoD/1.14c": "0x2B00",
        "LoD/1.14d": "0x2B00"
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
        "LoD/1.13d": 43,
        "LoD/1.14a": 43,
        "LoD/1.14b": 43,
        "LoD/1.14c": 43,
        "LoD/1.14d": 43
      },
      "name": "CalculateStringLengthWithLimit",
      "signature": "int CalculateStringLengthWithLimit(char * lpszString, int nMaxLength)",
      "calling_convention": "__cdecl",
      "return_type": "int",
      "comment": "Calculate the length of a null-terminated string with maximum limit.\n\nAlgorithm:\n1. Initialize current pointer to start of string and remaining counter to max length\n2. If max length is zero, skip to step 5\n3. Loop while remaining length > 0:\n   a. Decrement remaining length counter\n   b. Check if current character is null terminator, if so break loop\n   c. Advance current pointer to next character\n4. Continue loop until null terminator found or max length reached\n5. Check if null terminator was found:\n   a. If found: return actual string length (current pointer - original pointer)\n   b. If not found: return max length parameter (string exceeds limit)\n\nParameters:\nlpszString (char *): Pointer to null-terminated string buffer to measure\nnMaxLength (int): Maximum number of characters to examine before stopping\n\nReturns:\nint: Actual string length if null terminator found within limit\n     Maximum length parameter if string exceeds specified limit\n     Zero if maximum length parameter is zero\n\nSpecial Cases:\n- Returns 0 if nMaxLength is 0 (no characters to examine)\n- Returns nMaxLength if no null terminator found within limit\n- Handles empty string (immediate null terminator) correctly by returning 0",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:c365f0335b7bc4452623cbc78de16e67",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "c365f0335b7bc4452623cbc78de16e67",
        "CFG": "ce1512b65f10974868260b09ee7d6f5d",
        "PRO": "44eb51cb2190f284eca0a4e49c8cfa09",
        "CAL": null,
        "CON": null,
        "APS": null
      },
      "callers": {
        "LoD/1.07": [
          "LocaleMapStringWithConversion|0x4028DC"
        ],
        "LoD/1.08": [
          "LocaleMapStringWithConversion|0x4028DC"
        ],
        "LoD/1.09": [
          "LocaleMapStringWithConversion|0x4028DC"
        ],
        "LoD/1.09b": [
          "LocaleMapStringWithConversion|0x4028DC"
        ],
        "LoD/1.09d": [
          "LocaleMapStringWithConversion|0x4028DC"
        ],
        "LoD/1.10": [
          "LocaleMapStringWithConversion|0x4028DC"
        ],
        "LoD/1.11": [
          "LocaleMapStringWithConversion|0x4028DC"
        ],
        "LoD/1.11b": [
          "LocaleMapStringWithConversion|0x4028DC"
        ],
        "LoD/1.12a": [
          "LocaleMapStringWithConversion|0x4028DC"
        ],
        "LoD/1.13c": [
          "LocaleMapStringWithConversion|0x4028DC"
        ],
        "LoD/1.13d": [
          "LocaleMapStringWithConversion|0x4028DC"
        ],
        "LoD/1.14a": [
          "LocaleMapStringWithConversion|0x4028DC"
        ],
        "LoD/1.14b": [
          "LocaleMapStringWithConversion|0x4028DC"
        ],
        "LoD/1.14c": [
          "LocaleMapStringWithConversion|0x4028DC"
        ],
        "LoD/1.14d": [
          "LocaleMapStringWithConversion|0x4028DC"
        ]
      },
      "instruction_counts": {
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
        "LoD/1.13d": 20,
        "LoD/1.14a": 20,
        "LoD/1.14b": 20,
        "LoD/1.14c": 20,
        "LoD/1.14d": 20
      },
      "stack_frame_sizes": {
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
        "LoD/1.13d": 12,
        "LoD/1.14a": 12,
        "LoD/1.14b": 12,
        "LoD/1.14c": 12,
        "LoD/1.14d": 12
      },
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
        "LoD/1.13d": 6,
        "LoD/1.14a": 6,
        "LoD/1.14b": 6,
        "LoD/1.14c": 6,
        "LoD/1.14d": 6
      },
      "loop_counts": {
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
        "LoD/1.13d": 1,
        "LoD/1.14a": 1,
        "LoD/1.14b": 1,
        "LoD/1.14c": 1,
        "LoD/1.14d": 1
      },
      "mnemonic_hashes": {
        "LoD/1.07": "c365f0335b7bc4452623cbc78de16e67",
        "LoD/1.08": "c365f0335b7bc4452623cbc78de16e67",
        "LoD/1.09": "c365f0335b7bc4452623cbc78de16e67",
        "LoD/1.09b": "c365f0335b7bc4452623cbc78de16e67",
        "LoD/1.09d": "c365f0335b7bc4452623cbc78de16e67",
        "LoD/1.10": "c365f0335b7bc4452623cbc78de16e67",
        "LoD/1.11": "c365f0335b7bc4452623cbc78de16e67",
        "LoD/1.11b": "c365f0335b7bc4452623cbc78de16e67",
        "LoD/1.12a": "c365f0335b7bc4452623cbc78de16e67",
        "LoD/1.13c": "c365f0335b7bc4452623cbc78de16e67",
        "LoD/1.13d": "c365f0335b7bc4452623cbc78de16e67",
        "LoD/1.14a": "c365f0335b7bc4452623cbc78de16e67",
        "LoD/1.14b": "c365f0335b7bc4452623cbc78de16e67",
        "LoD/1.14c": "c365f0335b7bc4452623cbc78de16e67",
        "LoD/1.14d": "c365f0335b7bc4452623cbc78de16e67"
      },
      "globals": {
        "LoD/1.07": [
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.08": [
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.09": [
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.09b": [
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.09d": [
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.10": [
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.11": [
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.11b": [
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.12a": [
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.13c": [
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.13d": [
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.14a": [
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.14b": [
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.14c": [
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.14d": [
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|"
        ]
      }
    },
    "diablo ii.exe_GetCharacterTypeInfo": {
      "addresses": {
        "LoD/1.07": "0x00402B2B",
        "LoD/1.08": "0x00402B2B",
        "LoD/1.09": "0x00402B2B",
        "LoD/1.09b": "0x00402B2B",
        "LoD/1.09d": "0x00402B2B",
        "LoD/1.10": "0x00402B2B",
        "LoD/1.11": "0x00402B2B",
        "LoD/1.11b": "0x00402B2B",
        "LoD/1.12a": "0x00402B2B",
        "LoD/1.13c": "0x00402B2B",
        "LoD/1.13d": "0x00402B2B",
        "LoD/1.14a": "0x00402B2B",
        "LoD/1.14b": "0x00402B2B",
        "LoD/1.14c": "0x00402B2B",
        "LoD/1.14d": "0x00402B2B"
      },
      "rvas": {
        "LoD/1.07": "0x2B2B",
        "LoD/1.08": "0x2B2B",
        "LoD/1.09": "0x2B2B",
        "LoD/1.09b": "0x2B2B",
        "LoD/1.09d": "0x2B2B",
        "LoD/1.10": "0x2B2B",
        "LoD/1.11": "0x2B2B",
        "LoD/1.11b": "0x2B2B",
        "LoD/1.12a": "0x2B2B",
        "LoD/1.13c": "0x2B2B",
        "LoD/1.13d": "0x2B2B",
        "LoD/1.14a": "0x2B2B",
        "LoD/1.14b": "0x2B2B",
        "LoD/1.14c": "0x2B2B",
        "LoD/1.14d": "0x2B2B"
      },
      "sizes": {
        "LoD/1.07": 318,
        "LoD/1.08": 318,
        "LoD/1.09": 318,
        "LoD/1.09b": 318,
        "LoD/1.09d": 318,
        "LoD/1.10": 318,
        "LoD/1.11": 318,
        "LoD/1.11b": 318,
        "LoD/1.12a": 318,
        "LoD/1.13c": 318,
        "LoD/1.13d": 318,
        "LoD/1.14a": 318,
        "LoD/1.14b": 318,
        "LoD/1.14c": 318,
        "LoD/1.14d": 318
      },
      "name": "GetCharacterTypeInfo",
      "signature": "BOOL GetCharacterTypeInfo(DWORD dwInfoType, LPCSTR lpszString, int nStringLength, LPWORD lpwCharType, UINT uiCodePage, LCID dwLocaleId, int nConversionFlags)",
      "calling_convention": "__cdecl",
      "return_type": "BOOL",
      "comment": "Retrieves character type information for a string using either Unicode or ANSI APIs based on system capability detection.\n\nAlgorithm:\n1. Set up structured exception handling frame with stack-based exception list\n2. Initialize global character type detection state (DAT_1003ca98) on first call\n3. Test Unicode capability by calling GetStringTypeW with empty string\n4. Fall back to ANSI mode if Unicode fails by calling GetStringTypeA  \n5. Store detected capability (1=Unicode, 2=ANSI) in global state for subsequent calls\n6. Branch execution based on detected character handling mode:\n   - Unicode mode (1): Convert ANSI input to Unicode then call GetStringTypeW\n   - ANSI mode (2): Call GetStringTypeA directly with input parameters\n7. Apply default locale if codepage/locale parameters are zero\n8. Restore exception handling state and return API result\n\nParameters:\ndwInfoType - Character type flags (CT_CTYPE1, CT_CTYPE2, CT_CTYPE3)\nlpszString - Input string to analyze for character types\ncchString - Length of input string in characters, or -1 for null-terminated\nlpwCharType - Output buffer receiving character type information per character\nuiCodePage - Code page for Unicode conversion, 0 uses thread default\ndwLocaleId - Locale identifier for character analysis, 0 uses system default\ndwFlags - Conversion flags affecting MultiByteToWideChar behavior\n\nReturns:\nTRUE on successful character type analysis\nFALSE on failure (invalid parameters, conversion errors, or unsupported locale)\n\nSpecial Cases:\nMagic number 0xffffffff indicates exception handling state marker\nGlobal DAT_1003ca98 stores capability: 0=uninitialized, 1=Unicode, 2=ANSI only\nDynamic stack allocation used for Unicode conversion buffer sizing\nException handler DAT_10028758 protects against conversion failures\n\nError Handling:\nUnicode detection failure falls back to ANSI mode automatically\nZero codepage/locale parameters use system defaults (g_dwThreadLocaleCodePage, g_dwLocaleFlags)\nMultiByteToWideChar failure returns FALSE without character analysis\nStack allocation failure detected via null pointer check",
      "name_source": "LoD/1.07",
      "method": "CAL",
      "index": "CAL:7baa6daebac79b3e485665c35e660eb8",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "a7046d73bbd286a50d5e7204509858d2",
        "CFG": "df4d2cc4750989c094de567606c5d922",
        "PRO": "dcf290709e10ba1c807848e5f8e01997",
        "CAL": "7baa6daebac79b3e485665c35e660eb8",
        "CON": "99ebe54fd9c7f35cfed123d133021dc7",
        "APS": null
      },
      "callees": {
        "LoD/1.07": [
          "GetStringTypeA|0x26",
          "GetStringTypeW|0x27",
          "_memset|0x403CB0",
          "MultiByteToWideChar|0x23",
          "AllocateStackSpace|0x403C80"
        ],
        "LoD/1.08": [
          "GetStringTypeA|0x26",
          "MultiByteToWideChar|0x23",
          "GetStringTypeW|0x27",
          "_memset|0x403CB0",
          "AllocateStackSpace|0x403C80"
        ],
        "LoD/1.09": [
          "AllocateStackSpace|0x403C80",
          "_memset|0x403CB0",
          "MultiByteToWideChar|0x23",
          "GetStringTypeW|0x27",
          "GetStringTypeA|0x26"
        ],
        "LoD/1.09b": [
          "AllocateStackSpace|0x403C80",
          "GetStringTypeA|0x26",
          "_memset|0x403CB0",
          "GetStringTypeW|0x27",
          "MultiByteToWideChar|0x23"
        ],
        "LoD/1.09d": [
          "AllocateStackSpace|0x403C80",
          "GetStringTypeA|0x26",
          "GetStringTypeW|0x27",
          "_memset|0x403CB0",
          "MultiByteToWideChar|0x23"
        ],
        "LoD/1.10": [
          "GetStringTypeA|0x26",
          "AllocateStackSpace|0x403C80",
          "MultiByteToWideChar|0x23",
          "_memset|0x403CB0",
          "GetStringTypeW|0x27"
        ],
        "LoD/1.11": [
          "GetStringTypeW|0x27",
          "_memset|0x403CB0",
          "MultiByteToWideChar|0x23",
          "GetStringTypeA|0x26",
          "AllocateStackSpace|0x403C80"
        ],
        "LoD/1.11b": [
          "MultiByteToWideChar|0x23",
          "AllocateStackSpace|0x403C80",
          "GetStringTypeW|0x27",
          "GetStringTypeA|0x26",
          "_memset|0x403CB0"
        ],
        "LoD/1.12a": [
          "AllocateStackSpace|0x403C80",
          "_memset|0x403CB0",
          "GetStringTypeW|0x27",
          "GetStringTypeA|0x26",
          "MultiByteToWideChar|0x23"
        ],
        "LoD/1.13c": [
          "GetStringTypeA|0x26",
          "MultiByteToWideChar|0x23",
          "_memset|0x403CB0",
          "AllocateStackSpace|0x403C80",
          "GetStringTypeW|0x27"
        ],
        "LoD/1.13d": [
          "_memset|0x403CB0",
          "AllocateStackSpace|0x403C80",
          "GetStringTypeW|0x27",
          "GetStringTypeA|0x26",
          "MultiByteToWideChar|0x23"
        ],
        "LoD/1.14a": [
          "AllocateStackSpace|0x403C80",
          "GetStringTypeW|0x27",
          "GetStringTypeA|0x26",
          "MultiByteToWideChar|0x23",
          "_memset|0x403CB0"
        ],
        "LoD/1.14b": [
          "AllocateStackSpace|0x403C80",
          "MultiByteToWideChar|0x23",
          "_memset|0x403CB0",
          "GetStringTypeA|0x26",
          "GetStringTypeW|0x27"
        ],
        "LoD/1.14c": [
          "MultiByteToWideChar|0x23",
          "AllocateStackSpace|0x403C80",
          "GetStringTypeA|0x26",
          "GetStringTypeW|0x27",
          "_memset|0x403CB0"
        ],
        "LoD/1.14d": [
          "_memset|0x403CB0",
          "AllocateStackSpace|0x403C80",
          "MultiByteToWideChar|0x23",
          "GetStringTypeA|0x26",
          "GetStringTypeW|0x27"
        ]
      },
      "callers": {
        "LoD/1.07": [
          "InitializeCharacterTables|0x401861"
        ],
        "LoD/1.08": [
          "InitializeCharacterTables|0x401861"
        ],
        "LoD/1.09": [
          "InitializeCharacterTables|0x401861"
        ],
        "LoD/1.09b": [
          "InitializeCharacterTables|0x401861"
        ],
        "LoD/1.09d": [
          "InitializeCharacterTables|0x401861"
        ],
        "LoD/1.10": [
          "InitializeCharacterTables|0x401861"
        ],
        "LoD/1.11": [
          "InitializeCharacterTables|0x401861"
        ],
        "LoD/1.11b": [
          "InitializeCharacterTables|0x401861"
        ],
        "LoD/1.12a": [
          "InitializeCharacterTables|0x401861"
        ],
        "LoD/1.13c": [
          "InitializeCharacterTables|0x401861"
        ],
        "LoD/1.13d": [
          "InitializeCharacterTables|0x401861"
        ],
        "LoD/1.14a": [
          "InitializeCharacterTables|0x401861"
        ],
        "LoD/1.14b": [
          "InitializeCharacterTables|0x401861"
        ],
        "LoD/1.14c": [
          "InitializeCharacterTables|0x401861"
        ],
        "LoD/1.14d": [
          "InitializeCharacterTables|0x401861"
        ]
      },
      "instruction_counts": {
        "LoD/1.07": 117,
        "LoD/1.08": 117,
        "LoD/1.09": 117,
        "LoD/1.09b": 117,
        "LoD/1.09d": 117,
        "LoD/1.10": 117,
        "LoD/1.11": 117,
        "LoD/1.11b": 117,
        "LoD/1.12a": 117,
        "LoD/1.13c": 117,
        "LoD/1.13d": 117,
        "LoD/1.14a": 117,
        "LoD/1.14b": 117,
        "LoD/1.14c": 117,
        "LoD/1.14d": 117
      },
      "stack_frame_sizes": {
        "LoD/1.07": 88,
        "LoD/1.08": 88,
        "LoD/1.09": 88,
        "LoD/1.09b": 88,
        "LoD/1.09d": 88,
        "LoD/1.10": 88,
        "LoD/1.11": 88,
        "LoD/1.11b": 88,
        "LoD/1.12a": 88,
        "LoD/1.13c": 88,
        "LoD/1.13d": 88,
        "LoD/1.14a": 88,
        "LoD/1.14b": 88,
        "LoD/1.14c": 88,
        "LoD/1.14d": 88
      },
      "basic_block_counts": {
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
        "LoD/1.13d": 20,
        "LoD/1.14a": 20,
        "LoD/1.14b": 20,
        "LoD/1.14c": 20,
        "LoD/1.14d": 20
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
        "LoD/1.13d": 0,
        "LoD/1.14a": 0,
        "LoD/1.14b": 0,
        "LoD/1.14c": 0,
        "LoD/1.14d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "a7046d73bbd286a50d5e7204509858d2",
        "LoD/1.08": "a7046d73bbd286a50d5e7204509858d2",
        "LoD/1.09": "a7046d73bbd286a50d5e7204509858d2",
        "LoD/1.09b": "a7046d73bbd286a50d5e7204509858d2",
        "LoD/1.09d": "a7046d73bbd286a50d5e7204509858d2",
        "LoD/1.10": "a7046d73bbd286a50d5e7204509858d2",
        "LoD/1.11": "a7046d73bbd286a50d5e7204509858d2",
        "LoD/1.11b": "a7046d73bbd286a50d5e7204509858d2",
        "LoD/1.12a": "a7046d73bbd286a50d5e7204509858d2",
        "LoD/1.13c": "a7046d73bbd286a50d5e7204509858d2",
        "LoD/1.13d": "a7046d73bbd286a50d5e7204509858d2",
        "LoD/1.14a": "a7046d73bbd286a50d5e7204509858d2",
        "LoD/1.14b": "a7046d73bbd286a50d5e7204509858d2",
        "LoD/1.14c": "a7046d73bbd286a50d5e7204509858d2",
        "LoD/1.14d": "a7046d73bbd286a50d5e7204509858d2"
      },
      "constants": {
        "LoD/1.07": [
          4204152,
          4215732,
          4215736,
          4215768
        ],
        "LoD/1.08": [
          4204152,
          4215732,
          4215736,
          4215768
        ],
        "LoD/1.09": [
          4204152,
          4215732,
          4215736,
          4215768
        ],
        "LoD/1.09b": [
          4204152,
          4215732,
          4215736,
          4215768
        ],
        "LoD/1.09d": [
          4204152,
          4215732,
          4215736,
          4215768
        ],
        "LoD/1.10": [
          4204152,
          4215732,
          4215736,
          4215768
        ],
        "LoD/1.11": [
          4204152,
          4215732,
          4215736,
          4215768
        ],
        "LoD/1.11b": [
          4204152,
          4215732,
          4215736,
          4215768
        ],
        "LoD/1.12a": [
          4204152,
          4215732,
          4215736,
          4215768
        ],
        "LoD/1.13c": [
          4204152,
          4215732,
          4215736,
          4215768
        ],
        "LoD/1.13d": [
          4204152,
          4215732,
          4215736,
          4215768
        ],
        "LoD/1.14a": [
          4204152,
          4215732,
          4215736,
          4215768
        ],
        "LoD/1.14b": [
          4204152,
          4215732,
          4215736,
          4215768
        ],
        "LoD/1.14c": [
          4204152,
          4215732,
          4215736,
          4215768
        ],
        "LoD/1.14d": [
          4204152,
          4215732,
          4215736,
          4215768
        ]
      },
      "globals": {
        "LoD/1.07": [
          "0x53D8|DAT_004053d8",
          "0x2678|LAB_00402678",
          "0xFF9FF000|ExceptionList",
          "0xFFFFFFFFFFBFFFE4|",
          "0x6644|DAT_00406644",
          "0xFFFFFFFFFFBFFFE0|",
          "0x53B8|DAT_004053b8",
          "0x5098|PTR_GetStringTypeW_00405098",
          "0x53B4|DAT_004053b4",
          "0x5094|PTR_GetStringTypeA_00405094"
        ],
        "LoD/1.08": [
          "0x53D8|DAT_004053d8",
          "0x2678|LAB_00402678",
          "0xFF9FF000|ExceptionList",
          "0xFFFFFFFFFFBFFFE4|",
          "0x6644|DAT_00406644",
          "0xFFFFFFFFFFBFFFE0|",
          "0x53B8|DAT_004053b8",
          "0x5098|PTR_GetStringTypeW_00405098",
          "0x53B4|DAT_004053b4",
          "0x5094|PTR_GetStringTypeA_00405094"
        ],
        "LoD/1.09": [
          "0x53D8|DAT_004053d8",
          "0x2678|LAB_00402678",
          "0xFF9FF000|ExceptionList",
          "0xFFFFFFFFFFBFFFE4|",
          "0x6644|DAT_00406644",
          "0xFFFFFFFFFFBFFFE0|",
          "0x53B8|DAT_004053b8",
          "0x5098|PTR_GetStringTypeW_00405098",
          "0x53B4|DAT_004053b4",
          "0x5094|PTR_GetStringTypeA_00405094"
        ],
        "LoD/1.09b": [
          "0x53D8|DAT_004053d8",
          "0x2678|LAB_00402678",
          "0xFF9FF000|ExceptionList",
          "0xFFFFFFFFFFBFFFE4|",
          "0x6644|DAT_00406644",
          "0xFFFFFFFFFFBFFFE0|",
          "0x53B8|DAT_004053b8",
          "0x5098|PTR_GetStringTypeW_00405098",
          "0x53B4|DAT_004053b4",
          "0x5094|PTR_GetStringTypeA_00405094"
        ],
        "LoD/1.09d": [
          "0x53D8|DAT_004053d8",
          "0x2678|LAB_00402678",
          "0xFF9FF000|ExceptionList",
          "0xFFFFFFFFFFBFFFE4|",
          "0x6644|DAT_00406644",
          "0xFFFFFFFFFFBFFFE0|",
          "0x53B8|DAT_004053b8",
          "0x5098|PTR_GetStringTypeW_00405098",
          "0x53B4|DAT_004053b4",
          "0x5094|PTR_GetStringTypeA_00405094"
        ],
        "LoD/1.10": [
          "0x53D8|DAT_004053d8",
          "0x2678|LAB_00402678",
          "0xFF9FF000|ExceptionList",
          "0xFFFFFFFFFFBFFFE4|",
          "0x6644|DAT_00406644",
          "0xFFFFFFFFFFBFFFE0|",
          "0x53B8|DAT_004053b8",
          "0x5098|PTR_GetStringTypeW_00405098",
          "0x53B4|DAT_004053b4",
          "0x5094|PTR_GetStringTypeA_00405094"
        ],
        "LoD/1.11": [
          "0x53D8|DAT_004053d8",
          "0x2678|LAB_00402678",
          "0xFF9FF000|ExceptionList",
          "0xFFFFFFFFFFBFFFE4|",
          "0x6644|DAT_00406644",
          "0xFFFFFFFFFFBFFFE0|",
          "0x53B8|DAT_004053b8",
          "0x5098|PTR_GetStringTypeW_00405098",
          "0x53B4|DAT_004053b4",
          "0x5094|PTR_GetStringTypeA_00405094"
        ],
        "LoD/1.11b": [
          "0x53D8|DAT_004053d8",
          "0x2678|LAB_00402678",
          "0xFF9FF000|ExceptionList",
          "0xFFFFFFFFFFBFFFE4|",
          "0x6644|DAT_00406644",
          "0xFFFFFFFFFFBFFFE0|",
          "0x53B8|DAT_004053b8",
          "0x5098|PTR_GetStringTypeW_00405098",
          "0x53B4|DAT_004053b4",
          "0x5094|PTR_GetStringTypeA_00405094"
        ],
        "LoD/1.12a": [
          "0x53D8|DAT_004053d8",
          "0x2678|LAB_00402678",
          "0xFF9FF000|ExceptionList",
          "0xFFFFFFFFFFBFFFE4|",
          "0x6644|DAT_00406644",
          "0xFFFFFFFFFFBFFFE0|",
          "0x53B8|DAT_004053b8",
          "0x5098|PTR_GetStringTypeW_00405098",
          "0x53B4|DAT_004053b4",
          "0x5094|PTR_GetStringTypeA_00405094"
        ],
        "LoD/1.13c": [
          "0x53D8|DAT_004053d8",
          "0x2678|LAB_00402678",
          "0xFF9FF000|ExceptionList",
          "0xFFFFFFFFFFBFFFE4|",
          "0x6644|DAT_00406644",
          "0xFFFFFFFFFFBFFFE0|",
          "0x53B8|DAT_004053b8",
          "0x5098|PTR_GetStringTypeW_00405098",
          "0x53B4|DAT_004053b4",
          "0x5094|PTR_GetStringTypeA_00405094"
        ],
        "LoD/1.13d": [
          "0x53D8|DAT_004053d8",
          "0x2678|LAB_00402678",
          "0xFF9FF000|ExceptionList",
          "0xFFFFFFFFFFBFFFE4|",
          "0x6644|DAT_00406644",
          "0xFFFFFFFFFFBFFFE0|",
          "0x53B8|DAT_004053b8",
          "0x5098|PTR_GetStringTypeW_00405098",
          "0x53B4|DAT_004053b4",
          "0x5094|PTR_GetStringTypeA_00405094"
        ],
        "LoD/1.14a": [
          "0x53D8|DAT_004053d8",
          "0x2678|LAB_00402678",
          "0xFF9FF000|ExceptionList",
          "0xFFFFFFFFFFBFFFE4|",
          "0x6644|DAT_00406644",
          "0xFFFFFFFFFFBFFFE0|",
          "0x53B8|DAT_004053b8",
          "0x5098|PTR_GetStringTypeW_00405098",
          "0x53B4|DAT_004053b4",
          "0x5094|PTR_GetStringTypeA_00405094"
        ],
        "LoD/1.14b": [
          "0x53D8|DAT_004053d8",
          "0x2678|LAB_00402678",
          "0xFF9FF000|ExceptionList",
          "0xFFFFFFFFFFBFFFE4|",
          "0x6644|DAT_00406644",
          "0xFFFFFFFFFFBFFFE0|",
          "0x53B8|DAT_004053b8",
          "0x5098|PTR_GetStringTypeW_00405098",
          "0x53B4|DAT_004053b4",
          "0x5094|PTR_GetStringTypeA_00405094"
        ],
        "LoD/1.14c": [
          "0x53D8|DAT_004053d8",
          "0x2678|LAB_00402678",
          "0xFF9FF000|ExceptionList",
          "0xFFFFFFFFFFBFFFE4|",
          "0x6644|DAT_00406644",
          "0xFFFFFFFFFFBFFFE0|",
          "0x53B8|DAT_004053b8",
          "0x5098|PTR_GetStringTypeW_00405098",
          "0x53B4|DAT_004053b4",
          "0x5094|PTR_GetStringTypeA_00405094"
        ],
        "LoD/1.14d": [
          "0x53D8|DAT_004053d8",
          "0x2678|LAB_00402678",
          "0xFF9FF000|ExceptionList",
          "0xFFFFFFFFFFBFFFE4|",
          "0x6644|DAT_00406644",
          "0xFFFFFFFFFFBFFFE0|",
          "0x53B8|DAT_004053b8",
          "0x5098|PTR_GetStringTypeW_00405098",
          "0x53B4|DAT_004053b4",
          "0x5094|PTR_GetStringTypeA_00405094"
        ]
      }
    },
    "diablo ii.exe_CON_a25934a13615": {
      "addresses": {
        "LoD/1.07": "0x00402C74",
        "LoD/1.08": "0x00402C74",
        "LoD/1.09": "0x00402C74",
        "LoD/1.09b": "0x00402C74",
        "LoD/1.09d": "0x00402C74",
        "LoD/1.10": "0x00402C74",
        "LoD/1.11": "0x00402C74",
        "LoD/1.11b": "0x00402C74",
        "LoD/1.12a": "0x00402C74",
        "LoD/1.13c": "0x00402C74",
        "LoD/1.13d": "0x00402C74",
        "LoD/1.14a": "0x00402C74",
        "LoD/1.14b": "0x00402C74",
        "LoD/1.14c": "0x00402C74",
        "LoD/1.14d": "0x00402C74"
      },
      "rvas": {
        "LoD/1.07": "0x2C74",
        "LoD/1.08": "0x2C74",
        "LoD/1.09": "0x2C74",
        "LoD/1.09b": "0x2C74",
        "LoD/1.09d": "0x2C74",
        "LoD/1.10": "0x2C74",
        "LoD/1.11": "0x2C74",
        "LoD/1.11b": "0x2C74",
        "LoD/1.12a": "0x2C74",
        "LoD/1.13c": "0x2C74",
        "LoD/1.13d": "0x2C74",
        "LoD/1.14a": "0x2C74",
        "LoD/1.14b": "0x2C74",
        "LoD/1.14c": "0x2C74",
        "LoD/1.14d": "0x2C74"
      },
      "sizes": {
        "LoD/1.07": 68,
        "LoD/1.08": 68,
        "LoD/1.09": 68,
        "LoD/1.09b": 68,
        "LoD/1.09d": 68,
        "LoD/1.10": 68,
        "LoD/1.11": 68,
        "LoD/1.11b": 68,
        "LoD/1.12a": 68,
        "LoD/1.13c": 68,
        "LoD/1.13d": 68,
        "LoD/1.14a": 68,
        "LoD/1.14b": 68,
        "LoD/1.14c": 68,
        "LoD/1.14d": 68
      },
      "return_type": "int",
      "name_source": "LoD/1.07",
      "method": "CON",
      "index": "CON:a25934a13615bd9598bae62665dd096e",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "b31c4daec36fb36fa3cb9b8ebe073642",
        "CFG": "0fa1e39de5e198af9c73a3977127b991",
        "PRO": "55ad8d3af928417566a7f1f214235c31",
        "CAL": null,
        "CON": "a25934a13615bd9598bae62665dd096e",
        "APS": null
      },
      "display_name": "FUN_00402c74",
      "callers": {
        "LoD/1.07": [
          "FUN_00401a02|0x401A02"
        ],
        "LoD/1.08": [
          "FUN_00401a02|0x401A02"
        ],
        "LoD/1.09": [
          "FUN_00401a02|0x401A02"
        ],
        "LoD/1.09b": [
          "FUN_00401a02|0x401A02"
        ],
        "LoD/1.09d": [
          "FUN_00401a02|0x401A02"
        ],
        "LoD/1.10": [
          "FUN_00401a02|0x401A02"
        ],
        "LoD/1.11": [
          "FUN_00401a02|0x401A02"
        ],
        "LoD/1.11b": [
          "FUN_00401a02|0x401A02"
        ],
        "LoD/1.12a": [
          "FUN_00401a02|0x401A02"
        ],
        "LoD/1.13c": [
          "FUN_00401a02|0x401A02"
        ],
        "LoD/1.13d": [
          "FUN_00401a02|0x401A02"
        ],
        "LoD/1.14a": [
          "FUN_00401a02|0x401A02"
        ],
        "LoD/1.14b": [
          "FUN_00401a02|0x401A02"
        ],
        "LoD/1.14c": [
          "FUN_00401a02|0x401A02"
        ],
        "LoD/1.14d": [
          "FUN_00401a02|0x401A02"
        ]
      },
      "instruction_counts": {
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
        "LoD/1.13d": 25,
        "LoD/1.14a": 25,
        "LoD/1.14b": 25,
        "LoD/1.14c": 25,
        "LoD/1.14d": 25
      },
      "stack_frame_sizes": {
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
        "LoD/1.13d": 12,
        "LoD/1.14a": 12,
        "LoD/1.14b": 12,
        "LoD/1.14c": 12,
        "LoD/1.14d": 12
      },
      "basic_block_counts": {
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
        "LoD/1.13d": 8,
        "LoD/1.14a": 8,
        "LoD/1.14b": 8,
        "LoD/1.14c": 8,
        "LoD/1.14d": 8
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
        "LoD/1.13d": 0,
        "LoD/1.14a": 0,
        "LoD/1.14b": 0,
        "LoD/1.14c": 0,
        "LoD/1.14d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "b31c4daec36fb36fa3cb9b8ebe073642",
        "LoD/1.08": "b31c4daec36fb36fa3cb9b8ebe073642",
        "LoD/1.09": "b31c4daec36fb36fa3cb9b8ebe073642",
        "LoD/1.09b": "b31c4daec36fb36fa3cb9b8ebe073642",
        "LoD/1.09d": "b31c4daec36fb36fa3cb9b8ebe073642",
        "LoD/1.10": "b31c4daec36fb36fa3cb9b8ebe073642",
        "LoD/1.11": "b31c4daec36fb36fa3cb9b8ebe073642",
        "LoD/1.11b": "b31c4daec36fb36fa3cb9b8ebe073642",
        "LoD/1.12a": "b31c4daec36fb36fa3cb9b8ebe073642",
        "LoD/1.13c": "b31c4daec36fb36fa3cb9b8ebe073642",
        "LoD/1.13d": "b31c4daec36fb36fa3cb9b8ebe073642",
        "LoD/1.14a": "b31c4daec36fb36fa3cb9b8ebe073642",
        "LoD/1.14b": "b31c4daec36fb36fa3cb9b8ebe073642",
        "LoD/1.14c": "b31c4daec36fb36fa3cb9b8ebe073642",
        "LoD/1.14d": "b31c4daec36fb36fa3cb9b8ebe073642"
      },
      "constants": {
        "LoD/1.07": [
          343,
          4219562,
          4221121
        ],
        "LoD/1.08": [
          343,
          4219562,
          4221121
        ],
        "LoD/1.09": [
          343,
          4219562,
          4221121
        ],
        "LoD/1.09b": [
          343,
          4219562,
          4221121
        ],
        "LoD/1.09d": [
          343,
          4219562,
          4221121
        ],
        "LoD/1.10": [
          343,
          4219562,
          4221121
        ],
        "LoD/1.11": [
          343,
          4219562,
          4221121
        ],
        "LoD/1.11b": [
          343,
          4219562,
          4221121
        ],
        "LoD/1.12a": [
          343,
          4219562,
          4221121
        ],
        "LoD/1.13c": [
          343,
          4219562,
          4221121
        ],
        "LoD/1.13d": [
          343,
          4219562,
          4221121
        ],
        "LoD/1.14a": [
          343,
          4219562,
          4221121
        ],
        "LoD/1.14b": [
          343,
          4219562,
          4221121
        ],
        "LoD/1.14c": [
          343,
          4219562,
          4221121
        ],
        "LoD/1.14d": [
          343,
          4219562,
          4221121
        ]
      },
      "globals": {
        "LoD/1.07": [
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|",
          "0x68C1|DAT_004068c0+1",
          "0x62AA|DAT_004062aa"
        ],
        "LoD/1.08": [
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|",
          "0x68C1|DAT_004068c0+1",
          "0x62AA|DAT_004062aa"
        ],
        "LoD/1.09": [
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|",
          "0x68C1|DAT_004068c0+1",
          "0x62AA|DAT_004062aa"
        ],
        "LoD/1.09b": [
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|",
          "0x68C1|DAT_004068c0+1",
          "0x62AA|DAT_004062aa"
        ],
        "LoD/1.09d": [
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|",
          "0x68C1|DAT_004068c0+1",
          "0x62AA|DAT_004062aa"
        ],
        "LoD/1.10": [
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|",
          "0x68C1|DAT_004068c0+1",
          "0x62AA|DAT_004062aa"
        ],
        "LoD/1.11": [
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|",
          "0x68C1|DAT_004068c0+1",
          "0x62AA|DAT_004062aa"
        ],
        "LoD/1.11b": [
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|",
          "0x68C1|DAT_004068c0+1",
          "0x62AA|DAT_004062aa"
        ],
        "LoD/1.12a": [
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|",
          "0x68C1|DAT_004068c0+1",
          "0x62AA|DAT_004062aa"
        ],
        "LoD/1.13c": [
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|",
          "0x68C1|DAT_004068c0+1",
          "0x62AA|DAT_004062aa"
        ],
        "LoD/1.13d": [
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|",
          "0x68C1|DAT_004068c0+1",
          "0x62AA|DAT_004062aa"
        ],
        "LoD/1.14a": [
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|",
          "0x68C1|DAT_004068c0+1",
          "0x62AA|DAT_004062aa"
        ],
        "LoD/1.14b": [
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|",
          "0x68C1|DAT_004068c0+1",
          "0x62AA|DAT_004062aa"
        ],
        "LoD/1.14c": [
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|",
          "0x68C1|DAT_004068c0+1",
          "0x62AA|DAT_004062aa"
        ],
        "LoD/1.14d": [
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|",
          "0x68C1|DAT_004068c0+1",
          "0x62AA|DAT_004062aa"
        ]
      }
    },
    "diablo ii.exe_MNE_69f7deb725db": {
      "addresses": {
        "LoD/1.07": "0x00402CD6",
        "LoD/1.08": "0x00402CD6",
        "LoD/1.09": "0x00402CD6",
        "LoD/1.09b": "0x00402CD6",
        "LoD/1.09d": "0x00402CD6",
        "LoD/1.10": "0x00402CD6",
        "LoD/1.11": "0x00402CD6",
        "LoD/1.11b": "0x00402CD6",
        "LoD/1.12a": "0x00402CD6",
        "LoD/1.13c": "0x00402CD6",
        "LoD/1.13d": "0x00402CD6",
        "LoD/1.14a": "0x00402CD6",
        "LoD/1.14b": "0x00402CD6",
        "LoD/1.14c": "0x00402CD6",
        "LoD/1.14d": "0x00402CD6"
      },
      "rvas": {
        "LoD/1.07": "0x2CD6",
        "LoD/1.08": "0x2CD6",
        "LoD/1.09": "0x2CD6",
        "LoD/1.09b": "0x2CD6",
        "LoD/1.09d": "0x2CD6",
        "LoD/1.10": "0x2CD6",
        "LoD/1.11": "0x2CD6",
        "LoD/1.11b": "0x2CD6",
        "LoD/1.12a": "0x2CD6",
        "LoD/1.13c": "0x2CD6",
        "LoD/1.13d": "0x2CD6",
        "LoD/1.14a": "0x2CD6",
        "LoD/1.14b": "0x2CD6",
        "LoD/1.14c": "0x2CD6",
        "LoD/1.14d": "0x2CD6"
      },
      "sizes": {
        "LoD/1.07": 182,
        "LoD/1.08": 182,
        "LoD/1.09": 182,
        "LoD/1.09b": 182,
        "LoD/1.09d": 182,
        "LoD/1.10": 182,
        "LoD/1.11": 182,
        "LoD/1.11b": 182,
        "LoD/1.12a": 182,
        "LoD/1.13c": 182,
        "LoD/1.13d": 182,
        "LoD/1.14a": 182,
        "LoD/1.14b": 182,
        "LoD/1.14c": 182,
        "LoD/1.14d": 182
      },
      "return_type": "uint *",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:69f7deb725db18136e67b38972cf97de",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "69f7deb725db18136e67b38972cf97de",
        "CFG": "19728bdfad0380cab34bee784309c854",
        "PRO": "e953aaf38a96221b52d58979a1141175",
        "CAL": null,
        "CON": null,
        "APS": null
      },
      "display_name": "FUN_00402cd6",
      "callers": {
        "LoD/1.07": [
          "FUN_00401c00|0x401C00"
        ],
        "LoD/1.08": [
          "_strstr|0x401C00"
        ],
        "LoD/1.09": [
          "_strstr|0x401C00"
        ],
        "LoD/1.09b": [
          "_strstr|0x401C00"
        ],
        "LoD/1.09d": [
          "_strstr|0x401C00"
        ],
        "LoD/1.10": [
          "_strstr|0x401C00"
        ],
        "LoD/1.11": [
          "_strstr|0x401C00"
        ],
        "LoD/1.11b": [
          "_strstr|0x401C00"
        ],
        "LoD/1.12a": [
          "_strstr|0x401C00"
        ],
        "LoD/1.13c": [
          "_strstr|0x401C00"
        ],
        "LoD/1.13d": [
          "_strstr|0x401C00"
        ],
        "LoD/1.14a": [
          "_strstr|0x401C00"
        ],
        "LoD/1.14b": [
          "_strstr|0x401C00"
        ],
        "LoD/1.14c": [
          "_strstr|0x401C00"
        ],
        "LoD/1.14d": [
          "_strstr|0x401C00"
        ]
      },
      "instruction_counts": {
        "LoD/1.07": 84,
        "LoD/1.08": 84,
        "LoD/1.09": 84,
        "LoD/1.09b": 84,
        "LoD/1.09d": 84,
        "LoD/1.10": 84,
        "LoD/1.11": 84,
        "LoD/1.11b": 84,
        "LoD/1.12a": 84,
        "LoD/1.13c": 84,
        "LoD/1.13d": 84,
        "LoD/1.14a": 84,
        "LoD/1.14b": 84,
        "LoD/1.14c": 84,
        "LoD/1.14d": 84
      },
      "stack_frame_sizes": {
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
        "LoD/1.13d": 8,
        "LoD/1.14a": 8,
        "LoD/1.14b": 8,
        "LoD/1.14c": 8,
        "LoD/1.14d": 8
      },
      "basic_block_counts": {
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
        "LoD/1.13d": 24,
        "LoD/1.14a": 24,
        "LoD/1.14b": 24,
        "LoD/1.14c": 24,
        "LoD/1.14d": 24
      },
      "loop_counts": {
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
        "LoD/1.13d": 8,
        "LoD/1.14a": 8,
        "LoD/1.14b": 8,
        "LoD/1.14c": 8,
        "LoD/1.14d": 8
      },
      "mnemonic_hashes": {
        "LoD/1.07": "69f7deb725db18136e67b38972cf97de",
        "LoD/1.08": "69f7deb725db18136e67b38972cf97de",
        "LoD/1.09": "69f7deb725db18136e67b38972cf97de",
        "LoD/1.09b": "69f7deb725db18136e67b38972cf97de",
        "LoD/1.09d": "69f7deb725db18136e67b38972cf97de",
        "LoD/1.10": "69f7deb725db18136e67b38972cf97de",
        "LoD/1.11": "69f7deb725db18136e67b38972cf97de",
        "LoD/1.11b": "69f7deb725db18136e67b38972cf97de",
        "LoD/1.12a": "69f7deb725db18136e67b38972cf97de",
        "LoD/1.13c": "69f7deb725db18136e67b38972cf97de",
        "LoD/1.13d": "69f7deb725db18136e67b38972cf97de",
        "LoD/1.14a": "69f7deb725db18136e67b38972cf97de",
        "LoD/1.14b": "69f7deb725db18136e67b38972cf97de",
        "LoD/1.14c": "69f7deb725db18136e67b38972cf97de",
        "LoD/1.14d": "69f7deb725db18136e67b38972cf97de"
      },
      "constants": {
        "LoD/1.07": [
          16843008
        ],
        "LoD/1.08": [
          16843008
        ],
        "LoD/1.09": [
          16843008
        ],
        "LoD/1.09b": [
          16843008
        ],
        "LoD/1.09d": [
          16843008
        ],
        "LoD/1.10": [
          16843008
        ],
        "LoD/1.11": [
          16843008
        ],
        "LoD/1.11b": [
          16843008
        ],
        "LoD/1.12a": [
          16843008
        ],
        "LoD/1.13c": [
          16843008
        ],
        "LoD/1.13d": [
          16843008
        ],
        "LoD/1.14a": [
          16843008
        ],
        "LoD/1.14b": [
          16843008
        ],
        "LoD/1.14c": [
          16843008
        ],
        "LoD/1.14d": [
          16843008
        ]
      },
      "globals": {
        "LoD/1.07": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.08": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.09": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.09b": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.09d": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.10": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.11": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.11b": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.12a": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.13c": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.13d": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.14a": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.14b": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.14c": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.14d": [
          "0xFFFFFFFFFFC00004|"
        ]
      }
    },
    "diablo ii.exe_MNE_cd85d17a6b19": {
      "addresses": {
        "LoD/1.07": "0x00402D8C",
        "LoD/1.08": "0x00402D8C",
        "LoD/1.09": "0x00402D8C",
        "LoD/1.09b": "0x00402D8C",
        "LoD/1.09d": "0x00402D8C",
        "LoD/1.10": "0x00402D8C",
        "LoD/1.11": "0x00402D8C",
        "LoD/1.11b": "0x00402D8C",
        "LoD/1.12a": "0x00402D8C",
        "LoD/1.13c": "0x00402D8C",
        "LoD/1.13d": "0x00402D8C",
        "LoD/1.14a": "0x00402D8C",
        "LoD/1.14b": "0x00402D8C",
        "LoD/1.14c": "0x00402D8C",
        "LoD/1.14d": "0x00402D8C"
      },
      "rvas": {
        "LoD/1.07": "0x2D8C",
        "LoD/1.08": "0x2D8C",
        "LoD/1.09": "0x2D8C",
        "LoD/1.09b": "0x2D8C",
        "LoD/1.09d": "0x2D8C",
        "LoD/1.10": "0x2D8C",
        "LoD/1.11": "0x2D8C",
        "LoD/1.11b": "0x2D8C",
        "LoD/1.12a": "0x2D8C",
        "LoD/1.13c": "0x2D8C",
        "LoD/1.13d": "0x2D8C",
        "LoD/1.14a": "0x2D8C",
        "LoD/1.14b": "0x2D8C",
        "LoD/1.14c": "0x2D8C",
        "LoD/1.14d": "0x2D8C"
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
        "LoD/1.13d": 17,
        "LoD/1.14a": 17,
        "LoD/1.14b": 17,
        "LoD/1.14c": 17,
        "LoD/1.14d": 17
      },
      "return_type": "undefined",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:cd85d17a6b193c95680d3fdca645abba",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "cd85d17a6b193c95680d3fdca645abba",
        "CFG": "62e304a7d521240f86cfa75cc629cf4d",
        "PRO": "e067e555be462a2009cc84404e18b1ac",
        "CAL": null,
        "CON": null,
        "APS": null
      },
      "display_name": "FUN_00402d8c",
      "callees": {
        "LoD/1.07": [
          "FUN_00402d9d|0x402D9D"
        ],
        "LoD/1.08": [
          "FUN_00402d9d|0x402D9D"
        ],
        "LoD/1.09": [
          "FUN_00402d9d|0x402D9D"
        ],
        "LoD/1.09b": [
          "FUN_00402d9d|0x402D9D"
        ],
        "LoD/1.09d": [
          "FUN_00402d9d|0x402D9D"
        ],
        "LoD/1.10": [
          "FUN_00402d9d|0x402D9D"
        ],
        "LoD/1.11": [
          "FUN_00402d9d|0x402D9D"
        ],
        "LoD/1.11b": [
          "FUN_00402d9d|0x402D9D"
        ],
        "LoD/1.12a": [
          "FUN_00402d9d|0x402D9D"
        ],
        "LoD/1.13c": [
          "FUN_00402d9d|0x402D9D"
        ],
        "LoD/1.13d": [
          "FUN_00402d9d|0x402D9D"
        ],
        "LoD/1.14a": [
          "FUN_00402d9d|0x402D9D"
        ],
        "LoD/1.14b": [
          "FUN_00402d9d|0x402D9D"
        ],
        "LoD/1.14c": [
          "FUN_00402d9d|0x402D9D"
        ],
        "LoD/1.14d": [
          "FUN_00402d9d|0x402D9D"
        ]
      },
      "callers": {
        "LoD/1.07": [
          "FUN_00401f06|0x401F06"
        ],
        "LoD/1.08": [
          "FUN_00401f06|0x401F06"
        ],
        "LoD/1.09": [
          "FUN_00401f06|0x401F06"
        ],
        "LoD/1.09b": [
          "FUN_00401f06|0x401F06"
        ],
        "LoD/1.09d": [
          "FUN_00401f06|0x401F06"
        ],
        "LoD/1.10": [
          "FUN_00401f06|0x401F06"
        ],
        "LoD/1.11": [
          "FUN_00401f06|0x401F06"
        ],
        "LoD/1.11b": [
          "FUN_00401f06|0x401F06"
        ],
        "LoD/1.12a": [
          "FUN_00401f06|0x401F06"
        ],
        "LoD/1.13c": [
          "FUN_00401f06|0x401F06"
        ],
        "LoD/1.13d": [
          "FUN_00401f06|0x401F06"
        ],
        "LoD/1.14a": [
          "FUN_00401f06|0x401F06"
        ],
        "LoD/1.14b": [
          "FUN_00401f06|0x401F06"
        ],
        "LoD/1.14c": [
          "FUN_00401f06|0x401F06"
        ],
        "LoD/1.14d": [
          "FUN_00401f06|0x401F06"
        ]
      },
      "instruction_counts": {
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
        "LoD/1.13d": 6,
        "LoD/1.14a": 6,
        "LoD/1.14b": 6,
        "LoD/1.14c": 6,
        "LoD/1.14d": 6
      },
      "stack_frame_sizes": {
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
        "LoD/1.13d": 5,
        "LoD/1.14a": 5,
        "LoD/1.14b": 5,
        "LoD/1.14c": 5,
        "LoD/1.14d": 5
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
        "LoD/1.13d": 1,
        "LoD/1.14a": 1,
        "LoD/1.14b": 1,
        "LoD/1.14c": 1,
        "LoD/1.14d": 1
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
        "LoD/1.13d": 0,
        "LoD/1.14a": 0,
        "LoD/1.14b": 0,
        "LoD/1.14c": 0,
        "LoD/1.14d": 0
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
        "LoD/1.13d": "cd85d17a6b193c95680d3fdca645abba",
        "LoD/1.14a": "cd85d17a6b193c95680d3fdca645abba",
        "LoD/1.14b": "cd85d17a6b193c95680d3fdca645abba",
        "LoD/1.14c": "cd85d17a6b193c95680d3fdca645abba",
        "LoD/1.14d": "cd85d17a6b193c95680d3fdca645abba"
      },
      "globals": {
        "LoD/1.07": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.08": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.09": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.09b": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.09d": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.10": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.11": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.11b": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.12a": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.13c": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.13d": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.14a": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.14b": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.14c": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.14d": [
          "0xFFFFFFFFFFC00004|"
        ]
      }
    },
    "diablo ii.exe_CON_ab6177b600b4": {
      "addresses": {
        "LoD/1.07": "0x00402D9D",
        "LoD/1.08": "0x00402D9D",
        "LoD/1.09": "0x00402D9D",
        "LoD/1.09b": "0x00402D9D",
        "LoD/1.09d": "0x00402D9D",
        "LoD/1.10": "0x00402D9D",
        "LoD/1.11": "0x00402D9D",
        "LoD/1.11b": "0x00402D9D",
        "LoD/1.12a": "0x00402D9D",
        "LoD/1.13c": "0x00402D9D",
        "LoD/1.13d": "0x00402D9D",
        "LoD/1.14a": "0x00402D9D",
        "LoD/1.14b": "0x00402D9D",
        "LoD/1.14c": "0x00402D9D",
        "LoD/1.14d": "0x00402D9D"
      },
      "rvas": {
        "LoD/1.07": "0x2D9D",
        "LoD/1.08": "0x2D9D",
        "LoD/1.09": "0x2D9D",
        "LoD/1.09b": "0x2D9D",
        "LoD/1.09d": "0x2D9D",
        "LoD/1.10": "0x2D9D",
        "LoD/1.11": "0x2D9D",
        "LoD/1.11b": "0x2D9D",
        "LoD/1.12a": "0x2D9D",
        "LoD/1.13c": "0x2D9D",
        "LoD/1.13d": "0x2D9D",
        "LoD/1.14a": "0x2D9D",
        "LoD/1.14b": "0x2D9D",
        "LoD/1.14c": "0x2D9D",
        "LoD/1.14d": "0x2D9D"
      },
      "sizes": {
        "LoD/1.07": 49,
        "LoD/1.08": 49,
        "LoD/1.09": 49,
        "LoD/1.09b": 49,
        "LoD/1.09d": 49,
        "LoD/1.10": 49,
        "LoD/1.11": 49,
        "LoD/1.11b": 49,
        "LoD/1.12a": 49,
        "LoD/1.13c": 49,
        "LoD/1.13d": 49,
        "LoD/1.14a": 49,
        "LoD/1.14b": 49,
        "LoD/1.14c": 49,
        "LoD/1.14d": 49
      },
      "return_type": "undefined4",
      "name_source": "LoD/1.07",
      "method": "CON",
      "index": "CON:ab6177b600b40e04648bdcec182c8d4b",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "53a6ac985e66444c6c82f2b7b12d7c09",
        "CFG": "85d43acaaf4da912180ee68ae75e1834",
        "PRO": "eb79751ac250076fbd4621ac20b498cb",
        "CAL": null,
        "CON": "ab6177b600b40e04648bdcec182c8d4b",
        "APS": null
      },
      "display_name": "FUN_00402d9d",
      "callers": {
        "LoD/1.07": [
          "FUN_00402d8c|0x402D8C"
        ],
        "LoD/1.08": [
          "FUN_00402d8c|0x402D8C"
        ],
        "LoD/1.09": [
          "FUN_00402d8c|0x402D8C"
        ],
        "LoD/1.09b": [
          "FUN_00402d8c|0x402D8C"
        ],
        "LoD/1.09d": [
          "FUN_00402d8c|0x402D8C"
        ],
        "LoD/1.10": [
          "FUN_00402d8c|0x402D8C"
        ],
        "LoD/1.11": [
          "FUN_00402d8c|0x402D8C"
        ],
        "LoD/1.11b": [
          "FUN_00402d8c|0x402D8C"
        ],
        "LoD/1.12a": [
          "FUN_00402d8c|0x402D8C"
        ],
        "LoD/1.13c": [
          "FUN_00402d8c|0x402D8C"
        ],
        "LoD/1.13d": [
          "FUN_00402d8c|0x402D8C"
        ],
        "LoD/1.14a": [
          "FUN_00402d8c|0x402D8C"
        ],
        "LoD/1.14b": [
          "FUN_00402d8c|0x402D8C"
        ],
        "LoD/1.14c": [
          "FUN_00402d8c|0x402D8C"
        ],
        "LoD/1.14d": [
          "FUN_00402d8c|0x402D8C"
        ]
      },
      "instruction_counts": {
        "LoD/1.07": 16,
        "LoD/1.08": 16,
        "LoD/1.09": 16,
        "LoD/1.09b": 16,
        "LoD/1.09d": 16,
        "LoD/1.10": 16,
        "LoD/1.11": 16,
        "LoD/1.11b": 16,
        "LoD/1.12a": 16,
        "LoD/1.13c": 16,
        "LoD/1.13d": 16,
        "LoD/1.14a": 16,
        "LoD/1.14b": 16,
        "LoD/1.14c": 16,
        "LoD/1.14d": 16
      },
      "stack_frame_sizes": {
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
        "LoD/1.13d": 13,
        "LoD/1.14a": 13,
        "LoD/1.14b": 13,
        "LoD/1.14c": 13,
        "LoD/1.14d": 13
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
        "LoD/1.13d": 7,
        "LoD/1.14a": 7,
        "LoD/1.14b": 7,
        "LoD/1.14c": 7,
        "LoD/1.14d": 7
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
        "LoD/1.13d": 0,
        "LoD/1.14a": 0,
        "LoD/1.14b": 0,
        "LoD/1.14c": 0,
        "LoD/1.14d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "53a6ac985e66444c6c82f2b7b12d7c09",
        "LoD/1.08": "53a6ac985e66444c6c82f2b7b12d7c09",
        "LoD/1.09": "53a6ac985e66444c6c82f2b7b12d7c09",
        "LoD/1.09b": "53a6ac985e66444c6c82f2b7b12d7c09",
        "LoD/1.09d": "53a6ac985e66444c6c82f2b7b12d7c09",
        "LoD/1.10": "53a6ac985e66444c6c82f2b7b12d7c09",
        "LoD/1.11": "53a6ac985e66444c6c82f2b7b12d7c09",
        "LoD/1.11b": "53a6ac985e66444c6c82f2b7b12d7c09",
        "LoD/1.12a": "53a6ac985e66444c6c82f2b7b12d7c09",
        "LoD/1.13c": "53a6ac985e66444c6c82f2b7b12d7c09",
        "LoD/1.13d": "53a6ac985e66444c6c82f2b7b12d7c09",
        "LoD/1.14a": "53a6ac985e66444c6c82f2b7b12d7c09",
        "LoD/1.14b": "53a6ac985e66444c6c82f2b7b12d7c09",
        "LoD/1.14c": "53a6ac985e66444c6c82f2b7b12d7c09",
        "LoD/1.14d": "53a6ac985e66444c6c82f2b7b12d7c09"
      },
      "constants": {
        "LoD/1.07": [
          4219562,
          4221121
        ],
        "LoD/1.08": [
          4219562,
          4221121
        ],
        "LoD/1.09": [
          4219562,
          4221121
        ],
        "LoD/1.09b": [
          4219562,
          4221121
        ],
        "LoD/1.09d": [
          4219562,
          4221121
        ],
        "LoD/1.10": [
          4219562,
          4221121
        ],
        "LoD/1.11": [
          4219562,
          4221121
        ],
        "LoD/1.11b": [
          4219562,
          4221121
        ],
        "LoD/1.12a": [
          4219562,
          4221121
        ],
        "LoD/1.13c": [
          4219562,
          4221121
        ],
        "LoD/1.13d": [
          4219562,
          4221121
        ],
        "LoD/1.14a": [
          4219562,
          4221121
        ],
        "LoD/1.14b": [
          4219562,
          4221121
        ],
        "LoD/1.14c": [
          4219562,
          4221121
        ],
        "LoD/1.14d": [
          4219562,
          4221121
        ]
      },
      "globals": {
        "LoD/1.07": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC0000C|",
          "0x68C1|DAT_004068c0+1",
          "0xFFFFFFFFFFC00008|",
          "0x62AA|DAT_004062aa"
        ],
        "LoD/1.08": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC0000C|",
          "0x68C1|DAT_004068c0+1",
          "0xFFFFFFFFFFC00008|",
          "0x62AA|DAT_004062aa"
        ],
        "LoD/1.09": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC0000C|",
          "0x68C1|DAT_004068c0+1",
          "0xFFFFFFFFFFC00008|",
          "0x62AA|DAT_004062aa"
        ],
        "LoD/1.09b": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC0000C|",
          "0x68C1|DAT_004068c0+1",
          "0xFFFFFFFFFFC00008|",
          "0x62AA|DAT_004062aa"
        ],
        "LoD/1.09d": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC0000C|",
          "0x68C1|DAT_004068c0+1",
          "0xFFFFFFFFFFC00008|",
          "0x62AA|DAT_004062aa"
        ],
        "LoD/1.10": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC0000C|",
          "0x68C1|DAT_004068c0+1",
          "0xFFFFFFFFFFC00008|",
          "0x62AA|DAT_004062aa"
        ],
        "LoD/1.11": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC0000C|",
          "0x68C1|DAT_004068c0+1",
          "0xFFFFFFFFFFC00008|",
          "0x62AA|DAT_004062aa"
        ],
        "LoD/1.11b": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC0000C|",
          "0x68C1|DAT_004068c0+1",
          "0xFFFFFFFFFFC00008|",
          "0x62AA|DAT_004062aa"
        ],
        "LoD/1.12a": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC0000C|",
          "0x68C1|DAT_004068c0+1",
          "0xFFFFFFFFFFC00008|",
          "0x62AA|DAT_004062aa"
        ],
        "LoD/1.13c": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC0000C|",
          "0x68C1|DAT_004068c0+1",
          "0xFFFFFFFFFFC00008|",
          "0x62AA|DAT_004062aa"
        ],
        "LoD/1.13d": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC0000C|",
          "0x68C1|DAT_004068c0+1",
          "0xFFFFFFFFFFC00008|",
          "0x62AA|DAT_004062aa"
        ],
        "LoD/1.14a": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC0000C|",
          "0x68C1|DAT_004068c0+1",
          "0xFFFFFFFFFFC00008|",
          "0x62AA|DAT_004062aa"
        ],
        "LoD/1.14b": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC0000C|",
          "0x68C1|DAT_004068c0+1",
          "0xFFFFFFFFFFC00008|",
          "0x62AA|DAT_004062aa"
        ],
        "LoD/1.14c": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC0000C|",
          "0x68C1|DAT_004068c0+1",
          "0xFFFFFFFFFFC00008|",
          "0x62AA|DAT_004062aa"
        ],
        "LoD/1.14d": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC0000C|",
          "0x68C1|DAT_004068c0+1",
          "0xFFFFFFFFFFC00008|",
          "0x62AA|DAT_004062aa"
        ]
      }
    },
    "diablo ii.exe_SmartFree": {
      "addresses": {
        "LoD/1.07": "0x00402DCE",
        "LoD/1.08": "0x00402DCE",
        "LoD/1.09": "0x00402DCE",
        "LoD/1.09b": "0x00402DCE",
        "LoD/1.09d": "0x00402DCE",
        "LoD/1.10": "0x00402DCE",
        "LoD/1.11": "0x00402DCE",
        "LoD/1.11b": "0x00402DCE",
        "LoD/1.12a": "0x00402DCE",
        "LoD/1.13c": "0x00402DCE",
        "LoD/1.13d": "0x00402DCE",
        "LoD/1.14a": "0x00402DCE",
        "LoD/1.14b": "0x00402DCE",
        "LoD/1.14c": "0x00402DCE",
        "LoD/1.14d": "0x00402DCE"
      },
      "rvas": {
        "LoD/1.07": "0x2DCE",
        "LoD/1.08": "0x2DCE",
        "LoD/1.09": "0x2DCE",
        "LoD/1.09b": "0x2DCE",
        "LoD/1.09d": "0x2DCE",
        "LoD/1.10": "0x2DCE",
        "LoD/1.11": "0x2DCE",
        "LoD/1.11b": "0x2DCE",
        "LoD/1.12a": "0x2DCE",
        "LoD/1.13c": "0x2DCE",
        "LoD/1.13d": "0x2DCE",
        "LoD/1.14a": "0x2DCE",
        "LoD/1.14b": "0x2DCE",
        "LoD/1.14c": "0x2DCE",
        "LoD/1.14d": "0x2DCE"
      },
      "sizes": {
        "LoD/1.07": 47,
        "LoD/1.08": 47,
        "LoD/1.09": 47,
        "LoD/1.09b": 47,
        "LoD/1.09d": 47,
        "LoD/1.10": 47,
        "LoD/1.11": 47,
        "LoD/1.11b": 47,
        "LoD/1.12a": 47,
        "LoD/1.13c": 47,
        "LoD/1.13d": 47,
        "LoD/1.14a": 47,
        "LoD/1.14b": 47,
        "LoD/1.14c": 47,
        "LoD/1.14d": 47
      },
      "name": "SmartFree",
      "signature": "void SmartFree(void * pMemory)",
      "calling_convention": "__cdecl",
      "return_type": "void",
      "comment": "Smart memory deallocation function with managed pool fallback to system heap\n\nAlgorithm:\n1. Check if memory pointer is not null (early return if null)\n2. Call FUN_1001d50f to get control block for managed memory allocation\n3. If control block exists, call FUN_1001d53a for managed deallocation\n4. If no control block found, fallback to system HeapFree with global heap handle\n5. Return without value (void function)\n\nParameters:\n  pMemory - void* pointer to memory block to deallocate (may be null)\n\nReturns:\n  void (no return value)\n\nSpecial Cases:\n  - Null pointer: function returns immediately without action\n  - Memory not in managed pool: falls back to HeapFree\n  - Uses global heap handle g_hHeap for system memory deallocation\n\nError Handling:\n  - Graceful handling of null pointer input\n  - Fallback mechanism when managed deallocation unavailable\n  - No explicit error return codes (void function)",
      "name_source": "LoD/1.07",
      "method": "CAL",
      "index": "CAL:9ae59e844b8d8f6c7c24b4318d75d4a0",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "b18de4e8dfaa1ea94be3de3b62f2adf9",
        "CFG": "4521ae963f7f2fd59b191cef99ff20c1",
        "PRO": "21841d7cd76f33fea673861ccbc8c236",
        "CAL": "9ae59e844b8d8f6c7c24b4318d75d4a0",
        "CON": null,
        "APS": null
      },
      "callees": {
        "LoD/1.07": [
          "HeapFree|0x20",
          "FindMemoryDescriptorByAddress|0x4032E3",
          "FreeMemoryBlockWithLinkedListCleanup|0x40330E"
        ],
        "LoD/1.08": [
          "HeapFree|0x20",
          "FindMemoryDescriptorByAddress|0x4032E3",
          "FreeMemoryBlockWithLinkedListCleanup|0x40330E"
        ],
        "LoD/1.09": [
          "FindMemoryDescriptorByAddress|0x4032E3",
          "FreeMemoryBlockWithLinkedListCleanup|0x40330E",
          "HeapFree|0x20"
        ],
        "LoD/1.09b": [
          "FreeMemoryBlockWithLinkedListCleanup|0x40330E",
          "FindMemoryDescriptorByAddress|0x4032E3",
          "HeapFree|0x20"
        ],
        "LoD/1.09d": [
          "FindMemoryDescriptorByAddress|0x4032E3",
          "HeapFree|0x20",
          "FreeMemoryBlockWithLinkedListCleanup|0x40330E"
        ],
        "LoD/1.10": [
          "FreeMemoryBlockWithLinkedListCleanup|0x40330E",
          "HeapFree|0x20",
          "FindMemoryDescriptorByAddress|0x4032E3"
        ],
        "LoD/1.11": [
          "HeapFree|0x20",
          "FindMemoryDescriptorByAddress|0x4032E3",
          "FreeMemoryBlockWithLinkedListCleanup|0x40330E"
        ],
        "LoD/1.11b": [
          "HeapFree|0x20",
          "FindMemoryDescriptorByAddress|0x4032E3",
          "FreeMemoryBlockWithLinkedListCleanup|0x40330E"
        ],
        "LoD/1.12a": [
          "FreeMemoryBlockWithLinkedListCleanup|0x40330E",
          "HeapFree|0x20",
          "FindMemoryDescriptorByAddress|0x4032E3"
        ],
        "LoD/1.13c": [
          "HeapFree|0x20",
          "FreeMemoryBlockWithLinkedListCleanup|0x40330E",
          "FindMemoryDescriptorByAddress|0x4032E3"
        ],
        "LoD/1.13d": [
          "HeapFree|0x20",
          "FindMemoryDescriptorByAddress|0x4032E3",
          "FreeMemoryBlockWithLinkedListCleanup|0x40330E"
        ],
        "LoD/1.14a": [
          "FindMemoryDescriptorByAddress|0x4032E3",
          "HeapFree|0x20",
          "FreeMemoryBlockWithLinkedListCleanup|0x40330E"
        ],
        "LoD/1.14b": [
          "FindMemoryDescriptorByAddress|0x4032E3",
          "HeapFree|0x20",
          "FreeMemoryBlockWithLinkedListCleanup|0x40330E"
        ],
        "LoD/1.14c": [
          "FindMemoryDescriptorByAddress|0x4032E3",
          "FreeMemoryBlockWithLinkedListCleanup|0x40330E",
          "HeapFree|0x20"
        ],
        "LoD/1.14d": [
          "FindMemoryDescriptorByAddress|0x4032E3",
          "HeapFree|0x20",
          "FreeMemoryBlockWithLinkedListCleanup|0x40330E"
        ]
      },
      "callers": {
        "LoD/1.07": [
          "InitializeEnvironmentVariables|0x401F5E",
          "GetEnvironmentStringsConverted|0x402264"
        ],
        "LoD/1.08": [
          "InitializeEnvironmentVariables|0x401F5E",
          "GetEnvironmentStringsConverted|0x402264"
        ],
        "LoD/1.09": [
          "InitializeEnvironmentVariables|0x401F5E",
          "GetEnvironmentStringsConverted|0x402264"
        ],
        "LoD/1.09b": [
          "GetEnvironmentStringsConverted|0x402264",
          "InitializeEnvironmentVariables|0x401F5E"
        ],
        "LoD/1.09d": [
          "InitializeEnvironmentVariables|0x401F5E",
          "GetEnvironmentStringsConverted|0x402264"
        ],
        "LoD/1.10": [
          "InitializeEnvironmentVariables|0x401F5E",
          "GetEnvironmentStringsConverted|0x402264"
        ],
        "LoD/1.11": [
          "InitializeEnvironmentVariables|0x401F5E",
          "GetEnvironmentStringsConverted|0x402264"
        ],
        "LoD/1.11b": [
          "GetEnvironmentStringsConverted|0x402264",
          "InitializeEnvironmentVariables|0x401F5E"
        ],
        "LoD/1.12a": [
          "InitializeEnvironmentVariables|0x401F5E",
          "GetEnvironmentStringsConverted|0x402264"
        ],
        "LoD/1.13c": [
          "GetEnvironmentStringsConverted|0x402264",
          "InitializeEnvironmentVariables|0x401F5E"
        ],
        "LoD/1.13d": [
          "InitializeEnvironmentVariables|0x401F5E",
          "GetEnvironmentStringsConverted|0x402264"
        ],
        "LoD/1.14a": [
          "GetEnvironmentStringsConverted|0x402264",
          "InitializeEnvironmentVariables|0x401F5E"
        ],
        "LoD/1.14b": [
          "InitializeEnvironmentVariables|0x401F5E",
          "GetEnvironmentStringsConverted|0x402264"
        ],
        "LoD/1.14c": [
          "GetEnvironmentStringsConverted|0x402264",
          "InitializeEnvironmentVariables|0x401F5E"
        ],
        "LoD/1.14d": [
          "GetEnvironmentStringsConverted|0x402264",
          "InitializeEnvironmentVariables|0x401F5E"
        ]
      },
      "instruction_counts": {
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
        "LoD/1.13d": 21,
        "LoD/1.14a": 21,
        "LoD/1.14b": 21,
        "LoD/1.14c": 21,
        "LoD/1.14d": 21
      },
      "stack_frame_sizes": {
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
        "LoD/1.13d": 8,
        "LoD/1.14a": 8,
        "LoD/1.14b": 8,
        "LoD/1.14c": 8,
        "LoD/1.14d": 8
      },
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
        "LoD/1.13d": 5,
        "LoD/1.14a": 5,
        "LoD/1.14b": 5,
        "LoD/1.14c": 5,
        "LoD/1.14d": 5
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
        "LoD/1.13d": 0,
        "LoD/1.14a": 0,
        "LoD/1.14b": 0,
        "LoD/1.14c": 0,
        "LoD/1.14d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "b18de4e8dfaa1ea94be3de3b62f2adf9",
        "LoD/1.08": "b18de4e8dfaa1ea94be3de3b62f2adf9",
        "LoD/1.09": "b18de4e8dfaa1ea94be3de3b62f2adf9",
        "LoD/1.09b": "b18de4e8dfaa1ea94be3de3b62f2adf9",
        "LoD/1.09d": "b18de4e8dfaa1ea94be3de3b62f2adf9",
        "LoD/1.10": "b18de4e8dfaa1ea94be3de3b62f2adf9",
        "LoD/1.11": "b18de4e8dfaa1ea94be3de3b62f2adf9",
        "LoD/1.11b": "b18de4e8dfaa1ea94be3de3b62f2adf9",
        "LoD/1.12a": "b18de4e8dfaa1ea94be3de3b62f2adf9",
        "LoD/1.13c": "b18de4e8dfaa1ea94be3de3b62f2adf9",
        "LoD/1.13d": "b18de4e8dfaa1ea94be3de3b62f2adf9",
        "LoD/1.14a": "b18de4e8dfaa1ea94be3de3b62f2adf9",
        "LoD/1.14b": "b18de4e8dfaa1ea94be3de3b62f2adf9",
        "LoD/1.14c": "b18de4e8dfaa1ea94be3de3b62f2adf9",
        "LoD/1.14d": "b18de4e8dfaa1ea94be3de3b62f2adf9"
      },
      "globals": {
        "LoD/1.07": [
          "0xFFFFFFFFFFC00004|",
          "0x6674|g_hHeapHandle",
          "0x507C|PTR_HeapFree_0040507c"
        ],
        "LoD/1.08": [
          "0xFFFFFFFFFFC00004|",
          "0x6674|g_hHeapHandle",
          "0x507C|PTR_HeapFree_0040507c"
        ],
        "LoD/1.09": [
          "0xFFFFFFFFFFC00004|",
          "0x6674|g_hHeapHandle",
          "0x507C|PTR_HeapFree_0040507c"
        ],
        "LoD/1.09b": [
          "0xFFFFFFFFFFC00004|",
          "0x6674|g_hHeapHandle",
          "0x507C|PTR_HeapFree_0040507c"
        ],
        "LoD/1.09d": [
          "0xFFFFFFFFFFC00004|",
          "0x6674|g_hHeapHandle",
          "0x507C|PTR_HeapFree_0040507c"
        ],
        "LoD/1.10": [
          "0xFFFFFFFFFFC00004|",
          "0x6674|g_hHeap",
          "0x507C|PTR_HeapFree_0040507c"
        ],
        "LoD/1.11": [
          "0xFFFFFFFFFFC00004|",
          "0x6674|g_hHeapHandle",
          "0x507C|PTR_HeapFree_0040507c"
        ],
        "LoD/1.11b": [
          "0xFFFFFFFFFFC00004|",
          "0x6674|g_hHeapHandle",
          "0x507C|PTR_HeapFree_0040507c"
        ],
        "LoD/1.12a": [
          "0xFFFFFFFFFFC00004|",
          "0x6674|g_hHeapHandle",
          "0x507C|PTR_HeapFree_0040507c"
        ],
        "LoD/1.13c": [
          "0xFFFFFFFFFFC00004|",
          "0x6674|g_hHeapHandle",
          "0x507C|PTR_HeapFree_0040507c"
        ],
        "LoD/1.13d": [
          "0xFFFFFFFFFFC00004|",
          "0x6674|g_hHeapHandle",
          "0x507C|PTR_HeapFree_0040507c"
        ],
        "LoD/1.14a": [
          "0xFFFFFFFFFFC00004|",
          "0x6674|g_hHeapHandle",
          "0x507C|PTR_HeapFree_0040507c"
        ],
        "LoD/1.14b": [
          "0xFFFFFFFFFFC00004|",
          "0x6674|g_hHeapHandle",
          "0x507C|PTR_HeapFree_0040507c"
        ],
        "LoD/1.14c": [
          "0xFFFFFFFFFFC00004|",
          "0x6674|g_hHeapHandle",
          "0x507C|PTR_HeapFree_0040507c"
        ],
        "LoD/1.14d": [
          "0xFFFFFFFFFFC00004|",
          "0x6674|g_hHeapHandle",
          "0x507C|PTR_HeapFree_0040507c"
        ]
      }
    },
    "diablo ii.exe_CopyStringOptimized": {
      "addresses": {
        "LoD/1.07": "0x00402E00",
        "LoD/1.08": "0x00402E00",
        "LoD/1.09": "0x00402E00",
        "LoD/1.09b": "0x00402E00",
        "LoD/1.09d": "0x00402E00",
        "LoD/1.10": "0x00402E00",
        "LoD/1.11": "0x00402E00",
        "LoD/1.11b": "0x00402E00",
        "LoD/1.12a": "0x00402E00",
        "LoD/1.13c": "0x00402E00",
        "LoD/1.13d": "0x00402E00",
        "LoD/1.14a": "0x00402E00",
        "LoD/1.14b": "0x00402E00",
        "LoD/1.14c": "0x00402E00",
        "LoD/1.14d": "0x00402E00"
      },
      "rvas": {
        "LoD/1.07": "0x2E00",
        "LoD/1.08": "0x2E00",
        "LoD/1.09": "0x2E00",
        "LoD/1.09b": "0x2E00",
        "LoD/1.09d": "0x2E00",
        "LoD/1.10": "0x2E00",
        "LoD/1.11": "0x2E00",
        "LoD/1.11b": "0x2E00",
        "LoD/1.12a": "0x2E00",
        "LoD/1.13c": "0x2E00",
        "LoD/1.13d": "0x2E00",
        "LoD/1.14a": "0x2E00",
        "LoD/1.14b": "0x2E00",
        "LoD/1.14c": "0x2E00",
        "LoD/1.14d": "0x2E00"
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
        "LoD/1.13d": 7,
        "LoD/1.14a": 7,
        "LoD/1.14b": 7,
        "LoD/1.14c": 7,
        "LoD/1.14d": 7
      },
      "name": "CopyStringOptimized",
      "signature": "char * CopyStringOptimized(char * szDestination, char * szSource)",
      "calling_convention": "__cdecl",
      "return_type": "char *",
      "comment": "Optimized string copy function that efficiently copies null-terminated strings\nusing word-aligned memory operations and bitwise null detection for maximum\nperformance on x86 architecture.\n\nAlgorithm:\n1. Check source pointer alignment against 4-byte boundary (szSource & 3)\n2. Copy bytes individually until source reaches word alignment\n3. Check each copied byte for null terminator, exit early if found\n4. Begin optimized word-level copying once aligned\n5. Load 32-bit words from source and apply null detection algorithm\n6. Use magic constant 0x7efefeff to detect null bytes within words\n7. When null detected, determine exact byte position using bit masks\n8. Copy final bytes and null terminator based on detected position\n9. Return original destination pointer\n\nParameters:\nszDestination (char*): Destination buffer where string will be copied\nszSource (char*): Source null-terminated string to copy\n\nReturns:\nchar*: Returns szDestination (original destination buffer address)\n\nSpecial Cases:\nEmpty string (first byte is null) handled correctly by early exit\nSource and destination buffers must not overlap (undefined behavior)\nDestination buffer must be large enough to hold entire source string\n\nMagic Numbers:\n0x7efefeff: Magic constant for fast null byte detection in 32-bit words\n0x81010100: Bit mask for isolating overflow bits from null detection\n0xffffffff: XOR mask component of null detection algorithm  \n0x3: Bit mask for checking 4-byte memory alignment",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:70593f43ea0b0d7692df2cd60ddf29e8",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "70593f43ea0b0d7692df2cd60ddf29e8",
        "CFG": "4e3b3947cf15c11224705052794a4b4e",
        "PRO": "0893ef4135ff92704b4a57726c2e8b67",
        "CAL": null,
        "CON": null,
        "APS": null
      },
      "callers": {
        "LoD/1.07": [
          "DisplayRuntimeError|0x402789",
          "InitializeEnvironmentVariables|0x401F5E"
        ],
        "LoD/1.08": [
          "InitializeEnvironmentVariables|0x401F5E",
          "DisplayRuntimeError|0x402789"
        ],
        "LoD/1.09": [
          "InitializeEnvironmentVariables|0x401F5E",
          "DisplayRuntimeError|0x402789"
        ],
        "LoD/1.09b": [
          "DisplayRuntimeError|0x402789",
          "InitializeEnvironmentVariables|0x401F5E"
        ],
        "LoD/1.09d": [
          "InitializeEnvironmentVariables|0x401F5E",
          "DisplayRuntimeError|0x402789"
        ],
        "LoD/1.10": [
          "InitializeEnvironmentVariables|0x401F5E",
          "DisplayRuntimeError|0x402789"
        ],
        "LoD/1.11": [
          "InitializeEnvironmentVariables|0x401F5E",
          "DisplayRuntimeError|0x402789"
        ],
        "LoD/1.11b": [
          "InitializeEnvironmentVariables|0x401F5E",
          "DisplayRuntimeError|0x402789"
        ],
        "LoD/1.12a": [
          "InitializeEnvironmentVariables|0x401F5E",
          "DisplayRuntimeError|0x402789"
        ],
        "LoD/1.13c": [
          "InitializeEnvironmentVariables|0x401F5E",
          "DisplayRuntimeError|0x402789"
        ],
        "LoD/1.13d": [
          "DisplayRuntimeError|0x402789",
          "InitializeEnvironmentVariables|0x401F5E"
        ],
        "LoD/1.14a": [
          "DisplayRuntimeError|0x402789",
          "InitializeEnvironmentVariables|0x401F5E"
        ],
        "LoD/1.14b": [
          "InitializeEnvironmentVariables|0x401F5E",
          "DisplayRuntimeError|0x402789"
        ],
        "LoD/1.14c": [
          "DisplayRuntimeError|0x402789",
          "InitializeEnvironmentVariables|0x401F5E"
        ],
        "LoD/1.14d": [
          "DisplayRuntimeError|0x402789",
          "InitializeEnvironmentVariables|0x401F5E"
        ]
      },
      "instruction_counts": {
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
        "LoD/1.13d": 3,
        "LoD/1.14a": 3,
        "LoD/1.14b": 3,
        "LoD/1.14c": 3,
        "LoD/1.14d": 3
      },
      "stack_frame_sizes": {
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
        "LoD/1.13d": 12,
        "LoD/1.14a": 12,
        "LoD/1.14b": 12,
        "LoD/1.14c": 12,
        "LoD/1.14d": 12
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
        "LoD/1.13d": 1,
        "LoD/1.14a": 1,
        "LoD/1.14b": 1,
        "LoD/1.14c": 1,
        "LoD/1.14d": 1
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
        "LoD/1.13d": 0,
        "LoD/1.14a": 0,
        "LoD/1.14b": 0,
        "LoD/1.14c": 0,
        "LoD/1.14d": 0
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
        "LoD/1.13d": "70593f43ea0b0d7692df2cd60ddf29e8",
        "LoD/1.14a": "70593f43ea0b0d7692df2cd60ddf29e8",
        "LoD/1.14b": "70593f43ea0b0d7692df2cd60ddf29e8",
        "LoD/1.14c": "70593f43ea0b0d7692df2cd60ddf29e8",
        "LoD/1.14d": "70593f43ea0b0d7692df2cd60ddf29e8"
      },
      "globals": {
        "LoD/1.07": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.08": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.09": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.09b": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.09d": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.10": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.11": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.11b": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.12a": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.13c": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.13d": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.14a": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.14b": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.14c": [
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.14d": [
          "0xFFFFFFFFFFC00004|"
        ]
      }
    },
    "diablo ii.exe_OptimizedStringCopy": {
      "addresses": {
        "LoD/1.07": "0x00402E10",
        "LoD/1.08": "0x00402E10",
        "LoD/1.09": "0x00402E10",
        "LoD/1.09b": "0x00402E10",
        "LoD/1.09d": "0x00402E10",
        "LoD/1.10": "0x00402E10",
        "LoD/1.11": "0x00402E10",
        "LoD/1.11b": "0x00402E10",
        "LoD/1.12a": "0x00402E10",
        "LoD/1.13c": "0x00402E10",
        "LoD/1.13d": "0x00402E10",
        "LoD/1.14a": "0x00402E10",
        "LoD/1.14b": "0x00402E10",
        "LoD/1.14c": "0x00402E10",
        "LoD/1.14d": "0x00402E10"
      },
      "rvas": {
        "LoD/1.07": "0x2E10",
        "LoD/1.08": "0x2E10",
        "LoD/1.09": "0x2E10",
        "LoD/1.09b": "0x2E10",
        "LoD/1.09d": "0x2E10",
        "LoD/1.10": "0x2E10",
        "LoD/1.11": "0x2E10",
        "LoD/1.11b": "0x2E10",
        "LoD/1.12a": "0x2E10",
        "LoD/1.13c": "0x2E10",
        "LoD/1.13d": "0x2E10",
        "LoD/1.14a": "0x2E10",
        "LoD/1.14b": "0x2E10",
        "LoD/1.14c": "0x2E10",
        "LoD/1.14d": "0x2E10"
      },
      "sizes": {
        "LoD/1.07": 224,
        "LoD/1.08": 224,
        "LoD/1.09": 224,
        "LoD/1.09b": 224,
        "LoD/1.09d": 224,
        "LoD/1.10": 224,
        "LoD/1.11": 224,
        "LoD/1.11b": 224,
        "LoD/1.12a": 224,
        "LoD/1.13c": 224,
        "LoD/1.13d": 224,
        "LoD/1.14a": 224,
        "LoD/1.14b": 224,
        "LoD/1.14c": 224,
        "LoD/1.14d": 224
      },
      "name": "OptimizedStringCopy",
      "signature": "char * OptimizedStringCopy(char * lpszDestination, char * lpszSource)",
      "calling_convention": "__cdecl",
      "return_type": "char *",
      "comment": "Performs optimized string copying using word-aligned memory access and null-byte detection.\nThis function implements a high-performance strcpy equivalent using x86 alignment optimization.\nUses magic constants to detect null terminators within 32-bit words for maximum throughput.\nHandles both aligned and unaligned source/destination buffers gracefully.\n\nAlgorithm:\n1. Check destination pointer alignment against 4-byte word boundary\n2. Copy unaligned bytes one-by-one until destination reaches word alignment  \n3. Enter optimized loop processing 4-byte words from aligned destination\n4. Apply magic constant 0x7EFEFEFF to detect null bytes within words\n5. Use mask 0x81010100 to isolate carry bits indicating null presence\n6. When null detected in word, determine exact byte position and handle\n7. Switch to source processing with similar alignment optimization\n8. Copy source bytes individually until source is word-aligned\n9. Process aligned source words until null terminator found\n10. Terminate destination string with null and return original pointer\n\nParameters:\nlpszDestination - Pointer to destination buffer with sufficient space allocated\nlpcszSource - Pointer to source null-terminated string to be copied\n\nReturns:\nReturns lpszDestination pointer for function chaining operations\n\nMagic Numbers Reference:\n0x7EFEFEFF (2130640639) - Magic additive constant for null detection algorithm\n0x81010100 (2164391168) - Bit mask to isolate null detection carry flags  \n0x3 (3) - Alignment mask for checking 4-byte word boundaries\n0xFF0000 (16711680) - Third byte mask for null position detection\n0xFF000000 (4278190080) - Fourth byte mask for null position detection\n\nSpecial Cases:\nEmpty source string copies only null terminator to destination\nOverlapping memory regions produce undefined behavior per C standard\nDestination buffer must accommodate source length plus null terminator\nAlgorithm assumes little-endian x86 architecture for bit manipulation",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:845fc5044ff181fe96e2ae868d3aa1f6",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "845fc5044ff181fe96e2ae868d3aa1f6",
        "CFG": "a96a897a6b801f6ddf1257ad0becd475",
        "PRO": "91a93f07a9ad6d3f1f33172e65653a41",
        "CAL": null,
        "CON": null,
        "APS": null
      },
      "callers": {
        "LoD/1.07": [
          "DisplayRuntimeError|0x402789"
        ],
        "LoD/1.08": [
          "DisplayRuntimeError|0x402789"
        ],
        "LoD/1.09": [
          "DisplayRuntimeError|0x402789"
        ],
        "LoD/1.09b": [
          "DisplayRuntimeError|0x402789"
        ],
        "LoD/1.09d": [
          "DisplayRuntimeError|0x402789"
        ],
        "LoD/1.10": [
          "DisplayRuntimeError|0x402789"
        ],
        "LoD/1.11": [
          "DisplayRuntimeError|0x402789"
        ],
        "LoD/1.11b": [
          "DisplayRuntimeError|0x402789"
        ],
        "LoD/1.12a": [
          "DisplayRuntimeError|0x402789"
        ],
        "LoD/1.13c": [
          "DisplayRuntimeError|0x402789"
        ],
        "LoD/1.13d": [
          "DisplayRuntimeError|0x402789"
        ],
        "LoD/1.14a": [
          "DisplayRuntimeError|0x402789"
        ],
        "LoD/1.14b": [
          "DisplayRuntimeError|0x402789"
        ],
        "LoD/1.14c": [
          "DisplayRuntimeError|0x402789"
        ],
        "LoD/1.14d": [
          "DisplayRuntimeError|0x402789"
        ]
      },
      "instruction_counts": {
        "LoD/1.07": 84,
        "LoD/1.08": 84,
        "LoD/1.09": 84,
        "LoD/1.09b": 84,
        "LoD/1.09d": 84,
        "LoD/1.10": 84,
        "LoD/1.11": 84,
        "LoD/1.11b": 84,
        "LoD/1.12a": 84,
        "LoD/1.13c": 84,
        "LoD/1.13d": 84,
        "LoD/1.14a": 84,
        "LoD/1.14b": 84,
        "LoD/1.14c": 84,
        "LoD/1.14d": 84
      },
      "stack_frame_sizes": {
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
        "LoD/1.13d": 12,
        "LoD/1.14a": 12,
        "LoD/1.14b": 12,
        "LoD/1.14c": 12,
        "LoD/1.14d": 12
      },
      "basic_block_counts": {
        "LoD/1.07": 28,
        "LoD/1.08": 28,
        "LoD/1.09": 28,
        "LoD/1.09b": 28,
        "LoD/1.09d": 28,
        "LoD/1.10": 28,
        "LoD/1.11": 28,
        "LoD/1.11b": 28,
        "LoD/1.12a": 28,
        "LoD/1.13c": 28,
        "LoD/1.13d": 28,
        "LoD/1.14a": 28,
        "LoD/1.14b": 28,
        "LoD/1.14c": 28,
        "LoD/1.14d": 28
      },
      "loop_counts": {
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
        "LoD/1.13d": 6,
        "LoD/1.14a": 6,
        "LoD/1.14b": 6,
        "LoD/1.14c": 6,
        "LoD/1.14d": 6
      },
      "mnemonic_hashes": {
        "LoD/1.07": "845fc5044ff181fe96e2ae868d3aa1f6",
        "LoD/1.08": "845fc5044ff181fe96e2ae868d3aa1f6",
        "LoD/1.09": "845fc5044ff181fe96e2ae868d3aa1f6",
        "LoD/1.09b": "845fc5044ff181fe96e2ae868d3aa1f6",
        "LoD/1.09d": "845fc5044ff181fe96e2ae868d3aa1f6",
        "LoD/1.10": "845fc5044ff181fe96e2ae868d3aa1f6",
        "LoD/1.11": "845fc5044ff181fe96e2ae868d3aa1f6",
        "LoD/1.11b": "845fc5044ff181fe96e2ae868d3aa1f6",
        "LoD/1.12a": "845fc5044ff181fe96e2ae868d3aa1f6",
        "LoD/1.13c": "845fc5044ff181fe96e2ae868d3aa1f6",
        "LoD/1.13d": "845fc5044ff181fe96e2ae868d3aa1f6",
        "LoD/1.14a": "845fc5044ff181fe96e2ae868d3aa1f6",
        "LoD/1.14b": "845fc5044ff181fe96e2ae868d3aa1f6",
        "LoD/1.14c": "845fc5044ff181fe96e2ae868d3aa1f6",
        "LoD/1.14d": "845fc5044ff181fe96e2ae868d3aa1f6"
      },
      "constants": {
        "LoD/1.07": [
          16711680
        ],
        "LoD/1.08": [
          16711680
        ],
        "LoD/1.09": [
          16711680
        ],
        "LoD/1.09b": [
          16711680
        ],
        "LoD/1.09d": [
          16711680
        ],
        "LoD/1.10": [
          16711680
        ],
        "LoD/1.11": [
          16711680
        ],
        "LoD/1.11b": [
          16711680
        ],
        "LoD/1.12a": [
          16711680
        ],
        "LoD/1.13c": [
          16711680
        ],
        "LoD/1.13d": [
          16711680
        ],
        "LoD/1.14a": [
          16711680
        ],
        "LoD/1.14b": [
          16711680
        ],
        "LoD/1.14c": [
          16711680
        ],
        "LoD/1.14d": [
          16711680
        ]
      },
      "globals": {
        "LoD/1.07": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ],
        "LoD/1.08": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ],
        "LoD/1.09": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ],
        "LoD/1.09b": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ],
        "LoD/1.09d": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ],
        "LoD/1.10": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ],
        "LoD/1.11": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ],
        "LoD/1.11b": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ],
        "LoD/1.12a": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ],
        "LoD/1.13c": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ],
        "LoD/1.13d": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ],
        "LoD/1.14a": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ],
        "LoD/1.14b": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ],
        "LoD/1.14c": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ],
        "LoD/1.14d": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ]
      }
    },
    "diablo ii.exe__malloc": {
      "addresses": {
        "LoD/1.07": "0x00402EF0",
        "LoD/1.08": "0x00402EF0",
        "LoD/1.09": "0x00402EF0",
        "LoD/1.09b": "0x00402EF0",
        "LoD/1.09d": "0x00402EF0",
        "LoD/1.10": "0x00402EF0",
        "LoD/1.11": "0x00402EF0",
        "LoD/1.11b": "0x00402EF0",
        "LoD/1.12a": "0x00402EF0",
        "LoD/1.13c": "0x00402EF0",
        "LoD/1.13d": "0x00402EF0",
        "LoD/1.14a": "0x00402EF0",
        "LoD/1.14b": "0x00402EF0",
        "LoD/1.14c": "0x00402EF0",
        "LoD/1.14d": "0x00402EF0"
      },
      "rvas": {
        "LoD/1.07": "0x2EF0",
        "LoD/1.08": "0x2EF0",
        "LoD/1.09": "0x2EF0",
        "LoD/1.09b": "0x2EF0",
        "LoD/1.09d": "0x2EF0",
        "LoD/1.10": "0x2EF0",
        "LoD/1.11": "0x2EF0",
        "LoD/1.11b": "0x2EF0",
        "LoD/1.12a": "0x2EF0",
        "LoD/1.13c": "0x2EF0",
        "LoD/1.13d": "0x2EF0",
        "LoD/1.14a": "0x2EF0",
        "LoD/1.14b": "0x2EF0",
        "LoD/1.14c": "0x2EF0",
        "LoD/1.14d": "0x2EF0"
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
        "LoD/1.13d": 18,
        "LoD/1.14a": 18,
        "LoD/1.14b": 18,
        "LoD/1.14c": 18,
        "LoD/1.14d": 18
      },
      "name": "_malloc",
      "signature": "void * _malloc(size_t _Size)",
      "calling_convention": "__cdecl",
      "return_type": "void *",
      "comment": "Allocates memory block from the heap using the new handler mechanism.\n\nAlgorithm:\n1. Call internal __nh_malloc function with requested size and global new handler flag\n2. Return allocated memory pointer or NULL on failure\n\nParameters:\n_Size (size_t): Number of bytes to allocate from the heap\n\nReturns:\nvoid *: Pointer to allocated memory block on success\nNULL: If allocation fails or size is 0\n\nSpecial Cases:\n- Uses g_dwNewHandlerFlag (0x0) for new handler behavior configuration\n- Delegates actual allocation to __nh_malloc internal implementation\n- Standard C runtime library wrapper function\n\nError Handling:\n- Memory allocation failure returns NULL pointer\n- No exception throwing, relies on new handler mechanism",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:301bd5440f60703ca7a24a8fb30f1e56",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "301bd5440f60703ca7a24a8fb30f1e56",
        "CFG": "d6859c2eb1fab9ceaa654d0b9ae7bc20",
        "PRO": "34f4897579d5313b7e93086d02ff4197",
        "CAL": null,
        "CON": null,
        "APS": null
      },
      "callees": {
        "LoD/1.07": [
          "__nh_malloc|0x402F02"
        ],
        "LoD/1.08": [
          "__nh_malloc|0x402F02"
        ],
        "LoD/1.09": [
          "__nh_malloc|0x402F02"
        ],
        "LoD/1.09b": [
          "__nh_malloc|0x402F02"
        ],
        "LoD/1.09d": [
          "__nh_malloc|0x402F02"
        ],
        "LoD/1.10": [
          "__nh_malloc|0x402F02"
        ],
        "LoD/1.11": [
          "__nh_malloc|0x402F02"
        ],
        "LoD/1.11b": [
          "__nh_malloc|0x402F02"
        ],
        "LoD/1.12a": [
          "__nh_malloc|0x402F02"
        ],
        "LoD/1.13c": [
          "__nh_malloc|0x402F02"
        ],
        "LoD/1.13d": [
          "__nh_malloc|0x402F02"
        ],
        "LoD/1.14a": [
          "__nh_malloc|0x402F02"
        ],
        "LoD/1.14b": [
          "__nh_malloc|0x402F02"
        ],
        "LoD/1.14c": [
          "__nh_malloc|0x402F02"
        ],
        "LoD/1.14d": [
          "__nh_malloc|0x402F02"
        ]
      },
      "callers": {
        "LoD/1.07": [
          "InitializeModuleData|0x402017",
          "InitializeEnvironmentVariables|0x401F5E",
          "InitializeFileDescriptors|0x402396",
          "GetEnvironmentStringsConverted|0x402264"
        ],
        "LoD/1.08": [
          "InitializeEnvironmentVariables|0x401F5E",
          "InitializeModuleData|0x402017",
          "GetEnvironmentStringsConverted|0x402264",
          "InitializeFileDescriptors|0x402396"
        ],
        "LoD/1.09": [
          "InitializeEnvironmentVariables|0x401F5E",
          "InitializeModuleData|0x402017",
          "GetEnvironmentStringsConverted|0x402264",
          "InitializeFileDescriptors|0x402396"
        ],
        "LoD/1.09b": [
          "InitializeFileDescriptors|0x402396",
          "GetEnvironmentStringsConverted|0x402264",
          "InitializeEnvironmentVariables|0x401F5E",
          "InitializeModuleData|0x402017"
        ],
        "LoD/1.09d": [
          "InitializeEnvironmentVariables|0x401F5E",
          "InitializeModuleData|0x402017",
          "InitializeFileDescriptors|0x402396",
          "GetEnvironmentStringsConverted|0x402264"
        ],
        "LoD/1.10": [
          "InitializeFileDescriptors|0x402396",
          "InitializeEnvironmentVariables|0x401F5E",
          "InitializeModuleData|0x402017",
          "GetEnvironmentStringsConverted|0x402264"
        ],
        "LoD/1.11": [
          "InitializeModuleData|0x402017",
          "InitializeEnvironmentVariables|0x401F5E",
          "GetEnvironmentStringsConverted|0x402264",
          "InitializeFileDescriptors|0x402396"
        ],
        "LoD/1.11b": [
          "InitializeModuleData|0x402017",
          "GetEnvironmentStringsConverted|0x402264",
          "InitializeEnvironmentVariables|0x401F5E",
          "InitializeFileDescriptors|0x402396"
        ],
        "LoD/1.12a": [
          "InitializeFileDescriptors|0x402396",
          "InitializeEnvironmentVariables|0x401F5E",
          "InitializeModuleData|0x402017",
          "GetEnvironmentStringsConverted|0x402264"
        ],
        "LoD/1.13c": [
          "GetEnvironmentStringsConverted|0x402264",
          "InitializeFileDescriptors|0x402396",
          "InitializeModuleData|0x402017",
          "InitializeEnvironmentVariables|0x401F5E"
        ],
        "LoD/1.13d": [
          "InitializeModuleData|0x402017",
          "InitializeEnvironmentVariables|0x401F5E",
          "GetEnvironmentStringsConverted|0x402264",
          "InitializeFileDescriptors|0x402396"
        ],
        "LoD/1.14a": [
          "GetEnvironmentStringsConverted|0x402264",
          "InitializeFileDescriptors|0x402396",
          "InitializeEnvironmentVariables|0x401F5E",
          "InitializeModuleData|0x402017"
        ],
        "LoD/1.14b": [
          "InitializeModuleData|0x402017",
          "InitializeEnvironmentVariables|0x401F5E",
          "GetEnvironmentStringsConverted|0x402264",
          "InitializeFileDescriptors|0x402396"
        ],
        "LoD/1.14c": [
          "GetEnvironmentStringsConverted|0x402264",
          "InitializeFileDescriptors|0x402396",
          "InitializeModuleData|0x402017",
          "InitializeEnvironmentVariables|0x401F5E"
        ],
        "LoD/1.14d": [
          "InitializeModuleData|0x402017",
          "GetEnvironmentStringsConverted|0x402264",
          "InitializeFileDescriptors|0x402396",
          "InitializeEnvironmentVariables|0x401F5E"
        ]
      },
      "instruction_counts": {
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
        "LoD/1.13d": 6,
        "LoD/1.14a": 6,
        "LoD/1.14b": 6,
        "LoD/1.14c": 6,
        "LoD/1.14d": 6
      },
      "stack_frame_sizes": {
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
        "LoD/1.13d": 8,
        "LoD/1.14a": 8,
        "LoD/1.14b": 8,
        "LoD/1.14c": 8,
        "LoD/1.14d": 8
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
        "LoD/1.13d": 1,
        "LoD/1.14a": 1,
        "LoD/1.14b": 1,
        "LoD/1.14c": 1,
        "LoD/1.14d": 1
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
        "LoD/1.13d": 0,
        "LoD/1.14a": 0,
        "LoD/1.14b": 0,
        "LoD/1.14c": 0,
        "LoD/1.14d": 0
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
        "LoD/1.13d": "301bd5440f60703ca7a24a8fb30f1e56",
        "LoD/1.14a": "301bd5440f60703ca7a24a8fb30f1e56",
        "LoD/1.14b": "301bd5440f60703ca7a24a8fb30f1e56",
        "LoD/1.14c": "301bd5440f60703ca7a24a8fb30f1e56",
        "LoD/1.14d": "301bd5440f60703ca7a24a8fb30f1e56"
      },
      "globals": {
        "LoD/1.07": [
          "0x6654|g_pfnRetryHandler",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.08": [
          "0x6654|g_pfnRetryHandler",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.09": [
          "0x6654|g_pfnRetryHandler",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.09b": [
          "0x6654|g_pfnRetryHandler",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.09d": [
          "0x6654|g_pfnRetryHandler",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.10": [
          "0x6654|g_dwNewHandlerFlag",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.11": [
          "0x6654|g_pfnRetryHandler",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.11b": [
          "0x6654|g_pfnRetryHandler",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.12a": [
          "0x6654|g_pfnRetryHandler",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.13c": [
          "0x6654|g_pfnRetryHandler",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.13d": [
          "0x6654|g_pfnRetryHandler",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.14a": [
          "0x6654|g_pfnRetryHandler",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.14b": [
          "0x6654|g_pfnRetryHandler",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.14c": [
          "0x6654|g_pfnRetryHandler",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.14d": [
          "0x6654|g_pfnRetryHandler",
          "0xFFFFFFFFFFC00004|"
        ]
      }
    },
    "diablo ii.exe___nh_malloc": {
      "addresses": {
        "LoD/1.07": "0x00402F02",
        "LoD/1.08": "0x00402F02",
        "LoD/1.09": "0x00402F02",
        "LoD/1.09b": "0x00402F02",
        "LoD/1.09d": "0x00402F02",
        "LoD/1.10": "0x00402F02",
        "LoD/1.11": "0x00402F02",
        "LoD/1.11b": "0x00402F02",
        "LoD/1.12a": "0x00402F02",
        "LoD/1.13c": "0x00402F02",
        "LoD/1.13d": "0x00402F02",
        "LoD/1.14a": "0x00402F02",
        "LoD/1.14b": "0x00402F02",
        "LoD/1.14c": "0x00402F02",
        "LoD/1.14d": "0x00402F02"
      },
      "rvas": {
        "LoD/1.07": "0x2F02",
        "LoD/1.08": "0x2F02",
        "LoD/1.09": "0x2F02",
        "LoD/1.09b": "0x2F02",
        "LoD/1.09d": "0x2F02",
        "LoD/1.10": "0x2F02",
        "LoD/1.11": "0x2F02",
        "LoD/1.11b": "0x2F02",
        "LoD/1.12a": "0x2F02",
        "LoD/1.13c": "0x2F02",
        "LoD/1.13d": "0x2F02",
        "LoD/1.14a": "0x2F02",
        "LoD/1.14b": "0x2F02",
        "LoD/1.14c": "0x2F02",
        "LoD/1.14d": "0x2F02"
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
        "LoD/1.13d": 44,
        "LoD/1.14a": 44,
        "LoD/1.14b": 44,
        "LoD/1.14c": 44,
        "LoD/1.14d": 44
      },
      "name": "__nh_malloc",
      "signature": "void * __nh_malloc(size_t _Size, int _NhFlag)",
      "calling_convention": "__cdecl",
      "return_type": "void *",
      "comment": "Memory allocation with new handler support\n\nAlgorithm:\n1. Validate size parameter against maximum limit (0xffffffe1 = SIZE_MAX - 31)\n2. Enter allocation retry loop\n3. Attempt memory allocation via FUN_1001c99e (primary allocator)\n4. If allocation succeeds, return pointer to allocated memory\n5. If allocation fails and new handler flag is disabled, return NULL\n6. If allocation fails and new handler flag is enabled, call new handler FUN_1001d405\n7. If new handler returns non-zero (success), retry allocation from step 3\n8. If new handler returns zero (failure), exit loop and return NULL\n\nParameters:\n_Size - size_t: Number of bytes to allocate\n_NhFlag - int: New handler flag (0=disabled, non-zero=enabled)\n\nReturns:\nvoid* - Pointer to allocated memory on success, NULL on failure\n\nSpecial Cases:\nSize >= 0xffffffe1 bytes immediately returns NULL (size limit exceeded)\nNew handler disabled (_NhFlag=0) returns NULL on first allocation failure\nNew handler enabled retries allocation until handler indicates stop",
      "name_source": "LoD/1.07",
      "method": "CAL",
      "index": "CAL:edc0f37d3576a005f73adb0b703117a8",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "be05c38d951a724b98e30bc46956a8c1",
        "CFG": "9f044bca13552ccd8ed2b26b9e8086d5",
        "PRO": "c23a96deea647357438db7500c249a64",
        "CAL": "edc0f37d3576a005f73adb0b703117a8",
        "CON": null,
        "APS": null
      },
      "callees": {
        "LoD/1.07": [
          "AllocateMemoryWithCache|0x402F2E",
          "InvokeCallbackHandler|0x403D08"
        ],
        "LoD/1.08": [
          "InvokeCallbackHandler|0x403D08",
          "AllocateMemoryWithCache|0x402F2E"
        ],
        "LoD/1.09": [
          "InvokeCallbackHandler|0x403D08",
          "AllocateMemoryWithCache|0x402F2E"
        ],
        "LoD/1.09b": [
          "AllocateMemoryWithCache|0x402F2E",
          "InvokeCallbackHandler|0x403D08"
        ],
        "LoD/1.09d": [
          "InvokeCallbackHandler|0x403D08",
          "AllocateMemoryWithCache|0x402F2E"
        ],
        "LoD/1.10": [
          "AllocateMemoryWithCache|0x402F2E",
          "InvokeCallbackHandler|0x403D08"
        ],
        "LoD/1.11": [
          "AllocateMemoryWithCache|0x402F2E",
          "InvokeCallbackHandler|0x403D08"
        ],
        "LoD/1.11b": [
          "InvokeCallbackHandler|0x403D08",
          "AllocateMemoryWithCache|0x402F2E"
        ],
        "LoD/1.12a": [
          "AllocateMemoryWithCache|0x402F2E",
          "InvokeCallbackHandler|0x403D08"
        ],
        "LoD/1.13c": [
          "AllocateMemoryWithCache|0x402F2E",
          "InvokeCallbackHandler|0x403D08"
        ],
        "LoD/1.13d": [
          "InvokeCallbackHandler|0x403D08",
          "AllocateMemoryWithCache|0x402F2E"
        ],
        "LoD/1.14a": [
          "InvokeCallbackHandler|0x403D08",
          "AllocateMemoryWithCache|0x402F2E"
        ],
        "LoD/1.14b": [
          "InvokeCallbackHandler|0x403D08",
          "AllocateMemoryWithCache|0x402F2E"
        ],
        "LoD/1.14c": [
          "InvokeCallbackHandler|0x403D08",
          "AllocateMemoryWithCache|0x402F2E"
        ],
        "LoD/1.14d": [
          "AllocateMemoryWithCache|0x402F2E",
          "InvokeCallbackHandler|0x403D08"
        ]
      },
      "callers": {
        "LoD/1.07": [
          "_malloc|0x402EF0"
        ],
        "LoD/1.08": [
          "_malloc|0x402EF0"
        ],
        "LoD/1.09": [
          "_malloc|0x402EF0"
        ],
        "LoD/1.09b": [
          "_malloc|0x402EF0"
        ],
        "LoD/1.09d": [
          "_malloc|0x402EF0"
        ],
        "LoD/1.10": [
          "_malloc|0x402EF0"
        ],
        "LoD/1.11": [
          "_malloc|0x402EF0"
        ],
        "LoD/1.11b": [
          "_malloc|0x402EF0"
        ],
        "LoD/1.12a": [
          "_malloc|0x402EF0"
        ],
        "LoD/1.13c": [
          "_malloc|0x402EF0"
        ],
        "LoD/1.13d": [
          "_malloc|0x402EF0"
        ],
        "LoD/1.14a": [
          "_malloc|0x402EF0"
        ],
        "LoD/1.14b": [
          "_malloc|0x402EF0"
        ],
        "LoD/1.14c": [
          "_malloc|0x402EF0"
        ],
        "LoD/1.14d": [
          "_malloc|0x402EF0"
        ]
      },
      "instruction_counts": {
        "LoD/1.07": 16,
        "LoD/1.08": 16,
        "LoD/1.09": 16,
        "LoD/1.09b": 16,
        "LoD/1.09d": 16,
        "LoD/1.10": 16,
        "LoD/1.11": 16,
        "LoD/1.11b": 16,
        "LoD/1.12a": 16,
        "LoD/1.13c": 16,
        "LoD/1.13d": 16,
        "LoD/1.14a": 16,
        "LoD/1.14b": 16,
        "LoD/1.14c": 16,
        "LoD/1.14d": 16
      },
      "stack_frame_sizes": {
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
        "LoD/1.13d": 12,
        "LoD/1.14a": 12,
        "LoD/1.14b": 12,
        "LoD/1.14c": 12,
        "LoD/1.14d": 12
      },
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
        "LoD/1.13d": 6,
        "LoD/1.14a": 6,
        "LoD/1.14b": 6,
        "LoD/1.14c": 6,
        "LoD/1.14d": 6
      },
      "loop_counts": {
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
        "LoD/1.13d": 1,
        "LoD/1.14a": 1,
        "LoD/1.14b": 1,
        "LoD/1.14c": 1,
        "LoD/1.14d": 1
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
        "LoD/1.13d": "be05c38d951a724b98e30bc46956a8c1",
        "LoD/1.14a": "be05c38d951a724b98e30bc46956a8c1",
        "LoD/1.14b": "be05c38d951a724b98e30bc46956a8c1",
        "LoD/1.14c": "be05c38d951a724b98e30bc46956a8c1",
        "LoD/1.14d": "be05c38d951a724b98e30bc46956a8c1"
      },
      "globals": {
        "LoD/1.07": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ],
        "LoD/1.08": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ],
        "LoD/1.09": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ],
        "LoD/1.09b": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ],
        "LoD/1.09d": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ],
        "LoD/1.10": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ],
        "LoD/1.11": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ],
        "LoD/1.11b": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ],
        "LoD/1.12a": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ],
        "LoD/1.13c": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ],
        "LoD/1.13d": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ],
        "LoD/1.14a": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ],
        "LoD/1.14b": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ],
        "LoD/1.14c": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ],
        "LoD/1.14d": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ]
      }
    },
    "diablo ii.exe_AllocateMemoryWithCache": {
      "addresses": {
        "LoD/1.07": "0x00402F2E",
        "LoD/1.08": "0x00402F2E",
        "LoD/1.09": "0x00402F2E",
        "LoD/1.09b": "0x00402F2E",
        "LoD/1.09d": "0x00402F2E",
        "LoD/1.10": "0x00402F2E",
        "LoD/1.11": "0x00402F2E",
        "LoD/1.11b": "0x00402F2E",
        "LoD/1.12a": "0x00402F2E",
        "LoD/1.13c": "0x00402F2E",
        "LoD/1.13d": "0x00402F2E",
        "LoD/1.14a": "0x00402F2E",
        "LoD/1.14b": "0x00402F2E",
        "LoD/1.14c": "0x00402F2E",
        "LoD/1.14d": "0x00402F2E"
      },
      "rvas": {
        "LoD/1.07": "0x2F2E",
        "LoD/1.08": "0x2F2E",
        "LoD/1.09": "0x2F2E",
        "LoD/1.09b": "0x2F2E",
        "LoD/1.09d": "0x2F2E",
        "LoD/1.10": "0x2F2E",
        "LoD/1.11": "0x2F2E",
        "LoD/1.11b": "0x2F2E",
        "LoD/1.12a": "0x2F2E",
        "LoD/1.13c": "0x2F2E",
        "LoD/1.13d": "0x2F2E",
        "LoD/1.14a": "0x2F2E",
        "LoD/1.14b": "0x2F2E",
        "LoD/1.14c": "0x2F2E",
        "LoD/1.14d": "0x2F2E"
      },
      "sizes": {
        "LoD/1.07": 54,
        "LoD/1.08": 54,
        "LoD/1.09": 54,
        "LoD/1.09b": 54,
        "LoD/1.09d": 54,
        "LoD/1.10": 54,
        "LoD/1.11": 54,
        "LoD/1.11b": 54,
        "LoD/1.12a": 54,
        "LoD/1.13c": 54,
        "LoD/1.13d": 54,
        "LoD/1.14a": 54,
        "LoD/1.14b": 54,
        "LoD/1.14c": 54,
        "LoD/1.14d": 54
      },
      "name": "AllocateMemoryWithCache",
      "signature": "void * AllocateMemoryWithCache(uint dwRequestedSize)",
      "calling_convention": "__cdecl",
      "return_type": "void *",
      "comment": "Memory allocation wrapper with cache optimization for heap management.\n\nAlgorithm:\n\n1. Check if requested size is within cache limit (dwRequestedSize <= g_dwCacheSizeLimit)\n2. If within limit, attempt cache lookup via FUN_1001d865(dwRequestedSize)\n3. If cache hit (pCachedMemory != NULL), return early with cached memory\n4. If cache miss or size exceeds limit, proceed to heap allocation\n5. Validate parameter: if dwRequestedSize is NULL, default to 1 byte minimum\n6. Round up allocation size to 16-byte boundary alignment: (dwRequestedSize + 0xF) & 0xFFFFFFF0\n7. Call HeapAlloc(g_hHeap, 0, alignedSize) to allocate from process heap\n8. Return allocated memory pointer or NULL on failure\n\nParameters:\n\ndwRequestedSize (uint) - Size in bytes to allocate, 0 defaults to 1 byte minimum\n\nReturns:\n\nvoid* - Pointer to allocated memory block (16-byte aligned)\nNULL - Allocation failed or cache returned valid pointer\n\nSpecial Cases:\n\nSize 0: Converted to 1 byte minimum allocation to prevent zero-size requests\nCache hit: Early return bypasses heap allocation for performance optimization\nAlignment: All allocations rounded up to 16-byte boundaries for SIMD compatibility\n\nMagic Numbers Reference:\n\n0xF (15) - Alignment mask addition for rounding up to next 16-byte boundary\n0xFFFFFFF0 - Bitwise AND mask to clear lower 4 bits, enforcing 16-byte alignment\n\nError Handling:\n\nNull parameter validation converts 0-size requests to 1-byte minimum\nHeapAlloc failure returns NULL, propagated to caller for error handling\nCache lookup failure triggers fallback to heap allocation path",
      "name_source": "LoD/1.07",
      "method": "CAL",
      "index": "CAL:52a117cb90b97785fb6b3db59a8fe687",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "4e5e59b9a63f832f54b3dcf90c4a63d7",
        "CFG": "2f4c9f964ceef7c087d3e5f43a3d4cd4",
        "PRO": "7c2798772733d12aa5a4d0ccd50b453d",
        "CAL": "52a117cb90b97785fb6b3db59a8fe687",
        "CON": null,
        "APS": null
      },
      "callees": {
        "LoD/1.07": [
          "AllocateMemoryDescriptorBlock|0x403639",
          "HeapAlloc|0x28"
        ],
        "LoD/1.08": [
          "AllocateMemoryDescriptorBlock|0x403639",
          "HeapAlloc|0x28"
        ],
        "LoD/1.09": [
          "AllocateMemoryDescriptorBlock|0x403639",
          "HeapAlloc|0x28"
        ],
        "LoD/1.09b": [
          "AllocateMemoryDescriptorBlock|0x403639",
          "HeapAlloc|0x28"
        ],
        "LoD/1.09d": [
          "AllocateMemoryDescriptorBlock|0x403639",
          "HeapAlloc|0x28"
        ],
        "LoD/1.10": [
          "HeapAlloc|0x28",
          "AllocateMemoryDescriptorBlock|0x403639"
        ],
        "LoD/1.11": [
          "AllocateMemoryDescriptorBlock|0x403639",
          "HeapAlloc|0x28"
        ],
        "LoD/1.11b": [
          "AllocateMemoryDescriptorBlock|0x403639",
          "HeapAlloc|0x28"
        ],
        "LoD/1.12a": [
          "HeapAlloc|0x28",
          "AllocateMemoryDescriptorBlock|0x403639"
        ],
        "LoD/1.13c": [
          "HeapAlloc|0x28",
          "AllocateMemoryDescriptorBlock|0x403639"
        ],
        "LoD/1.13d": [
          "AllocateMemoryDescriptorBlock|0x403639",
          "HeapAlloc|0x28"
        ],
        "LoD/1.14a": [
          "AllocateMemoryDescriptorBlock|0x403639",
          "HeapAlloc|0x28"
        ],
        "LoD/1.14b": [
          "AllocateMemoryDescriptorBlock|0x403639",
          "HeapAlloc|0x28"
        ],
        "LoD/1.14c": [
          "HeapAlloc|0x28",
          "AllocateMemoryDescriptorBlock|0x403639"
        ],
        "LoD/1.14d": [
          "HeapAlloc|0x28",
          "AllocateMemoryDescriptorBlock|0x403639"
        ]
      },
      "callers": {
        "LoD/1.07": [
          "__nh_malloc|0x402F02"
        ],
        "LoD/1.08": [
          "__nh_malloc|0x402F02"
        ],
        "LoD/1.09": [
          "__nh_malloc|0x402F02"
        ],
        "LoD/1.09b": [
          "__nh_malloc|0x402F02"
        ],
        "LoD/1.09d": [
          "__nh_malloc|0x402F02"
        ],
        "LoD/1.10": [
          "__nh_malloc|0x402F02"
        ],
        "LoD/1.11": [
          "__nh_malloc|0x402F02"
        ],
        "LoD/1.11b": [
          "__nh_malloc|0x402F02"
        ],
        "LoD/1.12a": [
          "__nh_malloc|0x402F02"
        ],
        "LoD/1.13c": [
          "__nh_malloc|0x402F02"
        ],
        "LoD/1.13d": [
          "__nh_malloc|0x402F02"
        ],
        "LoD/1.14a": [
          "__nh_malloc|0x402F02"
        ],
        "LoD/1.14b": [
          "__nh_malloc|0x402F02"
        ],
        "LoD/1.14c": [
          "__nh_malloc|0x402F02"
        ],
        "LoD/1.14d": [
          "__nh_malloc|0x402F02"
        ]
      },
      "instruction_counts": {
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
        "LoD/1.13d": 21,
        "LoD/1.14a": 21,
        "LoD/1.14b": 21,
        "LoD/1.14c": 21,
        "LoD/1.14d": 21
      },
      "stack_frame_sizes": {
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
        "LoD/1.13d": 8,
        "LoD/1.14a": 8,
        "LoD/1.14b": 8,
        "LoD/1.14c": 8,
        "LoD/1.14d": 8
      },
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
        "LoD/1.13d": 6,
        "LoD/1.14a": 6,
        "LoD/1.14b": 6,
        "LoD/1.14c": 6,
        "LoD/1.14d": 6
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
        "LoD/1.13d": 0,
        "LoD/1.14a": 0,
        "LoD/1.14b": 0,
        "LoD/1.14c": 0,
        "LoD/1.14d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "4e5e59b9a63f832f54b3dcf90c4a63d7",
        "LoD/1.08": "4e5e59b9a63f832f54b3dcf90c4a63d7",
        "LoD/1.09": "4e5e59b9a63f832f54b3dcf90c4a63d7",
        "LoD/1.09b": "4e5e59b9a63f832f54b3dcf90c4a63d7",
        "LoD/1.09d": "4e5e59b9a63f832f54b3dcf90c4a63d7",
        "LoD/1.10": "4e5e59b9a63f832f54b3dcf90c4a63d7",
        "LoD/1.11": "4e5e59b9a63f832f54b3dcf90c4a63d7",
        "LoD/1.11b": "4e5e59b9a63f832f54b3dcf90c4a63d7",
        "LoD/1.12a": "4e5e59b9a63f832f54b3dcf90c4a63d7",
        "LoD/1.13c": "4e5e59b9a63f832f54b3dcf90c4a63d7",
        "LoD/1.13d": "4e5e59b9a63f832f54b3dcf90c4a63d7",
        "LoD/1.14a": "4e5e59b9a63f832f54b3dcf90c4a63d7",
        "LoD/1.14b": "4e5e59b9a63f832f54b3dcf90c4a63d7",
        "LoD/1.14c": "4e5e59b9a63f832f54b3dcf90c4a63d7",
        "LoD/1.14d": "4e5e59b9a63f832f54b3dcf90c4a63d7"
      },
      "globals": {
        "LoD/1.07": [
          "0xFFFFFFFFFFC00004|",
          "0x6290|g_dwCacheSizeLimit",
          "0x6674|g_hHeapHandle",
          "0x509C|PTR_HeapAlloc_0040509c"
        ],
        "LoD/1.08": [
          "0xFFFFFFFFFFC00004|",
          "0x6290|g_dwCacheSizeLimit",
          "0x6674|g_hHeapHandle",
          "0x509C|PTR_HeapAlloc_0040509c"
        ],
        "LoD/1.09": [
          "0xFFFFFFFFFFC00004|",
          "0x6290|g_dwCacheSizeLimit",
          "0x6674|g_hHeapHandle",
          "0x509C|PTR_HeapAlloc_0040509c"
        ],
        "LoD/1.09b": [
          "0xFFFFFFFFFFC00004|",
          "0x6290|g_dwCacheSizeLimit",
          "0x6674|g_hHeapHandle",
          "0x509C|PTR_HeapAlloc_0040509c"
        ],
        "LoD/1.09d": [
          "0xFFFFFFFFFFC00004|",
          "0x6290|g_dwCacheSizeLimit",
          "0x6674|g_hHeapHandle",
          "0x509C|PTR_HeapAlloc_0040509c"
        ],
        "LoD/1.10": [
          "0xFFFFFFFFFFC00004|",
          "0x6290|g_dwCacheSizeLimit",
          "0x6674|g_hHeap",
          "0x509C|PTR_HeapAlloc_0040509c"
        ],
        "LoD/1.11": [
          "0xFFFFFFFFFFC00004|",
          "0x6290|g_dwCacheSizeLimit",
          "0x6674|g_hHeapHandle",
          "0x509C|PTR_HeapAlloc_0040509c"
        ],
        "LoD/1.11b": [
          "0xFFFFFFFFFFC00004|",
          "0x6290|g_dwCacheSizeLimit",
          "0x6674|g_hHeapHandle",
          "0x509C|PTR_HeapAlloc_0040509c"
        ],
        "LoD/1.12a": [
          "0xFFFFFFFFFFC00004|",
          "0x6290|g_dwCacheSizeLimit",
          "0x6674|g_hHeapHandle",
          "0x509C|PTR_HeapAlloc_0040509c"
        ],
        "LoD/1.13c": [
          "0xFFFFFFFFFFC00004|",
          "0x6290|g_dwCacheSizeLimit",
          "0x6674|g_hHeapHandle",
          "0x509C|PTR_HeapAlloc_0040509c"
        ],
        "LoD/1.13d": [
          "0xFFFFFFFFFFC00004|",
          "0x6290|g_dwCacheSizeLimit",
          "0x6674|g_hHeapHandle",
          "0x509C|PTR_HeapAlloc_0040509c"
        ],
        "LoD/1.14a": [
          "0xFFFFFFFFFFC00004|",
          "0x6290|g_dwCacheSizeLimit",
          "0x6674|g_hHeapHandle",
          "0x509C|PTR_HeapAlloc_0040509c"
        ],
        "LoD/1.14b": [
          "0xFFFFFFFFFFC00004|",
          "0x6290|g_dwCacheSizeLimit",
          "0x6674|g_hHeapHandle",
          "0x509C|PTR_HeapAlloc_0040509c"
        ],
        "LoD/1.14c": [
          "0xFFFFFFFFFFC00004|",
          "0x6290|g_dwCacheSizeLimit",
          "0x6674|g_hHeapHandle",
          "0x509C|PTR_HeapAlloc_0040509c"
        ],
        "LoD/1.14d": [
          "0xFFFFFFFFFFC00004|",
          "0x6290|g_dwCacheSizeLimit",
          "0x6674|g_hHeapHandle",
          "0x509C|PTR_HeapAlloc_0040509c"
        ]
      }
    },
    "diablo ii.exe_OptimizedMemoryMove": {
      "addresses": {
        "LoD/1.07": "0x00403D30",
        "LoD/1.08": "0x00403D30",
        "LoD/1.09": "0x00403D30",
        "LoD/1.09b": "0x00403D30",
        "LoD/1.09d": "0x00403D30",
        "LoD/1.10": "0x00403D30",
        "LoD/1.11": "0x00403D30",
        "LoD/1.11b": "0x00403D30",
        "LoD/1.12a": "0x00403D30",
        "LoD/1.13c": "0x00403D30",
        "LoD/1.13d": "0x00403D30",
        "LoD/1.14a": "0x00403D30",
        "LoD/1.14b": "0x00403D30",
        "LoD/1.14c": "0x00403D30",
        "LoD/1.14d": "0x00403D30"
      },
      "rvas": {
        "LoD/1.07": "0x3D30",
        "LoD/1.08": "0x3D30",
        "LoD/1.09": "0x3D30",
        "LoD/1.09b": "0x3D30",
        "LoD/1.09d": "0x3D30",
        "LoD/1.10": "0x3D30",
        "LoD/1.11": "0x3D30",
        "LoD/1.11b": "0x3D30",
        "LoD/1.12a": "0x3D30",
        "LoD/1.13c": "0x3D30",
        "LoD/1.13d": "0x3D30",
        "LoD/1.14a": "0x3D30",
        "LoD/1.14b": "0x3D30",
        "LoD/1.14c": "0x3D30",
        "LoD/1.14d": "0x3D30"
      },
      "sizes": {
        "LoD/1.07": 664,
        "LoD/1.08": 664,
        "LoD/1.09": 664,
        "LoD/1.09b": 664,
        "LoD/1.09d": 664,
        "LoD/1.10": 664,
        "LoD/1.11": 664,
        "LoD/1.11b": 664,
        "LoD/1.12a": 664,
        "LoD/1.13c": 664,
        "LoD/1.13d": 664,
        "LoD/1.14a": 664,
        "LoD/1.14b": 664,
        "LoD/1.14c": 664,
        "LoD/1.14d": 664
      },
      "name": "OptimizedMemoryMove",
      "signature": "void * OptimizedMemoryMove(void * pDestination, void * pSource, uint dwByteCount)",
      "calling_convention": "__cdecl",
      "return_type": "void *",
      "comment": "Optimized memory move implementation with overlap detection and alignment optimization.\n\nAlgorithm:\n1. Check for overlapping memory regions (source and destination ranges overlap)\n2. If overlapping regions detected, copy backwards from end to start to avoid corruption\n3. If no overlap, copy forwards from start to end for better cache performance\n4. For both directions, optimize copying using 4-byte aligned transfers when possible\n5. Handle misaligned data by copying individual bytes first to reach alignment\n6. Perform bulk 4-byte transfers in optimized loop (unroll threshold of 8 iterations)\n7. Copy remaining bytes (0-3) using individual byte transfers\n\nParameters:\npDestination - Destination memory buffer to copy data to\npSource - Source memory buffer to copy data from  \ndwByteCount - Number of bytes to copy between buffers\n\nReturns:\nvoid * - Returns original destination pointer (pDestination) for function chaining\n\nSpecial Cases:\nZero byte count - Returns immediately without any memory operations\nMisaligned pointers - Falls back to byte-by-byte copying with alignment handling\nLarge transfers - Uses optimized 4-byte transfers with loop unrolling for performance\n\nMagic Numbers Reference:\n0x4 (4) - Alignment boundary and 4-byte transfer size\n0x3 (3) - Alignment mask to check 4-byte boundary alignment  \n0x7 (7) - Loop unrolling threshold for optimized bulk transfer\n\nError Handling:\nNo explicit error checking - assumes valid memory regions and non-null pointers\nOverlap detection prevents memory corruption during overlapping copies\nAlignment optimization ensures optimal performance on x86 architecture",
      "name_source": "LoD/1.07",
      "method": "CON",
      "index": "CON:c0cded2a7439ff1fc575ac62397d80a4",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "bff09423b51fd121ea30afec957819f4",
        "CFG": "b8bcea0773ca2dfa689f3f8d23e7384e",
        "PRO": "ff38c497c82643f818ac8c3950b7223d",
        "CAL": null,
        "CON": "c0cded2a7439ff1fc575ac62397d80a4",
        "APS": null
      },
      "callers": {
        "LoD/1.07": [
          "FreeMemoryBlockWithLinkedListCleanup|0x40330E"
        ],
        "LoD/1.08": [
          "FreeMemoryBlockWithLinkedListCleanup|0x40330E"
        ],
        "LoD/1.09": [
          "FreeMemoryBlockWithLinkedListCleanup|0x40330E"
        ],
        "LoD/1.09b": [
          "FreeMemoryBlockWithLinkedListCleanup|0x40330E"
        ],
        "LoD/1.09d": [
          "FreeMemoryBlockWithLinkedListCleanup|0x40330E"
        ],
        "LoD/1.10": [
          "FreeMemoryBlockWithLinkedListCleanup|0x40330E"
        ],
        "LoD/1.11": [
          "FreeMemoryBlockWithLinkedListCleanup|0x40330E"
        ],
        "LoD/1.11b": [
          "FreeMemoryBlockWithLinkedListCleanup|0x40330E"
        ],
        "LoD/1.12a": [
          "FreeMemoryBlockWithLinkedListCleanup|0x40330E"
        ],
        "LoD/1.13c": [
          "FreeMemoryBlockWithLinkedListCleanup|0x40330E"
        ],
        "LoD/1.13d": [
          "FreeMemoryBlockWithLinkedListCleanup|0x40330E"
        ],
        "LoD/1.14a": [
          "FreeMemoryBlockWithLinkedListCleanup|0x40330E"
        ],
        "LoD/1.14b": [
          "FreeMemoryBlockWithLinkedListCleanup|0x40330E"
        ],
        "LoD/1.14c": [
          "FreeMemoryBlockWithLinkedListCleanup|0x40330E"
        ],
        "LoD/1.14d": [
          "FreeMemoryBlockWithLinkedListCleanup|0x40330E"
        ]
      },
      "instruction_counts": {
        "LoD/1.07": 231,
        "LoD/1.08": 231,
        "LoD/1.09": 231,
        "LoD/1.09b": 231,
        "LoD/1.09d": 231,
        "LoD/1.10": 231,
        "LoD/1.11": 231,
        "LoD/1.11b": 231,
        "LoD/1.12a": 231,
        "LoD/1.13c": 231,
        "LoD/1.13d": 231,
        "LoD/1.14a": 231,
        "LoD/1.14b": 231,
        "LoD/1.14c": 231,
        "LoD/1.14d": 231
      },
      "stack_frame_sizes": {
        "LoD/1.07": 16,
        "LoD/1.08": 16,
        "LoD/1.09": 16,
        "LoD/1.09b": 16,
        "LoD/1.09d": 16,
        "LoD/1.10": 16,
        "LoD/1.11": 16,
        "LoD/1.11b": 16,
        "LoD/1.12a": 16,
        "LoD/1.13c": 16,
        "LoD/1.13d": 16,
        "LoD/1.14a": 16,
        "LoD/1.14b": 16,
        "LoD/1.14c": 16,
        "LoD/1.14d": 16
      },
      "basic_block_counts": {
        "LoD/1.07": 63,
        "LoD/1.08": 63,
        "LoD/1.09": 63,
        "LoD/1.09b": 63,
        "LoD/1.09d": 63,
        "LoD/1.10": 63,
        "LoD/1.11": 63,
        "LoD/1.11b": 63,
        "LoD/1.12a": 63,
        "LoD/1.13c": 63,
        "LoD/1.13d": 63,
        "LoD/1.14a": 63,
        "LoD/1.14b": 63,
        "LoD/1.14c": 63,
        "LoD/1.14d": 63
      },
      "loop_counts": {
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
        "LoD/1.13d": 6,
        "LoD/1.14a": 6,
        "LoD/1.14b": 6,
        "LoD/1.14c": 6,
        "LoD/1.14d": 6
      },
      "mnemonic_hashes": {
        "LoD/1.07": "bff09423b51fd121ea30afec957819f4",
        "LoD/1.08": "bff09423b51fd121ea30afec957819f4",
        "LoD/1.09": "bff09423b51fd121ea30afec957819f4",
        "LoD/1.09b": "bff09423b51fd121ea30afec957819f4",
        "LoD/1.09d": "bff09423b51fd121ea30afec957819f4",
        "LoD/1.10": "bff09423b51fd121ea30afec957819f4",
        "LoD/1.11": "bff09423b51fd121ea30afec957819f4",
        "LoD/1.11b": "bff09423b51fd121ea30afec957819f4",
        "LoD/1.12a": "bff09423b51fd121ea30afec957819f4",
        "LoD/1.13c": "bff09423b51fd121ea30afec957819f4",
        "LoD/1.13d": "bff09423b51fd121ea30afec957819f4",
        "LoD/1.14a": "bff09423b51fd121ea30afec957819f4",
        "LoD/1.14b": "bff09423b51fd121ea30afec957819f4",
        "LoD/1.14c": "bff09423b51fd121ea30afec957819f4",
        "LoD/1.14d": "bff09423b51fd121ea30afec957819f4"
      },
      "constants": {
        "LoD/1.07": [
          4210064,
          4210188,
          4210296,
          4210312,
          4210456,
          4210624,
          4210704
        ],
        "LoD/1.08": [
          4210064,
          4210188,
          4210296,
          4210312,
          4210456,
          4210624,
          4210704
        ],
        "LoD/1.09": [
          4210064,
          4210188,
          4210296,
          4210312,
          4210456,
          4210624,
          4210704
        ],
        "LoD/1.09b": [
          4210064,
          4210188,
          4210296,
          4210312,
          4210456,
          4210624,
          4210704
        ],
        "LoD/1.09d": [
          4210064,
          4210188,
          4210296,
          4210312,
          4210456,
          4210624,
          4210704
        ],
        "LoD/1.10": [
          4210064,
          4210188,
          4210296,
          4210312,
          4210456,
          4210624,
          4210704
        ],
        "LoD/1.11": [
          4210064,
          4210188,
          4210296,
          4210312,
          4210456,
          4210624,
          4210704
        ],
        "LoD/1.11b": [
          4210064,
          4210188,
          4210296,
          4210312,
          4210456,
          4210624,
          4210704
        ],
        "LoD/1.12a": [
          4210064,
          4210188,
          4210296,
          4210312,
          4210456,
          4210624,
          4210704
        ],
        "LoD/1.13c": [
          4210064,
          4210188,
          4210296,
          4210312,
          4210456,
          4210624,
          4210704
        ],
        "LoD/1.13d": [
          4210064,
          4210188,
          4210296,
          4210312,
          4210456,
          4210624,
          4210704
        ],
        "LoD/1.14a": [
          4210064,
          4210188,
          4210296,
          4210312,
          4210456,
          4210624,
          4210704
        ],
        "LoD/1.14b": [
          4210064,
          4210188,
          4210296,
          4210312,
          4210456,
          4210624,
          4210704
        ],
        "LoD/1.14c": [
          4210064,
          4210188,
          4210296,
          4210312,
          4210456,
          4210624,
          4210704
        ],
        "LoD/1.14d": [
          4210064,
          4210188,
          4210296,
          4210312,
          4210456,
          4210624,
          4210704
        ]
      },
      "globals": {
        "LoD/1.07": [
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00004|",
          "0x3E78|switchdataD_00403e78",
          "0x3D94|switchdataD_00403d94",
          "0x3E0C|switchdataD_00403e0c",
          "0x4010|switchdataD_00404010",
          "0x3FC0|PTR_caseD_0_00403fc0",
          "0x3F1C|switchdataD_00403f1c"
        ],
        "LoD/1.08": [
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00004|",
          "0x3E78|switchdataD_00403e78",
          "0x3D94|switchdataD_00403d94",
          "0x3E0C|switchdataD_00403e0c",
          "0x4010|switchdataD_00404010",
          "0x3FC0|PTR_caseD_0_00403fc0",
          "0x3F1C|switchdataD_00403f1c"
        ],
        "LoD/1.09": [
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00004|",
          "0x3E78|switchdataD_00403e78",
          "0x3D94|switchdataD_00403d94",
          "0x3E0C|switchdataD_00403e0c",
          "0x4010|switchdataD_00404010",
          "0x3FC0|PTR_caseD_0_00403fc0",
          "0x3F1C|switchdataD_00403f1c"
        ],
        "LoD/1.09b": [
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00004|",
          "0x3E78|switchdataD_00403e78",
          "0x3D94|switchdataD_00403d94",
          "0x3E0C|switchdataD_00403e0c",
          "0x4010|switchdataD_00404010",
          "0x3FC0|PTR_caseD_0_00403fc0",
          "0x3F1C|switchdataD_00403f1c"
        ],
        "LoD/1.09d": [
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00004|",
          "0x3E78|switchdataD_00403e78",
          "0x3D94|switchdataD_00403d94",
          "0x3E0C|switchdataD_00403e0c",
          "0x4010|switchdataD_00404010",
          "0x3FC0|PTR_caseD_0_00403fc0",
          "0x3F1C|switchdataD_00403f1c"
        ],
        "LoD/1.10": [
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00004|",
          "0x3E78|switchdataD_00403e78",
          "0x3D94|switchdataD_00403d94",
          "0x3E0C|switchdataD_00403e0c",
          "0x4010|switchdataD_00404010",
          "0x3FC0|PTR_caseD_0_00403fc0",
          "0x3F1C|switchdataD_00403f1c"
        ],
        "LoD/1.11": [
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00004|",
          "0x3E78|switchdataD_00403e78",
          "0x3D94|switchdataD_00403d94",
          "0x3E0C|switchdataD_00403e0c",
          "0x4010|switchdataD_00404010",
          "0x3FC0|PTR_caseD_0_00403fc0",
          "0x3F1C|switchdataD_00403f1c"
        ],
        "LoD/1.11b": [
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00004|",
          "0x3E78|switchdataD_00403e78",
          "0x3D94|switchdataD_00403d94",
          "0x3E0C|switchdataD_00403e0c",
          "0x4010|switchdataD_00404010",
          "0x3FC0|PTR_caseD_0_00403fc0",
          "0x3F1C|switchdataD_00403f1c"
        ],
        "LoD/1.12a": [
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00004|",
          "0x3E78|switchdataD_00403e78",
          "0x3D94|switchdataD_00403d94",
          "0x3E0C|switchdataD_00403e0c",
          "0x4010|switchdataD_00404010",
          "0x3FC0|PTR_caseD_0_00403fc0",
          "0x3F1C|switchdataD_00403f1c"
        ],
        "LoD/1.13c": [
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00004|",
          "0x3E78|switchdataD_00403e78",
          "0x3D94|switchdataD_00403d94",
          "0x3E0C|switchdataD_00403e0c",
          "0x4010|switchdataD_00404010",
          "0x3FC0|PTR_caseD_0_00403fc0",
          "0x3F1C|switchdataD_00403f1c"
        ],
        "LoD/1.13d": [
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00004|",
          "0x3E78|switchdataD_00403e78",
          "0x3D94|switchdataD_00403d94",
          "0x3E0C|switchdataD_00403e0c",
          "0x4010|switchdataD_00404010",
          "0x3FC0|PTR_caseD_0_00403fc0",
          "0x3F1C|switchdataD_00403f1c"
        ],
        "LoD/1.14a": [
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00004|",
          "0x3E78|switchdataD_00403e78",
          "0x3D94|switchdataD_00403d94",
          "0x3E0C|switchdataD_00403e0c",
          "0x4010|switchdataD_00404010",
          "0x3FC0|PTR_caseD_0_00403fc0",
          "0x3F1C|switchdataD_00403f1c"
        ],
        "LoD/1.14b": [
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00004|",
          "0x3E78|switchdataD_00403e78",
          "0x3D94|switchdataD_00403d94",
          "0x3E0C|switchdataD_00403e0c",
          "0x4010|switchdataD_00404010",
          "0x3FC0|PTR_caseD_0_00403fc0",
          "0x3F1C|switchdataD_00403f1c"
        ],
        "LoD/1.14c": [
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00004|",
          "0x3E78|switchdataD_00403e78",
          "0x3D94|switchdataD_00403d94",
          "0x3E0C|switchdataD_00403e0c",
          "0x4010|switchdataD_00404010",
          "0x3FC0|PTR_caseD_0_00403fc0",
          "0x3F1C|switchdataD_00403f1c"
        ],
        "LoD/1.14d": [
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00004|",
          "0x3E78|switchdataD_00403e78",
          "0x3D94|switchdataD_00403d94",
          "0x3E0C|switchdataD_00403e0c",
          "0x4010|switchdataD_00404010",
          "0x3FC0|PTR_caseD_0_00403fc0",
          "0x3F1C|switchdataD_00403f1c"
        ]
      }
    },
    "diablo ii.exe_InitializeBufferManager": {
      "addresses": {
        "LoD/1.07": "0x004032A5",
        "LoD/1.08": "0x004032A5",
        "LoD/1.09": "0x004032A5",
        "LoD/1.09b": "0x004032A5",
        "LoD/1.09d": "0x004032A5",
        "LoD/1.10": "0x004032A5",
        "LoD/1.11": "0x004032A5",
        "LoD/1.11b": "0x004032A5",
        "LoD/1.12a": "0x004032A5",
        "LoD/1.13c": "0x004032A5",
        "LoD/1.13d": "0x004032A5",
        "LoD/1.14a": "0x004032A5",
        "LoD/1.14b": "0x004032A5",
        "LoD/1.14c": "0x004032A5",
        "LoD/1.14d": "0x004032A5"
      },
      "rvas": {
        "LoD/1.07": "0x32A5",
        "LoD/1.08": "0x32A5",
        "LoD/1.09": "0x32A5",
        "LoD/1.09b": "0x32A5",
        "LoD/1.09d": "0x32A5",
        "LoD/1.10": "0x32A5",
        "LoD/1.11": "0x32A5",
        "LoD/1.11b": "0x32A5",
        "LoD/1.12a": "0x32A5",
        "LoD/1.13c": "0x32A5",
        "LoD/1.13d": "0x32A5",
        "LoD/1.14a": "0x32A5",
        "LoD/1.14b": "0x32A5",
        "LoD/1.14c": "0x32A5",
        "LoD/1.14d": "0x32A5"
      },
      "sizes": {
        "LoD/1.07": 62,
        "LoD/1.08": 62,
        "LoD/1.09": 62,
        "LoD/1.09b": 62,
        "LoD/1.09d": 62,
        "LoD/1.10": 62,
        "LoD/1.11": 62,
        "LoD/1.11b": 62,
        "LoD/1.12a": 62,
        "LoD/1.13c": 62,
        "LoD/1.13d": 62,
        "LoD/1.14a": 62,
        "LoD/1.14b": 62,
        "LoD/1.14c": 62,
        "LoD/1.14d": 62
      },
      "name": "InitializeBufferManager",
      "signature": "int InitializeBufferManager(void)",
      "calling_convention": "__stdcall",
      "return_type": "int",
      "comment": "Initialize buffer management system by allocating memory and setting up global state\n\nAlgorithm:\n1. Allocate 0x140 (320) bytes from process heap using HeapAlloc\n2. Verify allocation succeeded, return 0 on failure\n3. Initialize read index to 0 (g_dwBufferReadIndex)\n4. Initialize write index to 0 (g_dwBufferWriteIndex)\n5. Set base pointer to allocated buffer (g_pBufferBasePointer)\n6. Set element size to 0x10 (16) bytes (g_dwBufferElementSize)\n7. Return 1 for success\n\nParameters:\nNone - function takes no parameters\n\nReturns:\n1: Success - buffer manager initialized successfully\n0: Failure - heap allocation failed (out of memory)\n\nSpecial Cases:\nIf HeapAlloc returns NULL (out of memory), function returns immediately without initializing global state\nBuffer allocation size 0x140 (320 bytes) suggests space for 20 elements of 16 bytes each\n\nMagic Numbers Reference:\n0x140: Buffer allocation size in bytes (320 decimal)\n0x10: Element size in bytes (16 decimal)\n\nGlobal Buffer Manager Structure:\nOffset  Variable                Type     Description\n0x1003cdf4  g_dwBufferElementSize   uint     Element size (16 bytes)\n0x1003cdfc  g_pBufferBasePointer    void*    Base pointer to allocated buffer\n0x1003ce00  g_dwBufferReadIndex     uint     Current read index\n0x1003ce04  g_dwBufferWriteIndex    uint     Current write index\n0x1003ce08  g_pAllocatedBuffer      void*    Pointer returned by HeapAlloc\n0x1003ce0c  g_hHeap                 void*    Process heap handle",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:9714d3ad2deea30ac943f1376fae33d4",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "9714d3ad2deea30ac943f1376fae33d4",
        "CFG": "e5b8e3675e647a57b186af1caa74bfb1",
        "PRO": "a1b9fb36e2d9d764f2ab02021d9a5d11",
        "CAL": null,
        "CON": null,
        "APS": null
      },
      "callees": {
        "LoD/1.07": [
          "HeapAlloc|0x28"
        ],
        "LoD/1.08": [
          "HeapAlloc|0x28"
        ],
        "LoD/1.09": [
          "HeapAlloc|0x28"
        ],
        "LoD/1.09b": [
          "HeapAlloc|0x28"
        ],
        "LoD/1.09d": [
          "HeapAlloc|0x28"
        ],
        "LoD/1.10": [
          "HeapAlloc|0x28"
        ],
        "LoD/1.11": [
          "HeapAlloc|0x28"
        ],
        "LoD/1.11b": [
          "HeapAlloc|0x28"
        ],
        "LoD/1.12a": [
          "HeapAlloc|0x28"
        ],
        "LoD/1.13c": [
          "HeapAlloc|0x28"
        ],
        "LoD/1.13d": [
          "HeapAlloc|0x28"
        ],
        "LoD/1.14a": [
          "HeapAlloc|0x28"
        ],
        "LoD/1.14b": [
          "HeapAlloc|0x28"
        ],
        "LoD/1.14c": [
          "HeapAlloc|0x28"
        ],
        "LoD/1.14d": [
          "HeapAlloc|0x28"
        ]
      },
      "callers": {
        "LoD/1.07": [
          "InitializeDllHeapAndResources|0x402541"
        ],
        "LoD/1.08": [
          "InitializeDllHeapAndResources|0x402541"
        ],
        "LoD/1.09": [
          "InitializeDllHeapAndResources|0x402541"
        ],
        "LoD/1.09b": [
          "InitializeDllHeapAndResources|0x402541"
        ],
        "LoD/1.09d": [
          "InitializeDllHeapAndResources|0x402541"
        ],
        "LoD/1.10": [
          "InitializeDllHeapAndResources|0x402541"
        ],
        "LoD/1.11": [
          "InitializeDllHeapAndResources|0x402541"
        ],
        "LoD/1.11b": [
          "InitializeDllHeapAndResources|0x402541"
        ],
        "LoD/1.12a": [
          "InitializeDllHeapAndResources|0x402541"
        ],
        "LoD/1.13c": [
          "InitializeDllHeapAndResources|0x402541"
        ],
        "LoD/1.13d": [
          "InitializeDllHeapAndResources|0x402541"
        ],
        "LoD/1.14a": [
          "InitializeDllHeapAndResources|0x402541"
        ],
        "LoD/1.14b": [
          "InitializeDllHeapAndResources|0x402541"
        ],
        "LoD/1.14c": [
          "InitializeDllHeapAndResources|0x402541"
        ],
        "LoD/1.14d": [
          "InitializeDllHeapAndResources|0x402541"
        ]
      },
      "instruction_counts": {
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
        "LoD/1.13d": 15,
        "LoD/1.14a": 15,
        "LoD/1.14b": 15,
        "LoD/1.14c": 15,
        "LoD/1.14d": 15
      },
      "stack_frame_sizes": {
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
        "LoD/1.13d": 4,
        "LoD/1.14a": 4,
        "LoD/1.14b": 4,
        "LoD/1.14c": 4,
        "LoD/1.14d": 4
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
        "LoD/1.13d": 3,
        "LoD/1.14a": 3,
        "LoD/1.14b": 3,
        "LoD/1.14c": 3,
        "LoD/1.14d": 3
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
        "LoD/1.13d": 0,
        "LoD/1.14a": 0,
        "LoD/1.14b": 0,
        "LoD/1.14c": 0,
        "LoD/1.14d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "9714d3ad2deea30ac943f1376fae33d4",
        "LoD/1.08": "9714d3ad2deea30ac943f1376fae33d4",
        "LoD/1.09": "9714d3ad2deea30ac943f1376fae33d4",
        "LoD/1.09b": "9714d3ad2deea30ac943f1376fae33d4",
        "LoD/1.09d": "9714d3ad2deea30ac943f1376fae33d4",
        "LoD/1.10": "9714d3ad2deea30ac943f1376fae33d4",
        "LoD/1.11": "9714d3ad2deea30ac943f1376fae33d4",
        "LoD/1.11b": "9714d3ad2deea30ac943f1376fae33d4",
        "LoD/1.12a": "9714d3ad2deea30ac943f1376fae33d4",
        "LoD/1.13c": "9714d3ad2deea30ac943f1376fae33d4",
        "LoD/1.13d": "9714d3ad2deea30ac943f1376fae33d4",
        "LoD/1.14a": "9714d3ad2deea30ac943f1376fae33d4",
        "LoD/1.14b": "9714d3ad2deea30ac943f1376fae33d4",
        "LoD/1.14c": "9714d3ad2deea30ac943f1376fae33d4",
        "LoD/1.14d": "9714d3ad2deea30ac943f1376fae33d4"
      },
      "constants": {
        "LoD/1.07": [
          320
        ],
        "LoD/1.08": [
          320
        ],
        "LoD/1.09": [
          320
        ],
        "LoD/1.09b": [
          320
        ],
        "LoD/1.09d": [
          320
        ],
        "LoD/1.10": [
          320
        ],
        "LoD/1.11": [
          320
        ],
        "LoD/1.11b": [
          320
        ],
        "LoD/1.12a": [
          320
        ],
        "LoD/1.13c": [
          320
        ],
        "LoD/1.13d": [
          320
        ],
        "LoD/1.14a": [
          320
        ],
        "LoD/1.14b": [
          320
        ],
        "LoD/1.14c": [
          320
        ],
        "LoD/1.14d": [
          320
        ]
      },
      "globals": {
        "LoD/1.07": [
          "0x6674|g_hHeapHandle",
          "0x509C|PTR_HeapAlloc_0040509c",
          "0x6670|g_pDescriptorArray",
          "0x6668|g_dwBufferReadIndex",
          "0x666C|g_nDescriptorCount",
          "0x6664|g_pBufferBasePointer",
          "0x665C|g_dwBufferElementSize"
        ],
        "LoD/1.08": [
          "0x6674|g_hHeapHandle",
          "0x509C|PTR_HeapAlloc_0040509c",
          "0x6670|g_pDescriptorArray",
          "0x6668|g_dwBufferReadIndex",
          "0x666C|g_nDescriptorCount",
          "0x6664|g_pBufferBasePointer",
          "0x665C|g_dwBufferElementSize"
        ],
        "LoD/1.09": [
          "0x6674|g_hHeapHandle",
          "0x509C|PTR_HeapAlloc_0040509c",
          "0x6670|g_pDescriptorArray",
          "0x6668|g_dwBufferReadIndex",
          "0x666C|g_nDescriptorCount",
          "0x6664|g_pBufferBasePointer",
          "0x665C|g_dwBufferElementSize"
        ],
        "LoD/1.09b": [
          "0x6674|g_hHeapHandle",
          "0x509C|PTR_HeapAlloc_0040509c",
          "0x6670|g_pDescriptorArray",
          "0x6668|g_dwBufferReadIndex",
          "0x666C|g_nDescriptorCount",
          "0x6664|g_pBufferBasePointer",
          "0x665C|g_dwBufferElementSize"
        ],
        "LoD/1.09d": [
          "0x6674|g_hHeapHandle",
          "0x509C|PTR_HeapAlloc_0040509c",
          "0x6670|g_pDescriptorArray",
          "0x6668|g_dwBufferReadIndex",
          "0x666C|g_nDescriptorCount",
          "0x6664|g_pBufferBasePointer",
          "0x665C|g_dwBufferElementSize"
        ],
        "LoD/1.10": [
          "0x6674|g_hHeap",
          "0x509C|PTR_HeapAlloc_0040509c",
          "0x6670|g_pDescriptorArray",
          "0x6668|g_dwBufferReadIndex",
          "0x666C|g_nDescriptorCount",
          "0x6664|g_pBufferBasePointer",
          "0x665C|g_dwBufferElementSize"
        ],
        "LoD/1.11": [
          "0x6674|g_hHeapHandle",
          "0x509C|PTR_HeapAlloc_0040509c",
          "0x6670|g_pDescriptorArray",
          "0x6668|g_dwBufferReadIndex",
          "0x666C|g_nDescriptorCount",
          "0x6664|g_pBufferBasePointer",
          "0x665C|g_dwBufferElementSize"
        ],
        "LoD/1.11b": [
          "0x6674|g_hHeapHandle",
          "0x509C|PTR_HeapAlloc_0040509c",
          "0x6670|g_pDescriptorArray",
          "0x6668|g_dwBufferReadIndex",
          "0x666C|g_nDescriptorCount",
          "0x6664|g_pBufferBasePointer",
          "0x665C|g_dwBufferElementSize"
        ],
        "LoD/1.12a": [
          "0x6674|g_hHeapHandle",
          "0x509C|PTR_HeapAlloc_0040509c",
          "0x6670|g_pDescriptorArray",
          "0x6668|g_dwBufferReadIndex",
          "0x666C|g_nDescriptorCount",
          "0x6664|g_pBufferBasePointer",
          "0x665C|g_dwBufferElementSize"
        ],
        "LoD/1.13c": [
          "0x6674|g_hHeapHandle",
          "0x509C|PTR_HeapAlloc_0040509c",
          "0x6670|g_pDescriptorArray",
          "0x6668|g_dwBufferReadIndex",
          "0x666C|g_nDescriptorCount",
          "0x6664|g_pBufferBasePointer",
          "0x665C|g_dwBufferElementSize"
        ],
        "LoD/1.13d": [
          "0x6674|g_hHeapHandle",
          "0x509C|PTR_HeapAlloc_0040509c",
          "0x6670|g_pDescriptorArray",
          "0x6668|g_dwBufferReadIndex",
          "0x666C|g_nDescriptorCount",
          "0x6664|g_pBufferBasePointer",
          "0x665C|g_dwBufferElementSize"
        ],
        "LoD/1.14a": [
          "0x6674|g_hHeapHandle",
          "0x509C|PTR_HeapAlloc_0040509c",
          "0x6670|g_pDescriptorArray",
          "0x6668|g_dwBufferReadIndex",
          "0x666C|g_nDescriptorCount",
          "0x6664|g_pBufferBasePointer",
          "0x665C|g_dwBufferElementSize"
        ],
        "LoD/1.14b": [
          "0x6674|g_hHeapHandle",
          "0x509C|PTR_HeapAlloc_0040509c",
          "0x6670|g_pDescriptorArray",
          "0x6668|g_dwBufferReadIndex",
          "0x666C|g_nDescriptorCount",
          "0x6664|g_pBufferBasePointer",
          "0x665C|g_dwBufferElementSize"
        ],
        "LoD/1.14c": [
          "0x6674|g_hHeapHandle",
          "0x509C|PTR_HeapAlloc_0040509c",
          "0x6670|g_pDescriptorArray",
          "0x6668|g_dwBufferReadIndex",
          "0x666C|g_nDescriptorCount",
          "0x6664|g_pBufferBasePointer",
          "0x665C|g_dwBufferElementSize"
        ],
        "LoD/1.14d": [
          "0x6674|g_hHeapHandle",
          "0x509C|PTR_HeapAlloc_0040509c",
          "0x6670|g_pDescriptorArray",
          "0x6668|g_dwBufferReadIndex",
          "0x666C|g_nDescriptorCount",
          "0x6664|g_pBufferBasePointer",
          "0x665C|g_dwBufferElementSize"
        ]
      }
    },
    "diablo ii.exe_FindMemoryDescriptorByAddress": {
      "addresses": {
        "LoD/1.07": "0x004032E3",
        "LoD/1.08": "0x004032E3",
        "LoD/1.09": "0x004032E3",
        "LoD/1.09b": "0x004032E3",
        "LoD/1.09d": "0x004032E3",
        "LoD/1.10": "0x004032E3",
        "LoD/1.11": "0x004032E3",
        "LoD/1.11b": "0x004032E3",
        "LoD/1.12a": "0x004032E3",
        "LoD/1.13c": "0x004032E3",
        "LoD/1.13d": "0x004032E3",
        "LoD/1.14a": "0x004032E3",
        "LoD/1.14b": "0x004032E3",
        "LoD/1.14c": "0x004032E3",
        "LoD/1.14d": "0x004032E3"
      },
      "rvas": {
        "LoD/1.07": "0x32E3",
        "LoD/1.08": "0x32E3",
        "LoD/1.09": "0x32E3",
        "LoD/1.09b": "0x32E3",
        "LoD/1.09d": "0x32E3",
        "LoD/1.10": "0x32E3",
        "LoD/1.11": "0x32E3",
        "LoD/1.11b": "0x32E3",
        "LoD/1.12a": "0x32E3",
        "LoD/1.13c": "0x32E3",
        "LoD/1.13d": "0x32E3",
        "LoD/1.14a": "0x32E3",
        "LoD/1.14b": "0x32E3",
        "LoD/1.14c": "0x32E3",
        "LoD/1.14d": "0x32E3"
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
        "LoD/1.13d": 43,
        "LoD/1.14a": 43,
        "LoD/1.14b": 43,
        "LoD/1.14c": 43,
        "LoD/1.14d": 43
      },
      "name": "FindMemoryDescriptorByAddress",
      "signature": "MemoryDescriptor * FindMemoryDescriptorByAddress(uint dwTargetAddress)",
      "calling_convention": "__cdecl",
      "return_type": "MemoryDescriptor *",
      "comment": "Searches for a MemoryDescriptor entry containing a target address within a 1MB range.\n\nAlgorithm:\n1. Initialize iterator to start of MemoryDescriptor array (PTR_1003ce08)\n2. Calculate array end boundary using count (INT_1003ce04) * 20-byte element size\n3. Loop through array until end boundary reached:\n   a. Calculate address difference from target to descriptor base address (offset 0xc)\n   b. Check if difference is within 0x100000 (1MB) range using unsigned comparison\n   c. If match found, return pointer to current MemoryDescriptor\n   d. Otherwise advance iterator by 20 bytes (0x14) to next descriptor\n4. Return 0 if no matching descriptor found\n\nParameters:\n- nTargetAddress (int): Target address to locate within memory descriptors\n\nReturns:\n- MemoryDescriptor *: Pointer to descriptor containing target address\n- 0: No descriptor found containing target address within 1MB range\n\nSpecial Cases:\n- Empty array (count = 0): Returns 0 immediately\n- Target address beyond all descriptors: Returns 0 after full iteration\n\nMagic Numbers Reference:\n- 0x14 (20): MemoryDescriptor structure size in bytes\n- 0xc (12): Offset to base address field within MemoryDescriptor\n- 0x100000 (1048576): Maximum address range tolerance (1MB)\n\nStructure Layout:\nOffset | Size | Field Name       | Type | Description\n-------|------|------------------|------|------------------\n+0x00  | ?    | [Unknown fields] | ?    | Structure prefix\n+0x0c  | 4    | dwBaseAddress    | uint | Base memory address\n+0x10  | ?    | [Unknown fields] | ?    | Additional data\nTotal: 20 bytes (0x14)",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:2a0dd1f395da0f8e13609d337843c676",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "2a0dd1f395da0f8e13609d337843c676",
        "CFG": "1a3f7cfa3845a97e1009681b130f0d18",
        "PRO": "ea54e4b4b6d11783843fb018aafdb15a",
        "CAL": null,
        "CON": null,
        "APS": null
      },
      "callers": {
        "LoD/1.07": [
          "SmartFree|0x402DCE"
        ],
        "LoD/1.08": [
          "SmartFree|0x402DCE"
        ],
        "LoD/1.09": [
          "SmartFree|0x402DCE"
        ],
        "LoD/1.09b": [
          "SmartFree|0x402DCE"
        ],
        "LoD/1.09d": [
          "SmartFree|0x402DCE"
        ],
        "LoD/1.10": [
          "SmartFree|0x402DCE"
        ],
        "LoD/1.11": [
          "SmartFree|0x402DCE"
        ],
        "LoD/1.11b": [
          "SmartFree|0x402DCE"
        ],
        "LoD/1.12a": [
          "SmartFree|0x402DCE"
        ],
        "LoD/1.13c": [
          "SmartFree|0x402DCE"
        ],
        "LoD/1.13d": [
          "SmartFree|0x402DCE"
        ],
        "LoD/1.14a": [
          "SmartFree|0x402DCE"
        ],
        "LoD/1.14b": [
          "SmartFree|0x402DCE"
        ],
        "LoD/1.14c": [
          "SmartFree|0x402DCE"
        ],
        "LoD/1.14d": [
          "SmartFree|0x402DCE"
        ]
      },
      "instruction_counts": {
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
        "LoD/1.13d": 14,
        "LoD/1.14a": 14,
        "LoD/1.14b": 14,
        "LoD/1.14c": 14,
        "LoD/1.14d": 14
      },
      "stack_frame_sizes": {
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
        "LoD/1.13d": 8,
        "LoD/1.14a": 8,
        "LoD/1.14b": 8,
        "LoD/1.14c": 8,
        "LoD/1.14d": 8
      },
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
        "LoD/1.13d": 6,
        "LoD/1.14a": 6,
        "LoD/1.14b": 6,
        "LoD/1.14c": 6,
        "LoD/1.14d": 6
      },
      "loop_counts": {
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
        "LoD/1.13d": 1,
        "LoD/1.14a": 1,
        "LoD/1.14b": 1,
        "LoD/1.14c": 1,
        "LoD/1.14d": 1
      },
      "mnemonic_hashes": {
        "LoD/1.07": "2a0dd1f395da0f8e13609d337843c676",
        "LoD/1.08": "2a0dd1f395da0f8e13609d337843c676",
        "LoD/1.09": "2a0dd1f395da0f8e13609d337843c676",
        "LoD/1.09b": "2a0dd1f395da0f8e13609d337843c676",
        "LoD/1.09d": "2a0dd1f395da0f8e13609d337843c676",
        "LoD/1.10": "2a0dd1f395da0f8e13609d337843c676",
        "LoD/1.11": "2a0dd1f395da0f8e13609d337843c676",
        "LoD/1.11b": "2a0dd1f395da0f8e13609d337843c676",
        "LoD/1.12a": "2a0dd1f395da0f8e13609d337843c676",
        "LoD/1.13c": "2a0dd1f395da0f8e13609d337843c676",
        "LoD/1.13d": "2a0dd1f395da0f8e13609d337843c676",
        "LoD/1.14a": "2a0dd1f395da0f8e13609d337843c676",
        "LoD/1.14b": "2a0dd1f395da0f8e13609d337843c676",
        "LoD/1.14c": "2a0dd1f395da0f8e13609d337843c676",
        "LoD/1.14d": "2a0dd1f395da0f8e13609d337843c676"
      },
      "constants": {
        "LoD/1.07": [
          1048576
        ],
        "LoD/1.08": [
          1048576
        ],
        "LoD/1.09": [
          1048576
        ],
        "LoD/1.09b": [
          1048576
        ],
        "LoD/1.09d": [
          1048576
        ],
        "LoD/1.10": [
          1048576
        ],
        "LoD/1.11": [
          1048576
        ],
        "LoD/1.11b": [
          1048576
        ],
        "LoD/1.12a": [
          1048576
        ],
        "LoD/1.13c": [
          1048576
        ],
        "LoD/1.13d": [
          1048576
        ],
        "LoD/1.14a": [
          1048576
        ],
        "LoD/1.14b": [
          1048576
        ],
        "LoD/1.14c": [
          1048576
        ],
        "LoD/1.14d": [
          1048576
        ]
      },
      "globals": {
        "LoD/1.07": [
          "0x666C|g_nDescriptorCount",
          "0x6670|g_pDescriptorArray",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.08": [
          "0x666C|g_nDescriptorCount",
          "0x6670|g_pDescriptorArray",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.09": [
          "0x666C|g_nDescriptorCount",
          "0x6670|g_pDescriptorArray",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.09b": [
          "0x666C|g_nDescriptorCount",
          "0x6670|g_pDescriptorArray",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.09d": [
          "0x666C|g_nDescriptorCount",
          "0x6670|g_pDescriptorArray",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.10": [
          "0x666C|g_nDescriptorCount",
          "0x6670|g_pDescriptorArray",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.11": [
          "0x666C|g_nDescriptorCount",
          "0x6670|g_pDescriptorArray",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.11b": [
          "0x666C|g_nDescriptorCount",
          "0x6670|g_pDescriptorArray",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.12a": [
          "0x666C|g_nDescriptorCount",
          "0x6670|g_pDescriptorArray",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.13c": [
          "0x666C|g_nDescriptorCount",
          "0x6670|g_pDescriptorArray",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.13d": [
          "0x666C|g_nDescriptorCount",
          "0x6670|g_pDescriptorArray",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.14a": [
          "0x666C|g_nDescriptorCount",
          "0x6670|g_pDescriptorArray",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.14b": [
          "0x666C|g_nDescriptorCount",
          "0x6670|g_pDescriptorArray",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.14c": [
          "0x666C|g_nDescriptorCount",
          "0x6670|g_pDescriptorArray",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.14d": [
          "0x666C|g_nDescriptorCount",
          "0x6670|g_pDescriptorArray",
          "0xFFFFFFFFFFC00004|"
        ]
      }
    },
    "diablo ii.exe_FreeMemoryBlockWithLinkedListC": {
      "addresses": {
        "LoD/1.07": "0x0040330E",
        "LoD/1.08": "0x0040330E",
        "LoD/1.09": "0x0040330E",
        "LoD/1.09b": "0x0040330E",
        "LoD/1.09d": "0x0040330E",
        "LoD/1.10": "0x0040330E",
        "LoD/1.11": "0x0040330E",
        "LoD/1.11b": "0x0040330E",
        "LoD/1.12a": "0x0040330E",
        "LoD/1.13c": "0x0040330E",
        "LoD/1.13d": "0x0040330E",
        "LoD/1.14a": "0x0040330E",
        "LoD/1.14b": "0x0040330E",
        "LoD/1.14c": "0x0040330E",
        "LoD/1.14d": "0x0040330E"
      },
      "rvas": {
        "LoD/1.07": "0x330E",
        "LoD/1.08": "0x330E",
        "LoD/1.09": "0x330E",
        "LoD/1.09b": "0x330E",
        "LoD/1.09d": "0x330E",
        "LoD/1.10": "0x330E",
        "LoD/1.11": "0x330E",
        "LoD/1.11b": "0x330E",
        "LoD/1.12a": "0x330E",
        "LoD/1.13c": "0x330E",
        "LoD/1.13d": "0x330E",
        "LoD/1.14a": "0x330E",
        "LoD/1.14b": "0x330E",
        "LoD/1.14c": "0x330E",
        "LoD/1.14d": "0x330E"
      },
      "sizes": {
        "LoD/1.07": 811,
        "LoD/1.08": 811,
        "LoD/1.09": 811,
        "LoD/1.09b": 811,
        "LoD/1.09d": 811,
        "LoD/1.10": 811,
        "LoD/1.11": 811,
        "LoD/1.11b": 811,
        "LoD/1.12a": 811,
        "LoD/1.13c": 811,
        "LoD/1.13d": 811,
        "LoD/1.14a": 811,
        "LoD/1.14b": 811,
        "LoD/1.14c": 811,
        "LoD/1.14d": 811
      },
      "name": "FreeMemoryBlockWithLinkedListCleanup",
      "signature": "void FreeMemoryBlockWithLinkedListCleanup(MemoryDescriptor * pDescriptor, uint dwBlockAddress)",
      "calling_convention": "__cdecl",
      "return_type": "void",
      "comment": "Frees a memory block and performs associated linked list cleanup and bit mask management.\n\nAlgorithm:\n1. Extract memory descriptor base address from pDescriptor[4]\n2. Get original block size from memory header at (dwBlockAddress - 4)\n3. Calculate slot index using (dwBlockAddress - pDescriptor[3]) >> 15\n4. Get previous block info from (dwBlockAddress - 8)\n5. Adjust block size by subtracting 1 from original size\n6. Calculate free list head pointer using slot index * 516 + 324 + descriptor base\n7. Read current block info from adjusted position\n8. If current block is not marked as allocated (bit 0 clear):\n   a. Extract block index from bits 4-31, clamp to maximum 63\n   b. If linked list pointers are equal (empty list):\n      - Clear corresponding bit in bit mask arrays at offsets 0x44/0xC4\n      - Decrement reference counter at descriptor base + block index + 4\n      - If counter reaches 0, clear bit in main descriptor bit mask\n   c. Update linked list forward/backward pointers\n   d. Add current block size to adjusted size\n9. Calculate new block index from adjusted size, clamp to maximum 63\n10. If previous block exists and is not allocated:\n   a. Extract previous block index, clamp to maximum 63\n   b. Add previous block size to total adjusted size\n   c. Recalculate new block index, clamp to maximum 63\n   d. If indices differ, perform same bit mask and linked list operations as step 8\n   e. Update linked list pointers for previous block\n11. If conditions require re-linking or previous block was allocated:\n   a. Link current block into free list at new block index\n   b. Update forward and backward pointers in linked list\n   c. If linking into empty list:\n      - Increment reference counter\n      - Set corresponding bit in bit mask arrays\n      - If counter was 0, set bit in main descriptor bit mask\n12. Store final adjusted size in block header and size field\n13. Decrement free list head reference count\n14. If reference count reaches 0 and global descriptor exists:\n   a. Free virtual memory using VirtualFree with 0x8000 size and 0x4000 type\n   b. Update global bit masks and counters\n   c. If all bits cleared (0xFFFFFFFF), perform full cleanup:\n      - Free entire virtual memory region\n      - Free heap memory for descriptor\n      - Compact descriptor array using OptimizedMemoryMove\n      - Update global counters and pointers\n      - Adjust function parameter pointer if necessary\n\nParameters:\npDescriptor (MemoryDescriptor *): Pointer to memory descriptor containing virtual memory base, heap memory base, and management data\ndwBlockAddress (uint): Address within allocated memory block to be freed\n\nReturns:\nvoid\n\nSpecial Cases:\n- Block index clamped to maximum 63 (0x3F) to prevent array bounds overflow\n- Bit operations split between two 32-bit masks for indices 0-31 and 32-63\n- Empty linked lists trigger bit mask updates and reference counting\n- Global cleanup only occurs when all blocks in a descriptor are freed\n\nMagic Numbers Reference:\n0x0F: Shift amount for 32KB (0x8000) block alignment calculation\n0x204: Size of free list management structure (516 bytes)\n0x144: Offset to free list head array within descriptor (324 bytes)\n0x44: Offset to lower 32-bit mask array (68 bytes)\n0xC4: Offset to upper 32-bit mask array (196 bytes)\n0x43: Offset to reference counter (67 bytes)\n0x20: Boundary between lower and upper bit mask arrays\n0x80000000: Base bit pattern for mask calculations\n0x8000: Virtual memory allocation unit size (32KB)\n0x4000: VirtualFree MEM_DECOMMIT flag\n0x1F: Bit position mask for 32-bit operations\n0x3F: Maximum block index (63)\n0xFFFFFFFF: All bits set condition for complete cleanup\n\nStructure Layout:\nMemoryDescriptor (20 bytes):\nOffset | Size | Field Name    | Type    | Description\n-------|------|---------------|---------|--------------------\n0x00   | 4    | pVirtualMemory| void *  | Base virtual memory address\n0x04   | 4    | pHeapMemory   | void *  | Heap-allocated management data\n0x08   | 4    | dwReserved1   | uint    | Reserved field 1\n0x0C   | 4    | dwReserved2   | uint    | Reserved field 2\n0x10   | 4    | dwReserved3   | uint    | Reserved field 3\n\nBlock Header Layout (8 bytes before user data):\nOffset | Size | Description\n-------|------|------------------------------------------\n-8     | 4    | Previous block size and allocation flags\n-4     | 4    | Current block size and allocation flags\n\nFree List Node Layout (12 bytes):\nOffset | Size | Description\n-------|------|---------------------------\n0x00   | 4    | Block size with flags\n0x04   | 4    | Forward pointer to next free block\n0x08   | 4    | Backward pointer to previous free block\n\nBit Mask Management:\n- Two 32-bit arrays handle 64 possible block size indices\n- Array at offset 0x44: handles indices 0-31\n- Array at offset 0xC4: handles indices 32-63\n- Each bit represents whether blocks of that size index exist\n- Main descriptor masks track which descriptors have free blocks",
      "name_source": "LoD/1.07",
      "method": "CAL",
      "index": "CAL:e3ec679679a02264f139ac30186a970f",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "9bfd98dbbd3e5d7edb553bd7666739e4",
        "CFG": "b84f01dedd456598d3cbe7e053845bd4",
        "PRO": "00e2fa60d81eb194d407fbc1353f620d",
        "CAL": "e3ec679679a02264f139ac30186a970f",
        "CON": "f16898611ac5b33d9ecaf7330b5442fc",
        "APS": null
      },
      "callees": {
        "LoD/1.07": [
          "HeapFree|0x20",
          "VirtualFree|0x1F",
          "OptimizedMemoryMove|0x403D30"
        ],
        "LoD/1.08": [
          "HeapFree|0x20",
          "OptimizedMemoryMove|0x403D30",
          "VirtualFree|0x1F"
        ],
        "LoD/1.09": [
          "OptimizedMemoryMove|0x403D30",
          "HeapFree|0x20",
          "VirtualFree|0x1F"
        ],
        "LoD/1.09b": [
          "VirtualFree|0x1F",
          "HeapFree|0x20",
          "OptimizedMemoryMove|0x403D30"
        ],
        "LoD/1.09d": [
          "HeapFree|0x20",
          "OptimizedMemoryMove|0x403D30",
          "VirtualFree|0x1F"
        ],
        "LoD/1.10": [
          "HeapFree|0x20",
          "VirtualFree|0x1F",
          "OptimizedMemoryMove|0x403D30"
        ],
        "LoD/1.11": [
          "VirtualFree|0x1F",
          "HeapFree|0x20",
          "OptimizedMemoryMove|0x403D30"
        ],
        "LoD/1.11b": [
          "HeapFree|0x20",
          "VirtualFree|0x1F",
          "OptimizedMemoryMove|0x403D30"
        ],
        "LoD/1.12a": [
          "HeapFree|0x20",
          "VirtualFree|0x1F",
          "OptimizedMemoryMove|0x403D30"
        ],
        "LoD/1.13c": [
          "HeapFree|0x20",
          "OptimizedMemoryMove|0x403D30",
          "VirtualFree|0x1F"
        ],
        "LoD/1.13d": [
          "VirtualFree|0x1F",
          "HeapFree|0x20",
          "OptimizedMemoryMove|0x403D30"
        ],
        "LoD/1.14a": [
          "OptimizedMemoryMove|0x403D30",
          "HeapFree|0x20",
          "VirtualFree|0x1F"
        ],
        "LoD/1.14b": [
          "HeapFree|0x20",
          "VirtualFree|0x1F",
          "OptimizedMemoryMove|0x403D30"
        ],
        "LoD/1.14c": [
          "VirtualFree|0x1F",
          "OptimizedMemoryMove|0x403D30",
          "HeapFree|0x20"
        ],
        "LoD/1.14d": [
          "VirtualFree|0x1F",
          "HeapFree|0x20",
          "OptimizedMemoryMove|0x403D30"
        ]
      },
      "callers": {
        "LoD/1.07": [
          "SmartFree|0x402DCE"
        ],
        "LoD/1.08": [
          "SmartFree|0x402DCE"
        ],
        "LoD/1.09": [
          "SmartFree|0x402DCE"
        ],
        "LoD/1.09b": [
          "SmartFree|0x402DCE"
        ],
        "LoD/1.09d": [
          "SmartFree|0x402DCE"
        ],
        "LoD/1.10": [
          "SmartFree|0x402DCE"
        ],
        "LoD/1.11": [
          "SmartFree|0x402DCE"
        ],
        "LoD/1.11b": [
          "SmartFree|0x402DCE"
        ],
        "LoD/1.12a": [
          "SmartFree|0x402DCE"
        ],
        "LoD/1.13c": [
          "SmartFree|0x402DCE"
        ],
        "LoD/1.13d": [
          "SmartFree|0x402DCE"
        ],
        "LoD/1.14a": [
          "SmartFree|0x402DCE"
        ],
        "LoD/1.14b": [
          "SmartFree|0x402DCE"
        ],
        "LoD/1.14c": [
          "SmartFree|0x402DCE"
        ],
        "LoD/1.14d": [
          "SmartFree|0x402DCE"
        ]
      },
      "instruction_counts": {
        "LoD/1.07": 264,
        "LoD/1.08": 264,
        "LoD/1.09": 264,
        "LoD/1.09b": 264,
        "LoD/1.09d": 264,
        "LoD/1.10": 264,
        "LoD/1.11": 264,
        "LoD/1.11b": 264,
        "LoD/1.12a": 264,
        "LoD/1.13c": 264,
        "LoD/1.13d": 264,
        "LoD/1.14a": 264,
        "LoD/1.14b": 264,
        "LoD/1.14c": 264,
        "LoD/1.14d": 264
      },
      "stack_frame_sizes": {
        "LoD/1.07": 36,
        "LoD/1.08": 36,
        "LoD/1.09": 36,
        "LoD/1.09b": 36,
        "LoD/1.09d": 36,
        "LoD/1.10": 36,
        "LoD/1.11": 36,
        "LoD/1.11b": 36,
        "LoD/1.12a": 36,
        "LoD/1.13c": 36,
        "LoD/1.13d": 36,
        "LoD/1.14a": 36,
        "LoD/1.14b": 36,
        "LoD/1.14c": 36,
        "LoD/1.14d": 36
      },
      "basic_block_counts": {
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
        "LoD/1.13d": 48,
        "LoD/1.14a": 48,
        "LoD/1.14b": 48,
        "LoD/1.14c": 48,
        "LoD/1.14d": 48
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
        "LoD/1.13d": 0,
        "LoD/1.14a": 0,
        "LoD/1.14b": 0,
        "LoD/1.14c": 0,
        "LoD/1.14d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "9bfd98dbbd3e5d7edb553bd7666739e4",
        "LoD/1.08": "9bfd98dbbd3e5d7edb553bd7666739e4",
        "LoD/1.09": "9bfd98dbbd3e5d7edb553bd7666739e4",
        "LoD/1.09b": "9bfd98dbbd3e5d7edb553bd7666739e4",
        "LoD/1.09d": "9bfd98dbbd3e5d7edb553bd7666739e4",
        "LoD/1.10": "9bfd98dbbd3e5d7edb553bd7666739e4",
        "LoD/1.11": "9bfd98dbbd3e5d7edb553bd7666739e4",
        "LoD/1.11b": "9bfd98dbbd3e5d7edb553bd7666739e4",
        "LoD/1.12a": "9bfd98dbbd3e5d7edb553bd7666739e4",
        "LoD/1.13c": "9bfd98dbbd3e5d7edb553bd7666739e4",
        "LoD/1.13d": "9bfd98dbbd3e5d7edb553bd7666739e4",
        "LoD/1.14a": "9bfd98dbbd3e5d7edb553bd7666739e4",
        "LoD/1.14b": "9bfd98dbbd3e5d7edb553bd7666739e4",
        "LoD/1.14c": "9bfd98dbbd3e5d7edb553bd7666739e4",
        "LoD/1.14d": "9bfd98dbbd3e5d7edb553bd7666739e4"
      },
      "constants": {
        "LoD/1.07": [
          324,
          516,
          16384,
          32768
        ],
        "LoD/1.08": [
          324,
          516,
          16384,
          32768
        ],
        "LoD/1.09": [
          324,
          516,
          16384,
          32768
        ],
        "LoD/1.09b": [
          324,
          516,
          16384,
          32768
        ],
        "LoD/1.09d": [
          324,
          516,
          16384,
          32768
        ],
        "LoD/1.10": [
          324,
          516,
          16384,
          32768
        ],
        "LoD/1.11": [
          324,
          516,
          16384,
          32768
        ],
        "LoD/1.11b": [
          324,
          516,
          16384,
          32768
        ],
        "LoD/1.12a": [
          324,
          516,
          16384,
          32768
        ],
        "LoD/1.13c": [
          324,
          516,
          16384,
          32768
        ],
        "LoD/1.13d": [
          324,
          516,
          16384,
          32768
        ],
        "LoD/1.14a": [
          324,
          516,
          16384,
          32768
        ],
        "LoD/1.14b": [
          324,
          516,
          16384,
          32768
        ],
        "LoD/1.14c": [
          324,
          516,
          16384,
          32768
        ],
        "LoD/1.14d": [
          324,
          516,
          16384,
          32768
        ]
      },
      "globals": {
        "LoD/1.07": [
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFBFFFF8|",
          "0xFFFFFFFFFFBFFFF0|",
          "0xFFFFFFFFFFBFFFEC|",
          "0xFFFFFFFFFFBFFFF4|",
          "0xFFFFFFFFFFBFFFE8|",
          "0xFFFFFFFFFFC0000B|",
          "0x6668|g_dwBufferReadIndex",
          "0x6660|g_dwCurrentPoolIndex"
        ],
        "LoD/1.08": [
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFBFFFF8|",
          "0xFFFFFFFFFFBFFFF0|",
          "0xFFFFFFFFFFBFFFEC|",
          "0xFFFFFFFFFFBFFFF4|",
          "0xFFFFFFFFFFBFFFE8|",
          "0xFFFFFFFFFFC0000B|",
          "0x6668|g_dwBufferReadIndex",
          "0x6660|g_dwCurrentPoolIndex"
        ],
        "LoD/1.09": [
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFBFFFF8|",
          "0xFFFFFFFFFFBFFFF0|",
          "0xFFFFFFFFFFBFFFEC|",
          "0xFFFFFFFFFFBFFFF4|",
          "0xFFFFFFFFFFBFFFE8|",
          "0xFFFFFFFFFFC0000B|",
          "0x6668|g_dwBufferReadIndex",
          "0x6660|g_dwCurrentPoolIndex"
        ],
        "LoD/1.09b": [
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFBFFFF8|",
          "0xFFFFFFFFFFBFFFF0|",
          "0xFFFFFFFFFFBFFFEC|",
          "0xFFFFFFFFFFBFFFF4|",
          "0xFFFFFFFFFFBFFFE8|",
          "0xFFFFFFFFFFC0000B|",
          "0x6668|g_dwBufferReadIndex",
          "0x6660|g_dwCurrentPoolIndex"
        ],
        "LoD/1.09d": [
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFBFFFF8|",
          "0xFFFFFFFFFFBFFFF0|",
          "0xFFFFFFFFFFBFFFEC|",
          "0xFFFFFFFFFFBFFFF4|",
          "0xFFFFFFFFFFBFFFE8|",
          "0xFFFFFFFFFFC0000B|",
          "0x6668|g_dwBufferReadIndex",
          "0x6660|g_dwCurrentPoolIndex"
        ],
        "LoD/1.10": [
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFBFFFF8|",
          "0xFFFFFFFFFFBFFFF0|",
          "0xFFFFFFFFFFBFFFEC|",
          "0xFFFFFFFFFFBFFFF4|",
          "0xFFFFFFFFFFBFFFE8|",
          "0xFFFFFFFFFFC0000B|",
          "0x6668|g_dwBufferReadIndex",
          "0x6660|DAT_00406660"
        ],
        "LoD/1.11": [
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFBFFFF8|",
          "0xFFFFFFFFFFBFFFF0|",
          "0xFFFFFFFFFFBFFFEC|",
          "0xFFFFFFFFFFBFFFF4|",
          "0xFFFFFFFFFFBFFFE8|",
          "0xFFFFFFFFFFC0000B|",
          "0x6668|g_dwBufferReadIndex",
          "0x6660|g_dwCurrentPoolIndex"
        ],
        "LoD/1.11b": [
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFBFFFF8|",
          "0xFFFFFFFFFFBFFFF0|",
          "0xFFFFFFFFFFBFFFEC|",
          "0xFFFFFFFFFFBFFFF4|",
          "0xFFFFFFFFFFBFFFE8|",
          "0xFFFFFFFFFFC0000B|",
          "0x6668|g_dwBufferReadIndex",
          "0x6660|g_dwCurrentPoolIndex"
        ],
        "LoD/1.12a": [
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFBFFFF8|",
          "0xFFFFFFFFFFBFFFF0|",
          "0xFFFFFFFFFFBFFFEC|",
          "0xFFFFFFFFFFBFFFF4|",
          "0xFFFFFFFFFFBFFFE8|",
          "0xFFFFFFFFFFC0000B|",
          "0x6668|g_dwBufferReadIndex",
          "0x6660|g_dwCurrentPoolIndex"
        ],
        "LoD/1.13c": [
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFBFFFF8|",
          "0xFFFFFFFFFFBFFFF0|",
          "0xFFFFFFFFFFBFFFEC|",
          "0xFFFFFFFFFFBFFFF4|",
          "0xFFFFFFFFFFBFFFE8|",
          "0xFFFFFFFFFFC0000B|",
          "0x6668|g_dwBufferReadIndex",
          "0x6660|g_dwCurrentPoolIndex"
        ],
        "LoD/1.13d": [
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFBFFFF8|",
          "0xFFFFFFFFFFBFFFF0|",
          "0xFFFFFFFFFFBFFFEC|",
          "0xFFFFFFFFFFBFFFF4|",
          "0xFFFFFFFFFFBFFFE8|",
          "0xFFFFFFFFFFC0000B|",
          "0x6668|g_dwBufferReadIndex",
          "0x6660|g_dwCurrentPoolIndex"
        ],
        "LoD/1.14a": [
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFBFFFF8|",
          "0xFFFFFFFFFFBFFFF0|",
          "0xFFFFFFFFFFBFFFEC|",
          "0xFFFFFFFFFFBFFFF4|",
          "0xFFFFFFFFFFBFFFE8|",
          "0xFFFFFFFFFFC0000B|",
          "0x6668|g_dwBufferReadIndex",
          "0x6660|g_dwCurrentPoolIndex"
        ],
        "LoD/1.14b": [
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFBFFFF8|",
          "0xFFFFFFFFFFBFFFF0|",
          "0xFFFFFFFFFFBFFFEC|",
          "0xFFFFFFFFFFBFFFF4|",
          "0xFFFFFFFFFFBFFFE8|",
          "0xFFFFFFFFFFC0000B|",
          "0x6668|g_dwBufferReadIndex",
          "0x6660|g_dwCurrentPoolIndex"
        ],
        "LoD/1.14c": [
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFBFFFF8|",
          "0xFFFFFFFFFFBFFFF0|",
          "0xFFFFFFFFFFBFFFEC|",
          "0xFFFFFFFFFFBFFFF4|",
          "0xFFFFFFFFFFBFFFE8|",
          "0xFFFFFFFFFFC0000B|",
          "0x6668|g_dwBufferReadIndex",
          "0x6660|g_dwCurrentPoolIndex"
        ],
        "LoD/1.14d": [
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFBFFFF8|",
          "0xFFFFFFFFFFBFFFF0|",
          "0xFFFFFFFFFFBFFFEC|",
          "0xFFFFFFFFFFBFFFF4|",
          "0xFFFFFFFFFFBFFFE8|",
          "0xFFFFFFFFFFC0000B|",
          "0x6668|g_dwBufferReadIndex",
          "0x6660|g_dwCurrentPoolIndex"
        ]
      }
    },
    "diablo ii.exe_AllocateMemoryDescriptorBlock": {
      "addresses": {
        "LoD/1.07": "0x00403639",
        "LoD/1.08": "0x00403639",
        "LoD/1.09": "0x00403639",
        "LoD/1.09b": "0x00403639",
        "LoD/1.09d": "0x00403639",
        "LoD/1.10": "0x00403639",
        "LoD/1.11": "0x00403639",
        "LoD/1.11b": "0x00403639",
        "LoD/1.12a": "0x00403639",
        "LoD/1.13c": "0x00403639",
        "LoD/1.13d": "0x00403639",
        "LoD/1.14a": "0x00403639",
        "LoD/1.14b": "0x00403639",
        "LoD/1.14c": "0x00403639",
        "LoD/1.14d": "0x00403639"
      },
      "rvas": {
        "LoD/1.07": "0x3639",
        "LoD/1.08": "0x3639",
        "LoD/1.09": "0x3639",
        "LoD/1.09b": "0x3639",
        "LoD/1.09d": "0x3639",
        "LoD/1.10": "0x3639",
        "LoD/1.11": "0x3639",
        "LoD/1.11b": "0x3639",
        "LoD/1.12a": "0x3639",
        "LoD/1.13c": "0x3639",
        "LoD/1.13d": "0x3639",
        "LoD/1.14a": "0x3639",
        "LoD/1.14b": "0x3639",
        "LoD/1.14c": "0x3639",
        "LoD/1.14d": "0x3639"
      },
      "sizes": {
        "LoD/1.07": 777,
        "LoD/1.08": 777,
        "LoD/1.09": 777,
        "LoD/1.09b": 777,
        "LoD/1.09d": 777,
        "LoD/1.10": 777,
        "LoD/1.11": 777,
        "LoD/1.11b": 777,
        "LoD/1.12a": 777,
        "LoD/1.13c": 777,
        "LoD/1.13d": 777,
        "LoD/1.14a": 777,
        "LoD/1.14b": 777,
        "LoD/1.14c": 777,
        "LoD/1.14d": 777
      },
      "name": "AllocateMemoryDescriptorBlock",
      "signature": "void * AllocateMemoryDescriptorBlock(uint dwRequestedSize)",
      "calling_convention": "__cdecl",
      "return_type": "void *",
      "comment": "Allocates memory block from descriptor-based allocator with size-class free lists\n\nAlgorithm:\n1. Align requested size to 16-byte boundary and calculate size class index\n2. Generate bitmasks for free block tracking based on size class (splits at 32-bit boundary)\n3. Search descriptor array for available descriptor with matching free blocks\n4. If no descriptor found, search from beginning for any available descriptor\n5. If still no descriptor, search for descriptor with zero reserved field\n6. If no descriptor available, call allocation expansion function (FUN_1001db6e)\n7. If expansion fails, initialize new descriptor with FUN_1001dc1f\n8. Locate appropriate free list and find block of suitable size\n9. Calculate bit position for free block tracking within size class\n10. Remove block from free list by unlinking (doubly-linked list operations)\n11. If block larger than needed, split block and reinsert remainder into appropriate size class\n12. Update bit tracking arrays and reference counts for block allocation\n13. Set block headers with size information for boundary tag system\n14. Update global state if this was the last block in descriptor\n15. Return pointer to allocated memory (block pointer + 4 for header skip)\n\nParameters:\n- nRequestedSize (uint): Size in bytes to allocate, will be aligned to 16-byte boundary\n\nReturns:\n- void*: Pointer to allocated memory block, or NULL if allocation fails\n\nSpecial Cases:\n- Sizes are rounded up to next 16-byte boundary (add 0x17, mask with 0xfffffff0)\n- Free blocks tracked using dual bitmask system (low 32 bits, high 32 bits)\n- Size classes use bit positions 0-63 for different allocation sizes\n- Block splitting occurs when allocated block significantly larger than request\n- Boundary tag system maintains size at block start and end for coalescing\n\nMagic Numbers Reference:\n- 0x17 (23): Alignment padding for 16-byte boundaries\n- 0xfffffff0: Mask for 16-byte alignment\n- 0x20 (32): Bit boundary for high/low bitmask split\n- 0x3f (63): Maximum size class index\n- 0x81 (129): Stride for free list array access (129 dwords per size class)\n- 0x51 (81): Base offset for free list pointers in allocator data\n- 0x31 (49): Offset to high bitmask in allocator data\n- 0x11 (17): Offset to low bitmask in allocator data\n- 0x80000000: High bit mask for bit manipulation operations\n\nStructure Layout:\nOffset | Size | Field Name    | Type              | Description\n-------|------|---------------|-------------------|---------------------------\n0x00   | 4    | pHeapMemory   | void*             | Pointer to heap memory base\n0x04   | 4    | pVirtualMemory| void*             | Pointer to virtual memory\n0x08   | 4    | dwReserved1   | uint              | Reserved field, 0=available\n0x0C   | 4    | dwFlags       | uint              | Descriptor flags/status\n0x10   | 4    | pAllocatorData| AllocatorData*    | Pointer to allocator metadata\n\nError Handling:\n- Returns NULL if expansion function (FUN_1001db6e) fails to provide new descriptor\n- Returns NULL if descriptor initialization (FUN_1001dc1f) returns -1\n- Gracefully handles empty free lists by searching alternate size classes\n- Validates descriptor boundaries before proceeding with allocation",
      "name_source": "LoD/1.07",
      "method": "CAL",
      "index": "CAL:5bb0f1161464ac40af1960ad04967a2c",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "ff64648b3e6e32bc28a5e4bc8d984c1e",
        "CFG": "77ee9e9eb59c49729f84a4814c50ba23",
        "PRO": "74548a597b2dbd13776d58d1d4d74bdf",
        "CAL": "5bb0f1161464ac40af1960ad04967a2c",
        "CON": "8a8225fc5cf0d862e46335c317c8624f",
        "APS": null
      },
      "callees": {
        "LoD/1.07": [
          "AllocateMemoryDescriptor|0x403942",
          "AllocateMemorySlot|0x4039F3"
        ],
        "LoD/1.08": [
          "AllocateMemorySlot|0x4039F3",
          "AllocateMemoryDescriptor|0x403942"
        ],
        "LoD/1.09": [
          "AllocateMemoryDescriptor|0x403942",
          "AllocateMemorySlot|0x4039F3"
        ],
        "LoD/1.09b": [
          "AllocateMemorySlot|0x4039F3",
          "AllocateMemoryDescriptor|0x403942"
        ],
        "LoD/1.09d": [
          "AllocateMemorySlot|0x4039F3",
          "AllocateMemoryDescriptor|0x403942"
        ],
        "LoD/1.10": [
          "AllocateMemoryDescriptor|0x403942",
          "AllocateMemorySlot|0x4039F3"
        ],
        "LoD/1.11": [
          "AllocateMemorySlot|0x4039F3",
          "AllocateMemoryDescriptor|0x403942"
        ],
        "LoD/1.11b": [
          "AllocateMemorySlot|0x4039F3",
          "AllocateMemoryDescriptor|0x403942"
        ],
        "LoD/1.12a": [
          "AllocateMemorySlot|0x4039F3",
          "AllocateMemoryDescriptor|0x403942"
        ],
        "LoD/1.13c": [
          "AllocateMemoryDescriptor|0x403942",
          "AllocateMemorySlot|0x4039F3"
        ],
        "LoD/1.13d": [
          "AllocateMemoryDescriptor|0x403942",
          "AllocateMemorySlot|0x4039F3"
        ],
        "LoD/1.14a": [
          "AllocateMemorySlot|0x4039F3",
          "AllocateMemoryDescriptor|0x403942"
        ],
        "LoD/1.14b": [
          "AllocateMemorySlot|0x4039F3",
          "AllocateMemoryDescriptor|0x403942"
        ],
        "LoD/1.14c": [
          "AllocateMemoryDescriptor|0x403942",
          "AllocateMemorySlot|0x4039F3"
        ],
        "LoD/1.14d": [
          "AllocateMemorySlot|0x4039F3",
          "AllocateMemoryDescriptor|0x403942"
        ]
      },
      "callers": {
        "LoD/1.07": [
          "AllocateMemoryWithCache|0x402F2E"
        ],
        "LoD/1.08": [
          "AllocateMemoryWithCache|0x402F2E"
        ],
        "LoD/1.09": [
          "AllocateMemoryWithCache|0x402F2E"
        ],
        "LoD/1.09b": [
          "AllocateMemoryWithCache|0x402F2E"
        ],
        "LoD/1.09d": [
          "AllocateMemoryWithCache|0x402F2E"
        ],
        "LoD/1.10": [
          "AllocateMemoryWithCache|0x402F2E"
        ],
        "LoD/1.11": [
          "AllocateMemoryWithCache|0x402F2E"
        ],
        "LoD/1.11b": [
          "AllocateMemoryWithCache|0x402F2E"
        ],
        "LoD/1.12a": [
          "AllocateMemoryWithCache|0x402F2E"
        ],
        "LoD/1.13c": [
          "AllocateMemoryWithCache|0x402F2E"
        ],
        "LoD/1.13d": [
          "AllocateMemoryWithCache|0x402F2E"
        ],
        "LoD/1.14a": [
          "AllocateMemoryWithCache|0x402F2E"
        ],
        "LoD/1.14b": [
          "AllocateMemoryWithCache|0x402F2E"
        ],
        "LoD/1.14c": [
          "AllocateMemoryWithCache|0x402F2E"
        ],
        "LoD/1.14d": [
          "AllocateMemoryWithCache|0x402F2E"
        ]
      },
      "instruction_counts": {
        "LoD/1.07": 275,
        "LoD/1.08": 275,
        "LoD/1.09": 275,
        "LoD/1.09b": 275,
        "LoD/1.09d": 275,
        "LoD/1.10": 275,
        "LoD/1.11": 275,
        "LoD/1.11b": 275,
        "LoD/1.12a": 275,
        "LoD/1.13c": 275,
        "LoD/1.13d": 275,
        "LoD/1.14a": 275,
        "LoD/1.14b": 275,
        "LoD/1.14c": 275,
        "LoD/1.14d": 275
      },
      "stack_frame_sizes": {
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
        "LoD/1.13d": 32,
        "LoD/1.14a": 32,
        "LoD/1.14b": 32,
        "LoD/1.14c": 32,
        "LoD/1.14d": 32
      },
      "basic_block_counts": {
        "LoD/1.07": 65,
        "LoD/1.08": 65,
        "LoD/1.09": 65,
        "LoD/1.09b": 65,
        "LoD/1.09d": 65,
        "LoD/1.10": 65,
        "LoD/1.11": 65,
        "LoD/1.11b": 65,
        "LoD/1.12a": 65,
        "LoD/1.13c": 65,
        "LoD/1.13d": 65,
        "LoD/1.14a": 65,
        "LoD/1.14b": 65,
        "LoD/1.14c": 65,
        "LoD/1.14d": 65
      },
      "loop_counts": {
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
        "LoD/1.13d": 6,
        "LoD/1.14a": 6,
        "LoD/1.14b": 6,
        "LoD/1.14c": 6,
        "LoD/1.14d": 6
      },
      "mnemonic_hashes": {
        "LoD/1.07": "ff64648b3e6e32bc28a5e4bc8d984c1e",
        "LoD/1.08": "ff64648b3e6e32bc28a5e4bc8d984c1e",
        "LoD/1.09": "ff64648b3e6e32bc28a5e4bc8d984c1e",
        "LoD/1.09b": "ff64648b3e6e32bc28a5e4bc8d984c1e",
        "LoD/1.09d": "ff64648b3e6e32bc28a5e4bc8d984c1e",
        "LoD/1.10": "ff64648b3e6e32bc28a5e4bc8d984c1e",
        "LoD/1.11": "ff64648b3e6e32bc28a5e4bc8d984c1e",
        "LoD/1.11b": "ff64648b3e6e32bc28a5e4bc8d984c1e",
        "LoD/1.12a": "ff64648b3e6e32bc28a5e4bc8d984c1e",
        "LoD/1.13c": "ff64648b3e6e32bc28a5e4bc8d984c1e",
        "LoD/1.13d": "ff64648b3e6e32bc28a5e4bc8d984c1e",
        "LoD/1.14a": "ff64648b3e6e32bc28a5e4bc8d984c1e",
        "LoD/1.14b": "ff64648b3e6e32bc28a5e4bc8d984c1e",
        "LoD/1.14c": "ff64648b3e6e32bc28a5e4bc8d984c1e",
        "LoD/1.14d": "ff64648b3e6e32bc28a5e4bc8d984c1e"
      },
      "constants": {
        "LoD/1.07": [
          324,
          516
        ],
        "LoD/1.08": [
          324,
          516
        ],
        "LoD/1.09": [
          324,
          516
        ],
        "LoD/1.09b": [
          324,
          516
        ],
        "LoD/1.09d": [
          324,
          516
        ],
        "LoD/1.10": [
          324,
          516
        ],
        "LoD/1.11": [
          324,
          516
        ],
        "LoD/1.11b": [
          324,
          516
        ],
        "LoD/1.12a": [
          324,
          516
        ],
        "LoD/1.13c": [
          324,
          516
        ],
        "LoD/1.13d": [
          324,
          516
        ],
        "LoD/1.14a": [
          324,
          516
        ],
        "LoD/1.14b": [
          324,
          516
        ],
        "LoD/1.14c": [
          324,
          516
        ],
        "LoD/1.14d": [
          324,
          516
        ]
      },
      "globals": {
        "LoD/1.07": [
          "0x666C|g_nDescriptorCount",
          "0x6670|g_pDescriptorArray",
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFBFFFF8|",
          "0xFFFFFFFFFFBFFFEC|",
          "0xFFFFFFFFFFBFFFF4|",
          "0xFFFFFFFFFFBFFFF0|",
          "0x6664|g_pBufferBasePointer",
          "0xFFFFFFFFFFBFFFE8|",
          "0xFFFFFFFFFFC00007|"
        ],
        "LoD/1.08": [
          "0x666C|g_nDescriptorCount",
          "0x6670|g_pDescriptorArray",
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFBFFFF8|",
          "0xFFFFFFFFFFBFFFEC|",
          "0xFFFFFFFFFFBFFFF4|",
          "0xFFFFFFFFFFBFFFF0|",
          "0x6664|g_pBufferBasePointer",
          "0xFFFFFFFFFFBFFFE8|",
          "0xFFFFFFFFFFC00007|"
        ],
        "LoD/1.09": [
          "0x666C|g_nDescriptorCount",
          "0x6670|g_pDescriptorArray",
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFBFFFF8|",
          "0xFFFFFFFFFFBFFFEC|",
          "0xFFFFFFFFFFBFFFF4|",
          "0xFFFFFFFFFFBFFFF0|",
          "0x6664|g_pBufferBasePointer",
          "0xFFFFFFFFFFBFFFE8|",
          "0xFFFFFFFFFFC00007|"
        ],
        "LoD/1.09b": [
          "0x666C|g_nDescriptorCount",
          "0x6670|g_pDescriptorArray",
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFBFFFF8|",
          "0xFFFFFFFFFFBFFFEC|",
          "0xFFFFFFFFFFBFFFF4|",
          "0xFFFFFFFFFFBFFFF0|",
          "0x6664|g_pBufferBasePointer",
          "0xFFFFFFFFFFBFFFE8|",
          "0xFFFFFFFFFFC00007|"
        ],
        "LoD/1.09d": [
          "0x666C|g_nDescriptorCount",
          "0x6670|g_pDescriptorArray",
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFBFFFF8|",
          "0xFFFFFFFFFFBFFFEC|",
          "0xFFFFFFFFFFBFFFF4|",
          "0xFFFFFFFFFFBFFFF0|",
          "0x6664|g_pBufferBasePointer",
          "0xFFFFFFFFFFBFFFE8|",
          "0xFFFFFFFFFFC00007|"
        ],
        "LoD/1.10": [
          "0x666C|g_nDescriptorCount",
          "0x6670|g_pDescriptorArray",
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFBFFFF8|",
          "0xFFFFFFFFFFBFFFEC|",
          "0xFFFFFFFFFFBFFFF4|",
          "0xFFFFFFFFFFBFFFF0|",
          "0x6664|g_pBufferBasePointer",
          "0xFFFFFFFFFFBFFFE8|",
          "0xFFFFFFFFFFC00007|"
        ],
        "LoD/1.11": [
          "0x666C|g_nDescriptorCount",
          "0x6670|g_pDescriptorArray",
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFBFFFF8|",
          "0xFFFFFFFFFFBFFFEC|",
          "0xFFFFFFFFFFBFFFF4|",
          "0xFFFFFFFFFFBFFFF0|",
          "0x6664|g_pBufferBasePointer",
          "0xFFFFFFFFFFBFFFE8|",
          "0xFFFFFFFFFFC00007|"
        ],
        "LoD/1.11b": [
          "0x666C|g_nDescriptorCount",
          "0x6670|g_pDescriptorArray",
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFBFFFF8|",
          "0xFFFFFFFFFFBFFFEC|",
          "0xFFFFFFFFFFBFFFF4|",
          "0xFFFFFFFFFFBFFFF0|",
          "0x6664|g_pBufferBasePointer",
          "0xFFFFFFFFFFBFFFE8|",
          "0xFFFFFFFFFFC00007|"
        ],
        "LoD/1.12a": [
          "0x666C|g_nDescriptorCount",
          "0x6670|g_pDescriptorArray",
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFBFFFF8|",
          "0xFFFFFFFFFFBFFFEC|",
          "0xFFFFFFFFFFBFFFF4|",
          "0xFFFFFFFFFFBFFFF0|",
          "0x6664|g_pBufferBasePointer",
          "0xFFFFFFFFFFBFFFE8|",
          "0xFFFFFFFFFFC00007|"
        ],
        "LoD/1.13c": [
          "0x666C|g_nDescriptorCount",
          "0x6670|g_pDescriptorArray",
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFBFFFF8|",
          "0xFFFFFFFFFFBFFFEC|",
          "0xFFFFFFFFFFBFFFF4|",
          "0xFFFFFFFFFFBFFFF0|",
          "0x6664|g_pBufferBasePointer",
          "0xFFFFFFFFFFBFFFE8|",
          "0xFFFFFFFFFFC00007|"
        ],
        "LoD/1.13d": [
          "0x666C|g_nDescriptorCount",
          "0x6670|g_pDescriptorArray",
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFBFFFF8|",
          "0xFFFFFFFFFFBFFFEC|",
          "0xFFFFFFFFFFBFFFF4|",
          "0xFFFFFFFFFFBFFFF0|",
          "0x6664|g_pBufferBasePointer",
          "0xFFFFFFFFFFBFFFE8|",
          "0xFFFFFFFFFFC00007|"
        ],
        "LoD/1.14a": [
          "0x666C|g_nDescriptorCount",
          "0x6670|g_pDescriptorArray",
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFBFFFF8|",
          "0xFFFFFFFFFFBFFFEC|",
          "0xFFFFFFFFFFBFFFF4|",
          "0xFFFFFFFFFFBFFFF0|",
          "0x6664|g_pBufferBasePointer",
          "0xFFFFFFFFFFBFFFE8|",
          "0xFFFFFFFFFFC00007|"
        ],
        "LoD/1.14b": [
          "0x666C|g_nDescriptorCount",
          "0x6670|g_pDescriptorArray",
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFBFFFF8|",
          "0xFFFFFFFFFFBFFFEC|",
          "0xFFFFFFFFFFBFFFF4|",
          "0xFFFFFFFFFFBFFFF0|",
          "0x6664|g_pBufferBasePointer",
          "0xFFFFFFFFFFBFFFE8|",
          "0xFFFFFFFFFFC00007|"
        ],
        "LoD/1.14c": [
          "0x666C|g_nDescriptorCount",
          "0x6670|g_pDescriptorArray",
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFBFFFF8|",
          "0xFFFFFFFFFFBFFFEC|",
          "0xFFFFFFFFFFBFFFF4|",
          "0xFFFFFFFFFFBFFFF0|",
          "0x6664|g_pBufferBasePointer",
          "0xFFFFFFFFFFBFFFE8|",
          "0xFFFFFFFFFFC00007|"
        ],
        "LoD/1.14d": [
          "0x666C|g_nDescriptorCount",
          "0x6670|g_pDescriptorArray",
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFBFFFF8|",
          "0xFFFFFFFFFFBFFFEC|",
          "0xFFFFFFFFFFBFFFF4|",
          "0xFFFFFFFFFFBFFFF0|",
          "0x6664|g_pBufferBasePointer",
          "0xFFFFFFFFFFBFFFE8|",
          "0xFFFFFFFFFFC00007|"
        ]
      }
    },
    "diablo ii.exe_AllocateMemoryDescriptor": {
      "addresses": {
        "LoD/1.07": "0x00403942",
        "LoD/1.08": "0x00403942",
        "LoD/1.09": "0x00403942",
        "LoD/1.09b": "0x00403942",
        "LoD/1.09d": "0x00403942",
        "LoD/1.10": "0x00403942",
        "LoD/1.11": "0x00403942",
        "LoD/1.11b": "0x00403942",
        "LoD/1.12a": "0x00403942",
        "LoD/1.13c": "0x00403942",
        "LoD/1.13d": "0x00403942",
        "LoD/1.14a": "0x00403942",
        "LoD/1.14b": "0x00403942",
        "LoD/1.14c": "0x00403942",
        "LoD/1.14d": "0x00403942"
      },
      "rvas": {
        "LoD/1.07": "0x3942",
        "LoD/1.08": "0x3942",
        "LoD/1.09": "0x3942",
        "LoD/1.09b": "0x3942",
        "LoD/1.09d": "0x3942",
        "LoD/1.10": "0x3942",
        "LoD/1.11": "0x3942",
        "LoD/1.11b": "0x3942",
        "LoD/1.12a": "0x3942",
        "LoD/1.13c": "0x3942",
        "LoD/1.13d": "0x3942",
        "LoD/1.14a": "0x3942",
        "LoD/1.14b": "0x3942",
        "LoD/1.14c": "0x3942",
        "LoD/1.14d": "0x3942"
      },
      "sizes": {
        "LoD/1.07": 177,
        "LoD/1.08": 177,
        "LoD/1.09": 177,
        "LoD/1.09b": 177,
        "LoD/1.09d": 177,
        "LoD/1.10": 177,
        "LoD/1.11": 177,
        "LoD/1.11b": 177,
        "LoD/1.12a": 177,
        "LoD/1.13c": 177,
        "LoD/1.13d": 177,
        "LoD/1.14a": 177,
        "LoD/1.14b": 177,
        "LoD/1.14c": 177,
        "LoD/1.14d": 177
      },
      "name": "AllocateMemoryDescriptor",
      "signature": "undefined4 * AllocateMemoryDescriptor(void)",
      "calling_convention": "__stdcall",
      "return_type": "undefined4 *",
      "comment": "Allocates a new memory descriptor with associated heap and virtual memory buffers.\n\nAlgorithm:\n1. Check if descriptor array is full (g_nDescriptorCount == g_dwBufferElementSize)\n2. If full, reallocate descriptor array with space for 16 more entries using HeapReAlloc\n3. Update g_dwBufferElementSize by adding 0x10 and store new array pointer in g_pDescriptorArray\n4. Calculate pointer to next available descriptor (g_pDescriptorArray + g_nDescriptorCount)\n5. Allocate 0x41c4 bytes of heap memory using HeapAlloc with HEAP_ZERO_MEMORY flag (0x8)\n6. Store heap allocation pointer in descriptor dwReserved3 field\n7. Allocate 1MB (0x100000) of virtual memory using VirtualAlloc with MEM_RESERVE flag (0x2000)\n8. Store virtual allocation pointer in descriptor dwReserved2 field\n9. Initialize descriptor fields: dwReserved1 = 0xffffffff, clear pVirtualMemory and pHeapMemory\n10. Increment global descriptor count (g_nDescriptorCount)\n11. Set first DWORD of heap memory to 0xffffffff as initialization marker\n12. Return pointer to pVirtualMemory field of the new descriptor\n\nParameters:\nNone\n\nReturns:\nvoid * - Pointer to pVirtualMemory field of allocated descriptor on success\nNULL - If descriptor array reallocation fails, heap allocation fails, or virtual memory allocation fails\n\nSpecial Cases:\nIf heap allocation succeeds but virtual memory allocation fails, the heap memory is freed to prevent leaks before returning NULL\n\nMagic Numbers Reference:\n0x10 (16) - Descriptor array growth increment\n0x41c4 (16836) - Size of heap allocation per descriptor\n0x100000 (1048576) - Virtual memory allocation size (1MB)\n0x2000 (8192) - MEM_RESERVE flag for VirtualAlloc\n0x8 (8) - HEAP_ZERO_MEMORY flag for HeapAlloc\n0xffffffff (-1) - Initialization value for dwReserved1 and heap memory marker\n\nStructure Layout:\nMemoryDescriptor (20 bytes total):\nOffset | Size | Field Name      | Type    | Description\n0x00   | 4    | pVirtualMemory  | void *  | Pointer to virtual memory allocation\n0x04   | 4    | pHeapMemory     | void *  | Pointer to heap memory allocation\n0x08   | 4    | dwReserved1     | uint    | Status/flags field, initialized to 0xffffffff\n0x0C   | 4    | dwReserved2     | uint    | Stores virtual memory allocation pointer\n0x10   | 4    | dwReserved3     | uint    | Stores heap memory allocation pointer\n\nError Handling:\nArray reallocation failure returns NULL immediately without cleanup\nHeap allocation failure returns NULL immediately\nVirtual allocation failure after successful heap allocation frees heap memory before returning NULL",
      "name_source": "LoD/1.07",
      "method": "CAL",
      "index": "CAL:d162a691c996bedefb297d13afb4296d",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "b59a8a7d2c8fdcc2aac183f01f99a847",
        "CFG": "1dc319af88f2e70d9474a5ad20c0aa4a",
        "PRO": "30c72037c3458611ecf2fcd89dd1352a",
        "CAL": "d162a691c996bedefb297d13afb4296d",
        "CON": "96c1a5fdc99677050d0c1df56bae10f7",
        "APS": null
      },
      "callees": {
        "LoD/1.07": [
          "HeapFree|0x20",
          "VirtualAlloc|0x29",
          "HeapAlloc|0x28",
          "HeapReAlloc|0x2A"
        ],
        "LoD/1.08": [
          "HeapFree|0x20",
          "HeapAlloc|0x28",
          "VirtualAlloc|0x29",
          "HeapReAlloc|0x2A"
        ],
        "LoD/1.09": [
          "HeapReAlloc|0x2A",
          "HeapAlloc|0x28",
          "VirtualAlloc|0x29",
          "HeapFree|0x20"
        ],
        "LoD/1.09b": [
          "VirtualAlloc|0x29",
          "HeapAlloc|0x28",
          "HeapReAlloc|0x2A",
          "HeapFree|0x20"
        ],
        "LoD/1.09d": [
          "HeapFree|0x20",
          "HeapReAlloc|0x2A",
          "HeapAlloc|0x28",
          "VirtualAlloc|0x29"
        ],
        "LoD/1.10": [
          "HeapReAlloc|0x2A",
          "HeapAlloc|0x28",
          "VirtualAlloc|0x29",
          "HeapFree|0x20"
        ],
        "LoD/1.11": [
          "HeapReAlloc|0x2A",
          "HeapFree|0x20",
          "HeapAlloc|0x28",
          "VirtualAlloc|0x29"
        ],
        "LoD/1.11b": [
          "HeapFree|0x20",
          "VirtualAlloc|0x29",
          "HeapAlloc|0x28",
          "HeapReAlloc|0x2A"
        ],
        "LoD/1.12a": [
          "HeapFree|0x20",
          "HeapReAlloc|0x2A",
          "VirtualAlloc|0x29",
          "HeapAlloc|0x28"
        ],
        "LoD/1.13c": [
          "HeapFree|0x20",
          "VirtualAlloc|0x29",
          "HeapAlloc|0x28",
          "HeapReAlloc|0x2A"
        ],
        "LoD/1.13d": [
          "HeapReAlloc|0x2A",
          "HeapFree|0x20",
          "HeapAlloc|0x28",
          "VirtualAlloc|0x29"
        ],
        "LoD/1.14a": [
          "VirtualAlloc|0x29",
          "HeapAlloc|0x28",
          "HeapReAlloc|0x2A",
          "HeapFree|0x20"
        ],
        "LoD/1.14b": [
          "HeapFree|0x20",
          "VirtualAlloc|0x29",
          "HeapAlloc|0x28",
          "HeapReAlloc|0x2A"
        ],
        "LoD/1.14c": [
          "HeapAlloc|0x28",
          "HeapReAlloc|0x2A",
          "HeapFree|0x20",
          "VirtualAlloc|0x29"
        ],
        "LoD/1.14d": [
          "HeapAlloc|0x28",
          "HeapFree|0x20",
          "VirtualAlloc|0x29",
          "HeapReAlloc|0x2A"
        ]
      },
      "callers": {
        "LoD/1.07": [
          "AllocateMemoryDescriptorBlock|0x403639"
        ],
        "LoD/1.08": [
          "AllocateMemoryDescriptorBlock|0x403639"
        ],
        "LoD/1.09": [
          "AllocateMemoryDescriptorBlock|0x403639"
        ],
        "LoD/1.09b": [
          "AllocateMemoryDescriptorBlock|0x403639"
        ],
        "LoD/1.09d": [
          "AllocateMemoryDescriptorBlock|0x403639"
        ],
        "LoD/1.10": [
          "AllocateMemoryDescriptorBlock|0x403639"
        ],
        "LoD/1.11": [
          "AllocateMemoryDescriptorBlock|0x403639"
        ],
        "LoD/1.11b": [
          "AllocateMemoryDescriptorBlock|0x403639"
        ],
        "LoD/1.12a": [
          "AllocateMemoryDescriptorBlock|0x403639"
        ],
        "LoD/1.13c": [
          "AllocateMemoryDescriptorBlock|0x403639"
        ],
        "LoD/1.13d": [
          "AllocateMemoryDescriptorBlock|0x403639"
        ],
        "LoD/1.14a": [
          "AllocateMemoryDescriptorBlock|0x403639"
        ],
        "LoD/1.14b": [
          "AllocateMemoryDescriptorBlock|0x403639"
        ],
        "LoD/1.14c": [
          "AllocateMemoryDescriptorBlock|0x403639"
        ],
        "LoD/1.14d": [
          "AllocateMemoryDescriptorBlock|0x403639"
        ]
      },
      "instruction_counts": {
        "LoD/1.07": 53,
        "LoD/1.08": 53,
        "LoD/1.09": 53,
        "LoD/1.09b": 53,
        "LoD/1.09d": 53,
        "LoD/1.10": 53,
        "LoD/1.11": 53,
        "LoD/1.11b": 53,
        "LoD/1.12a": 53,
        "LoD/1.13c": 53,
        "LoD/1.13d": 53,
        "LoD/1.14a": 53,
        "LoD/1.14b": 53,
        "LoD/1.14c": 53,
        "LoD/1.14d": 53
      },
      "stack_frame_sizes": {
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
        "LoD/1.13d": 4,
        "LoD/1.14a": 4,
        "LoD/1.14b": 4,
        "LoD/1.14c": 4,
        "LoD/1.14d": 4
      },
      "basic_block_counts": {
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
        "LoD/1.13d": 9,
        "LoD/1.14a": 9,
        "LoD/1.14b": 9,
        "LoD/1.14c": 9,
        "LoD/1.14d": 9
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
        "LoD/1.13d": 0,
        "LoD/1.14a": 0,
        "LoD/1.14b": 0,
        "LoD/1.14c": 0,
        "LoD/1.14d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "b59a8a7d2c8fdcc2aac183f01f99a847",
        "LoD/1.08": "b59a8a7d2c8fdcc2aac183f01f99a847",
        "LoD/1.09": "b59a8a7d2c8fdcc2aac183f01f99a847",
        "LoD/1.09b": "b59a8a7d2c8fdcc2aac183f01f99a847",
        "LoD/1.09d": "b59a8a7d2c8fdcc2aac183f01f99a847",
        "LoD/1.10": "b59a8a7d2c8fdcc2aac183f01f99a847",
        "LoD/1.11": "b59a8a7d2c8fdcc2aac183f01f99a847",
        "LoD/1.11b": "b59a8a7d2c8fdcc2aac183f01f99a847",
        "LoD/1.12a": "b59a8a7d2c8fdcc2aac183f01f99a847",
        "LoD/1.13c": "b59a8a7d2c8fdcc2aac183f01f99a847",
        "LoD/1.13d": "b59a8a7d2c8fdcc2aac183f01f99a847",
        "LoD/1.14a": "b59a8a7d2c8fdcc2aac183f01f99a847",
        "LoD/1.14b": "b59a8a7d2c8fdcc2aac183f01f99a847",
        "LoD/1.14c": "b59a8a7d2c8fdcc2aac183f01f99a847",
        "LoD/1.14d": "b59a8a7d2c8fdcc2aac183f01f99a847"
      },
      "constants": {
        "LoD/1.07": [
          8192,
          16836,
          1048576
        ],
        "LoD/1.08": [
          8192,
          16836,
          1048576
        ],
        "LoD/1.09": [
          8192,
          16836,
          1048576
        ],
        "LoD/1.09b": [
          8192,
          16836,
          1048576
        ],
        "LoD/1.09d": [
          8192,
          16836,
          1048576
        ],
        "LoD/1.10": [
          8192,
          16836,
          1048576
        ],
        "LoD/1.11": [
          8192,
          16836,
          1048576
        ],
        "LoD/1.11b": [
          8192,
          16836,
          1048576
        ],
        "LoD/1.12a": [
          8192,
          16836,
          1048576
        ],
        "LoD/1.13c": [
          8192,
          16836,
          1048576
        ],
        "LoD/1.13d": [
          8192,
          16836,
          1048576
        ],
        "LoD/1.14a": [
          8192,
          16836,
          1048576
        ],
        "LoD/1.14b": [
          8192,
          16836,
          1048576
        ],
        "LoD/1.14c": [
          8192,
          16836,
          1048576
        ],
        "LoD/1.14d": [
          8192,
          16836,
          1048576
        ]
      },
      "globals": {
        "LoD/1.07": [
          "0x666C|g_nDescriptorCount",
          "0x665C|g_dwBufferElementSize",
          "0x6670|g_pDescriptorArray",
          "0x6674|g_hHeapHandle",
          "0x50A4|PTR_HeapReAlloc_004050a4",
          "0x509C|PTR_HeapAlloc_0040509c",
          "0x50A0|PTR_VirtualAlloc_004050a0",
          "0x507C|PTR_HeapFree_0040507c"
        ],
        "LoD/1.08": [
          "0x666C|g_nDescriptorCount",
          "0x665C|g_dwBufferElementSize",
          "0x6670|g_pDescriptorArray",
          "0x6674|g_hHeapHandle",
          "0x50A4|PTR_HeapReAlloc_004050a4",
          "0x509C|PTR_HeapAlloc_0040509c",
          "0x50A0|PTR_VirtualAlloc_004050a0",
          "0x507C|PTR_HeapFree_0040507c"
        ],
        "LoD/1.09": [
          "0x666C|g_nDescriptorCount",
          "0x665C|g_dwBufferElementSize",
          "0x6670|g_pDescriptorArray",
          "0x6674|g_hHeapHandle",
          "0x50A4|PTR_HeapReAlloc_004050a4",
          "0x509C|PTR_HeapAlloc_0040509c",
          "0x50A0|PTR_VirtualAlloc_004050a0",
          "0x507C|PTR_HeapFree_0040507c"
        ],
        "LoD/1.09b": [
          "0x666C|g_nDescriptorCount",
          "0x665C|g_dwBufferElementSize",
          "0x6670|g_pDescriptorArray",
          "0x6674|g_hHeapHandle",
          "0x50A4|PTR_HeapReAlloc_004050a4",
          "0x509C|PTR_HeapAlloc_0040509c",
          "0x50A0|PTR_VirtualAlloc_004050a0",
          "0x507C|PTR_HeapFree_0040507c"
        ],
        "LoD/1.09d": [
          "0x666C|g_nDescriptorCount",
          "0x665C|g_dwBufferElementSize",
          "0x6670|g_pDescriptorArray",
          "0x6674|g_hHeapHandle",
          "0x50A4|PTR_HeapReAlloc_004050a4",
          "0x509C|PTR_HeapAlloc_0040509c",
          "0x50A0|PTR_VirtualAlloc_004050a0",
          "0x507C|PTR_HeapFree_0040507c"
        ],
        "LoD/1.10": [
          "0x666C|g_nDescriptorCount",
          "0x665C|g_dwBufferElementSize",
          "0x6670|g_pDescriptorArray",
          "0x6674|g_hHeap",
          "0x50A4|PTR_HeapReAlloc_004050a4",
          "0x509C|PTR_HeapAlloc_0040509c",
          "0x50A0|PTR_VirtualAlloc_004050a0",
          "0x507C|PTR_HeapFree_0040507c"
        ],
        "LoD/1.11": [
          "0x666C|g_nDescriptorCount",
          "0x665C|g_dwBufferElementSize",
          "0x6670|g_pDescriptorArray",
          "0x6674|g_hHeapHandle",
          "0x50A4|PTR_HeapReAlloc_004050a4",
          "0x509C|PTR_HeapAlloc_0040509c",
          "0x50A0|PTR_VirtualAlloc_004050a0",
          "0x507C|PTR_HeapFree_0040507c"
        ],
        "LoD/1.11b": [
          "0x666C|g_nDescriptorCount",
          "0x665C|g_dwBufferElementSize",
          "0x6670|g_pDescriptorArray",
          "0x6674|g_hHeapHandle",
          "0x50A4|PTR_HeapReAlloc_004050a4",
          "0x509C|PTR_HeapAlloc_0040509c",
          "0x50A0|PTR_VirtualAlloc_004050a0",
          "0x507C|PTR_HeapFree_0040507c"
        ],
        "LoD/1.12a": [
          "0x666C|g_nDescriptorCount",
          "0x665C|g_dwBufferElementSize",
          "0x6670|g_pDescriptorArray",
          "0x6674|g_hHeapHandle",
          "0x50A4|PTR_HeapReAlloc_004050a4",
          "0x509C|PTR_HeapAlloc_0040509c",
          "0x50A0|PTR_VirtualAlloc_004050a0",
          "0x507C|PTR_HeapFree_0040507c"
        ],
        "LoD/1.13c": [
          "0x666C|g_nDescriptorCount",
          "0x665C|g_dwBufferElementSize",
          "0x6670|g_pDescriptorArray",
          "0x6674|g_hHeapHandle",
          "0x50A4|PTR_HeapReAlloc_004050a4",
          "0x509C|PTR_HeapAlloc_0040509c",
          "0x50A0|PTR_VirtualAlloc_004050a0",
          "0x507C|PTR_HeapFree_0040507c"
        ],
        "LoD/1.13d": [
          "0x666C|g_nDescriptorCount",
          "0x665C|g_dwBufferElementSize",
          "0x6670|g_pDescriptorArray",
          "0x6674|g_hHeapHandle",
          "0x50A4|PTR_HeapReAlloc_004050a4",
          "0x509C|PTR_HeapAlloc_0040509c",
          "0x50A0|PTR_VirtualAlloc_004050a0",
          "0x507C|PTR_HeapFree_0040507c"
        ],
        "LoD/1.14a": [
          "0x666C|g_nDescriptorCount",
          "0x665C|g_dwBufferElementSize",
          "0x6670|g_pDescriptorArray",
          "0x6674|g_hHeapHandle",
          "0x50A4|PTR_HeapReAlloc_004050a4",
          "0x509C|PTR_HeapAlloc_0040509c",
          "0x50A0|PTR_VirtualAlloc_004050a0",
          "0x507C|PTR_HeapFree_0040507c"
        ],
        "LoD/1.14b": [
          "0x666C|g_nDescriptorCount",
          "0x665C|g_dwBufferElementSize",
          "0x6670|g_pDescriptorArray",
          "0x6674|g_hHeapHandle",
          "0x50A4|PTR_HeapReAlloc_004050a4",
          "0x509C|PTR_HeapAlloc_0040509c",
          "0x50A0|PTR_VirtualAlloc_004050a0",
          "0x507C|PTR_HeapFree_0040507c"
        ],
        "LoD/1.14c": [
          "0x666C|g_nDescriptorCount",
          "0x665C|g_dwBufferElementSize",
          "0x6670|g_pDescriptorArray",
          "0x6674|g_hHeapHandle",
          "0x50A4|PTR_HeapReAlloc_004050a4",
          "0x509C|PTR_HeapAlloc_0040509c",
          "0x50A0|PTR_VirtualAlloc_004050a0",
          "0x507C|PTR_HeapFree_0040507c"
        ],
        "LoD/1.14d": [
          "0x666C|g_nDescriptorCount",
          "0x665C|g_dwBufferElementSize",
          "0x6670|g_pDescriptorArray",
          "0x6674|g_hHeapHandle",
          "0x50A4|PTR_HeapReAlloc_004050a4",
          "0x509C|PTR_HeapAlloc_0040509c",
          "0x50A0|PTR_VirtualAlloc_004050a0",
          "0x507C|PTR_HeapFree_0040507c"
        ]
      }
    },
    "diablo ii.exe_AllocateMemorySlot": {
      "addresses": {
        "LoD/1.07": "0x004039F3",
        "LoD/1.08": "0x004039F3",
        "LoD/1.09": "0x004039F3",
        "LoD/1.09b": "0x004039F3",
        "LoD/1.09d": "0x004039F3",
        "LoD/1.10": "0x004039F3",
        "LoD/1.11": "0x004039F3",
        "LoD/1.11b": "0x004039F3",
        "LoD/1.12a": "0x004039F3",
        "LoD/1.13c": "0x004039F3",
        "LoD/1.13d": "0x004039F3",
        "LoD/1.14a": "0x004039F3",
        "LoD/1.14b": "0x004039F3",
        "LoD/1.14c": "0x004039F3",
        "LoD/1.14d": "0x004039F3"
      },
      "rvas": {
        "LoD/1.07": "0x39F3",
        "LoD/1.08": "0x39F3",
        "LoD/1.09": "0x39F3",
        "LoD/1.09b": "0x39F3",
        "LoD/1.09d": "0x39F3",
        "LoD/1.10": "0x39F3",
        "LoD/1.11": "0x39F3",
        "LoD/1.11b": "0x39F3",
        "LoD/1.12a": "0x39F3",
        "LoD/1.13c": "0x39F3",
        "LoD/1.13d": "0x39F3",
        "LoD/1.14a": "0x39F3",
        "LoD/1.14b": "0x39F3",
        "LoD/1.14c": "0x39F3",
        "LoD/1.14d": "0x39F3"
      },
      "sizes": {
        "LoD/1.07": 251,
        "LoD/1.08": 251,
        "LoD/1.09": 251,
        "LoD/1.09b": 251,
        "LoD/1.09d": 251,
        "LoD/1.10": 251,
        "LoD/1.11": 251,
        "LoD/1.11b": 251,
        "LoD/1.12a": 251,
        "LoD/1.13c": 251,
        "LoD/1.13d": 251,
        "LoD/1.14a": 251,
        "LoD/1.14b": 251,
        "LoD/1.14c": 251,
        "LoD/1.14d": 251
      },
      "name": "AllocateMemorySlot",
      "signature": "int AllocateMemorySlot(MemoryDescriptor * pMemoryDescriptor)",
      "calling_convention": "__cdecl",
      "return_type": "int",
      "comment": "Allocates a memory slot in the memory descriptor system and initializes linked list structures.\n\nAlgorithm:\n1. Extract base offset from memory descriptor (offset 0x10)\n2. Find next available slot by counting leading set bits in allocation mask (offset 0x8)\n3. Calculate descriptor offset: slot_index * 0x204 + 0x144 + base_offset\n4. Initialize 64 linked list node pairs (0x3f iterations) with self-referencing pointers\n5. Calculate memory base address: slot_index * 0x8000 + base_address (offset 0xc)\n6. Allocate 32KB (0x8000 bytes) of virtual memory with VirtualAlloc\n7. If allocation fails, return -1\n8. Initialize memory block as doubly-linked list with 1024-byte (0x400) stride\n9. Set up forward and backward pointers for each node in the allocated block\n10. Link descriptor to allocated memory at specific offsets (0x1fc, 0x200)\n11. Clear slot status flag at base_offset + 0x44 + slot_index * 4\n12. Set slot allocation flag at base_offset + 0xc4 + slot_index * 4\n13. Increment allocation counter at base_offset + 0x43\n14. If counter wraps to 0, set overflow flag (bit 0) in descriptor flags (offset 0x4)\n15. Clear allocated bit in allocation mask using bit manipulation\n\nParameters:\npMemoryDescriptor - Pointer to MemoryDescriptor structure containing allocation state\n\nReturns:\nSlot index (0-31) on successful allocation\n-1 on VirtualAlloc failure\n\nSpecial Cases:\nMagic Numbers Reference:\n0x204 (516) - Descriptor block size per slot\n0x144 (324) - Base descriptor offset \n0x8000 (32768) - Memory block size (32KB)\n0x1000 (4096) - VirtualAlloc MEM_COMMIT flag\n0x3f (63) - Loop counter for 64 node pairs\n0x400 (1024) - Node stride in memory block\n0xff0 (4080) - Node size/offset marker\n0x1c00 (7168) - Memory block boundary check\n\nStructure Layout:\nOffset | Size | Field Name    | Type | Description\n0x4    | 4    | dwFlags       | uint | Status flags (bit 0 = overflow)\n0x8    | 4    | dwAllocMask   | uint | Allocation bitmask (bit per slot)  \n0xc    | 4    | pBaseMemory   | int* | Base address for memory blocks\n0x10   | 4    | nBaseOffset   | int  | Base offset for descriptor blocks\n\nError Handling:\nVirtualAlloc failure returns -1 without modifying descriptor state\nSlot index calculation assumes valid input parameters",
      "name_source": "LoD/1.07",
      "method": "CON",
      "index": "CON:29da550efe003bc20354fd57a4971440",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "0002c858ef3942a0b403454c72674bfe",
        "CFG": "3fbf2bd19df4bd936c35c3bd28c3f8a5",
        "PRO": "dea8c343a18f51e1084181af8b8e840f",
        "CAL": null,
        "CON": "29da550efe003bc20354fd57a4971440",
        "APS": null
      },
      "callees": {
        "LoD/1.07": [
          "VirtualAlloc|0x29"
        ],
        "LoD/1.08": [
          "VirtualAlloc|0x29"
        ],
        "LoD/1.09": [
          "VirtualAlloc|0x29"
        ],
        "LoD/1.09b": [
          "VirtualAlloc|0x29"
        ],
        "LoD/1.09d": [
          "VirtualAlloc|0x29"
        ],
        "LoD/1.10": [
          "VirtualAlloc|0x29"
        ],
        "LoD/1.11": [
          "VirtualAlloc|0x29"
        ],
        "LoD/1.11b": [
          "VirtualAlloc|0x29"
        ],
        "LoD/1.12a": [
          "VirtualAlloc|0x29"
        ],
        "LoD/1.13c": [
          "VirtualAlloc|0x29"
        ],
        "LoD/1.13d": [
          "VirtualAlloc|0x29"
        ],
        "LoD/1.14a": [
          "VirtualAlloc|0x29"
        ],
        "LoD/1.14b": [
          "VirtualAlloc|0x29"
        ],
        "LoD/1.14c": [
          "VirtualAlloc|0x29"
        ],
        "LoD/1.14d": [
          "VirtualAlloc|0x29"
        ]
      },
      "callers": {
        "LoD/1.07": [
          "AllocateMemoryDescriptorBlock|0x403639"
        ],
        "LoD/1.08": [
          "AllocateMemoryDescriptorBlock|0x403639"
        ],
        "LoD/1.09": [
          "AllocateMemoryDescriptorBlock|0x403639"
        ],
        "LoD/1.09b": [
          "AllocateMemoryDescriptorBlock|0x403639"
        ],
        "LoD/1.09d": [
          "AllocateMemoryDescriptorBlock|0x403639"
        ],
        "LoD/1.10": [
          "AllocateMemoryDescriptorBlock|0x403639"
        ],
        "LoD/1.11": [
          "AllocateMemoryDescriptorBlock|0x403639"
        ],
        "LoD/1.11b": [
          "AllocateMemoryDescriptorBlock|0x403639"
        ],
        "LoD/1.12a": [
          "AllocateMemoryDescriptorBlock|0x403639"
        ],
        "LoD/1.13c": [
          "AllocateMemoryDescriptorBlock|0x403639"
        ],
        "LoD/1.13d": [
          "AllocateMemoryDescriptorBlock|0x403639"
        ],
        "LoD/1.14a": [
          "AllocateMemoryDescriptorBlock|0x403639"
        ],
        "LoD/1.14b": [
          "AllocateMemoryDescriptorBlock|0x403639"
        ],
        "LoD/1.14c": [
          "AllocateMemoryDescriptorBlock|0x403639"
        ],
        "LoD/1.14d": [
          "AllocateMemoryDescriptorBlock|0x403639"
        ]
      },
      "instruction_counts": {
        "LoD/1.07": 85,
        "LoD/1.08": 85,
        "LoD/1.09": 85,
        "LoD/1.09b": 85,
        "LoD/1.09d": 85,
        "LoD/1.10": 85,
        "LoD/1.11": 85,
        "LoD/1.11b": 85,
        "LoD/1.12a": 85,
        "LoD/1.13c": 85,
        "LoD/1.13d": 85,
        "LoD/1.14a": 85,
        "LoD/1.14b": 85,
        "LoD/1.14c": 85,
        "LoD/1.14d": 85
      },
      "stack_frame_sizes": {
        "LoD/1.07": 16,
        "LoD/1.08": 16,
        "LoD/1.09": 16,
        "LoD/1.09b": 16,
        "LoD/1.09d": 16,
        "LoD/1.10": 16,
        "LoD/1.11": 16,
        "LoD/1.11b": 16,
        "LoD/1.12a": 16,
        "LoD/1.13c": 16,
        "LoD/1.13d": 16,
        "LoD/1.14a": 16,
        "LoD/1.14b": 16,
        "LoD/1.14c": 16,
        "LoD/1.14d": 16
      },
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
        "LoD/1.13d": 14,
        "LoD/1.14a": 14,
        "LoD/1.14b": 14,
        "LoD/1.14c": 14,
        "LoD/1.14d": 14
      },
      "loop_counts": {
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
        "LoD/1.13d": 3,
        "LoD/1.14a": 3,
        "LoD/1.14b": 3,
        "LoD/1.14c": 3,
        "LoD/1.14d": 3
      },
      "mnemonic_hashes": {
        "LoD/1.07": "0002c858ef3942a0b403454c72674bfe",
        "LoD/1.08": "0002c858ef3942a0b403454c72674bfe",
        "LoD/1.09": "0002c858ef3942a0b403454c72674bfe",
        "LoD/1.09b": "0002c858ef3942a0b403454c72674bfe",
        "LoD/1.09d": "0002c858ef3942a0b403454c72674bfe",
        "LoD/1.10": "0002c858ef3942a0b403454c72674bfe",
        "LoD/1.11": "0002c858ef3942a0b403454c72674bfe",
        "LoD/1.11b": "0002c858ef3942a0b403454c72674bfe",
        "LoD/1.12a": "0002c858ef3942a0b403454c72674bfe",
        "LoD/1.13c": "0002c858ef3942a0b403454c72674bfe",
        "LoD/1.13d": "0002c858ef3942a0b403454c72674bfe",
        "LoD/1.14a": "0002c858ef3942a0b403454c72674bfe",
        "LoD/1.14b": "0002c858ef3942a0b403454c72674bfe",
        "LoD/1.14c": "0002c858ef3942a0b403454c72674bfe",
        "LoD/1.14d": "0002c858ef3942a0b403454c72674bfe"
      },
      "constants": {
        "LoD/1.07": [
          324,
          504,
          516,
          4072,
          4076,
          4080,
          4092,
          4096,
          28672,
          32768
        ],
        "LoD/1.08": [
          324,
          504,
          516,
          4072,
          4076,
          4080,
          4092,
          4096,
          28672,
          32768
        ],
        "LoD/1.09": [
          324,
          504,
          516,
          4072,
          4076,
          4080,
          4092,
          4096,
          28672,
          32768
        ],
        "LoD/1.09b": [
          324,
          504,
          516,
          4072,
          4076,
          4080,
          4092,
          4096,
          28672,
          32768
        ],
        "LoD/1.09d": [
          324,
          504,
          516,
          4072,
          4076,
          4080,
          4092,
          4096,
          28672,
          32768
        ],
        "LoD/1.10": [
          324,
          504,
          516,
          4072,
          4076,
          4080,
          4092,
          4096,
          28672,
          32768
        ],
        "LoD/1.11": [
          324,
          504,
          516,
          4072,
          4076,
          4080,
          4092,
          4096,
          28672,
          32768
        ],
        "LoD/1.11b": [
          324,
          504,
          516,
          4072,
          4076,
          4080,
          4092,
          4096,
          28672,
          32768
        ],
        "LoD/1.12a": [
          324,
          504,
          516,
          4072,
          4076,
          4080,
          4092,
          4096,
          28672,
          32768
        ],
        "LoD/1.13c": [
          324,
          504,
          516,
          4072,
          4076,
          4080,
          4092,
          4096,
          28672,
          32768
        ],
        "LoD/1.13d": [
          324,
          504,
          516,
          4072,
          4076,
          4080,
          4092,
          4096,
          28672,
          32768
        ],
        "LoD/1.14a": [
          324,
          504,
          516,
          4072,
          4076,
          4080,
          4092,
          4096,
          28672,
          32768
        ],
        "LoD/1.14b": [
          324,
          504,
          516,
          4072,
          4076,
          4080,
          4092,
          4096,
          28672,
          32768
        ],
        "LoD/1.14c": [
          324,
          504,
          516,
          4072,
          4076,
          4080,
          4092,
          4096,
          28672,
          32768
        ],
        "LoD/1.14d": [
          324,
          504,
          516,
          4072,
          4076,
          4080,
          4092,
          4096,
          28672,
          32768
        ]
      },
      "globals": {
        "LoD/1.07": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFBFFFF8|",
          "0x50A0|PTR_VirtualAlloc_004050a0"
        ],
        "LoD/1.08": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFBFFFF8|",
          "0x50A0|PTR_VirtualAlloc_004050a0"
        ],
        "LoD/1.09": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFBFFFF8|",
          "0x50A0|PTR_VirtualAlloc_004050a0"
        ],
        "LoD/1.09b": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFBFFFF8|",
          "0x50A0|PTR_VirtualAlloc_004050a0"
        ],
        "LoD/1.09d": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFBFFFF8|",
          "0x50A0|PTR_VirtualAlloc_004050a0"
        ],
        "LoD/1.10": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFBFFFF8|",
          "0x50A0|PTR_VirtualAlloc_004050a0"
        ],
        "LoD/1.11": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFBFFFF8|",
          "0x50A0|PTR_VirtualAlloc_004050a0"
        ],
        "LoD/1.11b": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFBFFFF8|",
          "0x50A0|PTR_VirtualAlloc_004050a0"
        ],
        "LoD/1.12a": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFBFFFF8|",
          "0x50A0|PTR_VirtualAlloc_004050a0"
        ],
        "LoD/1.13c": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFBFFFF8|",
          "0x50A0|PTR_VirtualAlloc_004050a0"
        ],
        "LoD/1.13d": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFBFFFF8|",
          "0x50A0|PTR_VirtualAlloc_004050a0"
        ],
        "LoD/1.14a": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFBFFFF8|",
          "0x50A0|PTR_VirtualAlloc_004050a0"
        ],
        "LoD/1.14b": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFBFFFF8|",
          "0x50A0|PTR_VirtualAlloc_004050a0"
        ],
        "LoD/1.14c": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFBFFFF8|",
          "0x50A0|PTR_VirtualAlloc_004050a0"
        ],
        "LoD/1.14d": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFBFFFF8|",
          "0x50A0|PTR_VirtualAlloc_004050a0"
        ]
      }
    },
    "diablo ii.exe_ShowMessageBoxWithActiveWindow": {
      "addresses": {
        "LoD/1.07": "0x00403AEE",
        "LoD/1.08": "0x00403AEE",
        "LoD/1.09": "0x00403AEE",
        "LoD/1.09b": "0x00403AEE",
        "LoD/1.09d": "0x00403AEE",
        "LoD/1.10": "0x00403AEE",
        "LoD/1.11": "0x00403AEE",
        "LoD/1.11b": "0x00403AEE",
        "LoD/1.12a": "0x00403AEE",
        "LoD/1.13c": "0x00403AEE",
        "LoD/1.13d": "0x00403AEE",
        "LoD/1.14a": "0x00403AEE",
        "LoD/1.14b": "0x00403AEE",
        "LoD/1.14c": "0x00403AEE",
        "LoD/1.14d": "0x00403AEE"
      },
      "rvas": {
        "LoD/1.07": "0x3AEE",
        "LoD/1.08": "0x3AEE",
        "LoD/1.09": "0x3AEE",
        "LoD/1.09b": "0x3AEE",
        "LoD/1.09d": "0x3AEE",
        "LoD/1.10": "0x3AEE",
        "LoD/1.11": "0x3AEE",
        "LoD/1.11b": "0x3AEE",
        "LoD/1.12a": "0x3AEE",
        "LoD/1.13c": "0x3AEE",
        "LoD/1.13d": "0x3AEE",
        "LoD/1.14a": "0x3AEE",
        "LoD/1.14b": "0x3AEE",
        "LoD/1.14c": "0x3AEE",
        "LoD/1.14d": "0x3AEE"
      },
      "sizes": {
        "LoD/1.07": 137,
        "LoD/1.08": 137,
        "LoD/1.09": 137,
        "LoD/1.09b": 137,
        "LoD/1.09d": 137,
        "LoD/1.10": 137,
        "LoD/1.11": 137,
        "LoD/1.11b": 137,
        "LoD/1.12a": 137,
        "LoD/1.13c": 137,
        "LoD/1.13d": 137,
        "LoD/1.14a": 137,
        "LoD/1.14b": 137,
        "LoD/1.14c": 137,
        "LoD/1.14d": 137
      },
      "name": "ShowMessageBoxWithActiveWindow",
      "signature": "int ShowMessageBoxWithActiveWindow(char * lpszText, char * lpszCaption, int nType)",
      "calling_convention": "__cdecl",
      "return_type": "int",
      "comment": "Displays a message box using dynamic loading of user32.dll functions with active window detection.\n\nAlgorithm:\n\n1. Check if MessageBoxA function pointer is already loaded (DAT_1003ca8c)\n2. If not loaded, dynamically load user32.dll using LoadLibraryA\n3. Get function pointers for MessageBoxA, GetActiveWindow, and GetLastActivePopup\n4. Store function pointers in global variables (DAT_1003ca8c, DAT_1003ca90, DAT_1003ca94)\n5. If GetActiveWindow is available, call it to get active window handle\n6. If active window exists and GetLastActivePopup is available, get last active popup\n7. Call MessageBoxA with detected window handle and provided text, caption, and type\n8. Return the result from MessageBoxA\n\nParameters:\n\nlpszText - Pointer to null-terminated string containing message text to display\nlpszCaption - Pointer to null-terminated string containing dialog caption/title\nnType - Message box type flags controlling buttons and icon (MB_OK, MB_ICONERROR, etc.)\n\nReturns:\n\nInteger result from MessageBoxA indicating which button was pressed:\n- IDOK (1) if OK button clicked\n- IDCANCEL (2) if Cancel button clicked  \n- IDABORT (3) if Abort button clicked\n- IDRETRY (4) if Retry button clicked\n- IDIGNORE (5) if Ignore button clicked\n- IDYES (6) if Yes button clicked\n- IDNO (7) if No button clicked\n- 0 if function initialization failed\n\nSpecial Cases:\n\nIf user32.dll cannot be loaded or required functions cannot be found, returns 0.\nUses lazy loading pattern - initializes function pointers only on first call.\nWindow handle detection provides proper message box parenting for modal behavior.\n\nGlobal Variables:\n\nDAT_1003ca8c - Function pointer to MessageBoxA (FARPROC)\nDAT_1003ca90 - Function pointer to GetActiveWindow (FARPROC) \nDAT_1003ca94 - Function pointer to GetLastActivePopup (FARPROC)",
      "name_source": "LoD/1.07",
      "method": "STR",
      "index": "STR:1d436b74681e11a9bd214b6331c37f94",
      "indexes": {
        "EXP": null,
        "STR": "1d436b74681e11a9bd214b6331c37f94",
        "API": null,
        "MNE": "d28466b802ff41201d4ac81308d22266",
        "CFG": "df5c6e7657bf03b5e12df2df4e8951a5",
        "PRO": "e0ac0c93da57517ada9568fe18581bfb",
        "CAL": "6815bfbd6fdd9e2bf9bacba9c707ff1e",
        "CON": "09008a8029a6964fd456536138290bb0",
        "APS": null
      },
      "callees": {
        "LoD/1.07": [
          "LoadLibraryA|0x1B",
          "GetProcAddress|0xA"
        ],
        "LoD/1.08": [
          "GetProcAddress|0xA",
          "LoadLibraryA|0x1B"
        ],
        "LoD/1.09": [
          "GetProcAddress|0xA",
          "LoadLibraryA|0x1B"
        ],
        "LoD/1.09b": [
          "LoadLibraryA|0x1B",
          "GetProcAddress|0xA"
        ],
        "LoD/1.09d": [
          "LoadLibraryA|0x1B",
          "GetProcAddress|0xA"
        ],
        "LoD/1.10": [
          "LoadLibraryA|0x1B",
          "GetProcAddress|0xA"
        ],
        "LoD/1.11": [
          "GetProcAddress|0xA",
          "LoadLibraryA|0x1B"
        ],
        "LoD/1.11b": [
          "LoadLibraryA|0x1B",
          "GetProcAddress|0xA"
        ],
        "LoD/1.12a": [
          "LoadLibraryA|0x1B",
          "GetProcAddress|0xA"
        ],
        "LoD/1.13c": [
          "GetProcAddress|0xA",
          "LoadLibraryA|0x1B"
        ],
        "LoD/1.13d": [
          "LoadLibraryA|0x1B",
          "GetProcAddress|0xA"
        ],
        "LoD/1.14a": [
          "GetProcAddress|0xA",
          "LoadLibraryA|0x1B"
        ],
        "LoD/1.14b": [
          "GetProcAddress|0xA",
          "LoadLibraryA|0x1B"
        ],
        "LoD/1.14c": [
          "GetProcAddress|0xA",
          "LoadLibraryA|0x1B"
        ],
        "LoD/1.14d": [
          "LoadLibraryA|0x1B",
          "GetProcAddress|0xA"
        ]
      },
      "callers": {
        "LoD/1.07": [
          "DisplayRuntimeError|0x402789"
        ],
        "LoD/1.08": [
          "DisplayRuntimeError|0x402789"
        ],
        "LoD/1.09": [
          "DisplayRuntimeError|0x402789"
        ],
        "LoD/1.09b": [
          "DisplayRuntimeError|0x402789"
        ],
        "LoD/1.09d": [
          "DisplayRuntimeError|0x402789"
        ],
        "LoD/1.10": [
          "DisplayRuntimeError|0x402789"
        ],
        "LoD/1.11": [
          "DisplayRuntimeError|0x402789"
        ],
        "LoD/1.11b": [
          "DisplayRuntimeError|0x402789"
        ],
        "LoD/1.12a": [
          "DisplayRuntimeError|0x402789"
        ],
        "LoD/1.13c": [
          "DisplayRuntimeError|0x402789"
        ],
        "LoD/1.13d": [
          "DisplayRuntimeError|0x402789"
        ],
        "LoD/1.14a": [
          "DisplayRuntimeError|0x402789"
        ],
        "LoD/1.14b": [
          "DisplayRuntimeError|0x402789"
        ],
        "LoD/1.14c": [
          "DisplayRuntimeError|0x402789"
        ],
        "LoD/1.14d": [
          "DisplayRuntimeError|0x402789"
        ]
      },
      "strings": {
        "LoD/1.07": [
          "\"GetLastActivePopup\"",
          "\"user32.dll\"",
          "\"MessageBoxA\"",
          "\"GetActiveWindow\""
        ],
        "LoD/1.08": [
          "\"GetLastActivePopup\"",
          "\"user32.dll\"",
          "\"MessageBoxA\"",
          "\"GetActiveWindow\""
        ],
        "LoD/1.09": [
          "\"GetLastActivePopup\"",
          "\"user32.dll\"",
          "\"MessageBoxA\"",
          "\"GetActiveWindow\""
        ],
        "LoD/1.09b": [
          "\"GetLastActivePopup\"",
          "\"user32.dll\"",
          "\"MessageBoxA\"",
          "\"GetActiveWindow\""
        ],
        "LoD/1.09d": [
          "\"GetLastActivePopup\"",
          "\"user32.dll\"",
          "\"MessageBoxA\"",
          "\"GetActiveWindow\""
        ],
        "LoD/1.10": [
          "\"GetLastActivePopup\"",
          "\"user32.dll\"",
          "\"MessageBoxA\"",
          "\"GetActiveWindow\""
        ],
        "LoD/1.11": [
          "\"GetLastActivePopup\"",
          "\"user32.dll\"",
          "\"MessageBoxA\"",
          "\"GetActiveWindow\""
        ],
        "LoD/1.11b": [
          "\"GetLastActivePopup\"",
          "\"user32.dll\"",
          "\"MessageBoxA\"",
          "\"GetActiveWindow\""
        ],
        "LoD/1.12a": [
          "\"GetLastActivePopup\"",
          "\"user32.dll\"",
          "\"MessageBoxA\"",
          "\"GetActiveWindow\""
        ],
        "LoD/1.13c": [
          "\"GetLastActivePopup\"",
          "\"user32.dll\"",
          "\"MessageBoxA\"",
          "\"GetActiveWindow\""
        ],
        "LoD/1.13d": [
          "\"GetLastActivePopup\"",
          "\"user32.dll\"",
          "\"MessageBoxA\"",
          "\"GetActiveWindow\""
        ],
        "LoD/1.14a": [
          "\"GetLastActivePopup\"",
          "\"user32.dll\"",
          "\"MessageBoxA\"",
          "\"GetActiveWindow\""
        ],
        "LoD/1.14b": [
          "\"GetLastActivePopup\"",
          "\"user32.dll\"",
          "\"MessageBoxA\"",
          "\"GetActiveWindow\""
        ],
        "LoD/1.14c": [
          "\"GetLastActivePopup\"",
          "\"user32.dll\"",
          "\"MessageBoxA\"",
          "\"GetActiveWindow\""
        ],
        "LoD/1.14d": [
          "\"GetLastActivePopup\"",
          "\"user32.dll\"",
          "\"MessageBoxA\"",
          "\"GetActiveWindow\""
        ]
      },
      "instruction_counts": {
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
        "LoD/1.13d": 50,
        "LoD/1.14a": 50,
        "LoD/1.14b": 50,
        "LoD/1.14c": 50,
        "LoD/1.14d": 50
      },
      "stack_frame_sizes": {
        "LoD/1.07": 16,
        "LoD/1.08": 16,
        "LoD/1.09": 16,
        "LoD/1.09b": 16,
        "LoD/1.09d": 16,
        "LoD/1.10": 16,
        "LoD/1.11": 16,
        "LoD/1.11b": 16,
        "LoD/1.12a": 16,
        "LoD/1.13c": 16,
        "LoD/1.13d": 16,
        "LoD/1.14a": 16,
        "LoD/1.14b": 16,
        "LoD/1.14c": 16,
        "LoD/1.14d": 16
      },
      "basic_block_counts": {
        "LoD/1.07": 11,
        "LoD/1.08": 11,
        "LoD/1.09": 11,
        "LoD/1.09b": 11,
        "LoD/1.09d": 11,
        "LoD/1.10": 11,
        "LoD/1.11": 11,
        "LoD/1.11b": 11,
        "LoD/1.12a": 11,
        "LoD/1.13c": 11,
        "LoD/1.13d": 11,
        "LoD/1.14a": 11,
        "LoD/1.14b": 11,
        "LoD/1.14c": 11,
        "LoD/1.14d": 11
      },
      "loop_counts": {
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
        "LoD/1.13d": 1,
        "LoD/1.14a": 1,
        "LoD/1.14b": 1,
        "LoD/1.14c": 1,
        "LoD/1.14d": 1
      },
      "mnemonic_hashes": {
        "LoD/1.07": "d28466b802ff41201d4ac81308d22266",
        "LoD/1.08": "d28466b802ff41201d4ac81308d22266",
        "LoD/1.09": "d28466b802ff41201d4ac81308d22266",
        "LoD/1.09b": "d28466b802ff41201d4ac81308d22266",
        "LoD/1.09d": "d28466b802ff41201d4ac81308d22266",
        "LoD/1.10": "d28466b802ff41201d4ac81308d22266",
        "LoD/1.11": "d28466b802ff41201d4ac81308d22266",
        "LoD/1.11b": "d28466b802ff41201d4ac81308d22266",
        "LoD/1.12a": "d28466b802ff41201d4ac81308d22266",
        "LoD/1.13c": "d28466b802ff41201d4ac81308d22266",
        "LoD/1.13d": "d28466b802ff41201d4ac81308d22266",
        "LoD/1.14a": "d28466b802ff41201d4ac81308d22266",
        "LoD/1.14b": "d28466b802ff41201d4ac81308d22266",
        "LoD/1.14c": "d28466b802ff41201d4ac81308d22266",
        "LoD/1.14d": "d28466b802ff41201d4ac81308d22266"
      },
      "constants": {
        "LoD/1.07": [
          4215780,
          4215800,
          4215816,
          4215828
        ],
        "LoD/1.08": [
          4215780,
          4215800,
          4215816,
          4215828
        ],
        "LoD/1.09": [
          4215780,
          4215800,
          4215816,
          4215828
        ],
        "LoD/1.09b": [
          4215780,
          4215800,
          4215816,
          4215828
        ],
        "LoD/1.09d": [
          4215780,
          4215800,
          4215816,
          4215828
        ],
        "LoD/1.10": [
          4215780,
          4215800,
          4215816,
          4215828
        ],
        "LoD/1.11": [
          4215780,
          4215800,
          4215816,
          4215828
        ],
        "LoD/1.11b": [
          4215780,
          4215800,
          4215816,
          4215828
        ],
        "LoD/1.12a": [
          4215780,
          4215800,
          4215816,
          4215828
        ],
        "LoD/1.13c": [
          4215780,
          4215800,
          4215816,
          4215828
        ],
        "LoD/1.13d": [
          4215780,
          4215800,
          4215816,
          4215828
        ],
        "LoD/1.14a": [
          4215780,
          4215800,
          4215816,
          4215828
        ],
        "LoD/1.14b": [
          4215780,
          4215800,
          4215816,
          4215828
        ],
        "LoD/1.14c": [
          4215780,
          4215800,
          4215816,
          4215828
        ],
        "LoD/1.14d": [
          4215780,
          4215800,
          4215816,
          4215828
        ]
      },
      "globals": {
        "LoD/1.07": [
          "0x6648|g_pfnMessageBoxA",
          "0x5414|s_user32.dll_00405414",
          "0x5068|PTR_LoadLibraryA_00405068",
          "0x5024|PTR_GetProcAddress_00405024",
          "0x5408|s_MessageBoxA_00405408",
          "0x53F8|s_GetActiveWindow_004053f8",
          "0x53E4|s_GetLastActivePopup_004053e4",
          "0x664C|g_pfnGetActiveWindow",
          "0x6650|g_pfnGetLastActivePopup"
        ],
        "LoD/1.08": [
          "0x6648|g_pfnMessageBoxA",
          "0x5414|s_user32.dll_00405414",
          "0x5068|PTR_LoadLibraryA_00405068",
          "0x5024|PTR_GetProcAddress_00405024",
          "0x5408|s_MessageBoxA_00405408",
          "0x53F8|s_GetActiveWindow_004053f8",
          "0x53E4|s_GetLastActivePopup_004053e4",
          "0x664C|g_pfnGetActiveWindow",
          "0x6650|g_pfnGetLastActivePopup"
        ],
        "LoD/1.09": [
          "0x6648|g_pfnMessageBoxA",
          "0x5414|s_user32.dll_00405414",
          "0x5068|PTR_LoadLibraryA_00405068",
          "0x5024|PTR_GetProcAddress_00405024",
          "0x5408|s_MessageBoxA_00405408",
          "0x53F8|s_GetActiveWindow_004053f8",
          "0x53E4|s_GetLastActivePopup_004053e4",
          "0x664C|g_pfnGetActiveWindow",
          "0x6650|g_pfnGetLastActivePopup"
        ],
        "LoD/1.09b": [
          "0x6648|g_pfnMessageBoxA",
          "0x5414|s_user32.dll_00405414",
          "0x5068|PTR_LoadLibraryA_00405068",
          "0x5024|PTR_GetProcAddress_00405024",
          "0x5408|s_MessageBoxA_00405408",
          "0x53F8|s_GetActiveWindow_004053f8",
          "0x53E4|s_GetLastActivePopup_004053e4",
          "0x664C|g_pfnGetActiveWindow",
          "0x6650|g_pfnGetLastActivePopup"
        ],
        "LoD/1.09d": [
          "0x6648|g_pfnMessageBoxA",
          "0x5414|s_user32.dll_00405414",
          "0x5068|PTR_LoadLibraryA_00405068",
          "0x5024|PTR_GetProcAddress_00405024",
          "0x5408|s_MessageBoxA_00405408",
          "0x53F8|s_GetActiveWindow_004053f8",
          "0x53E4|s_GetLastActivePopup_004053e4",
          "0x664C|g_pfnGetActiveWindow",
          "0x6650|g_pfnGetLastActivePopup"
        ],
        "LoD/1.10": [
          "0x6648|g_pfnMessageBoxA",
          "0x5414|s_user32.dll_00405414",
          "0x5068|PTR_LoadLibraryA_00405068",
          "0x5024|PTR_GetProcAddress_00405024",
          "0x5408|s_MessageBoxA_00405408",
          "0x53F8|s_GetActiveWindow_004053f8",
          "0x53E4|s_GetLastActivePopup_004053e4",
          "0x664C|g_pfnGetActiveWindow",
          "0x6650|g_pfnGetLastActivePopup"
        ],
        "LoD/1.11": [
          "0x6648|g_pfnMessageBoxA",
          "0x5414|s_user32.dll_00405414",
          "0x5068|PTR_LoadLibraryA_00405068",
          "0x5024|PTR_GetProcAddress_00405024",
          "0x5408|s_MessageBoxA_00405408",
          "0x53F8|s_GetActiveWindow_004053f8",
          "0x53E4|s_GetLastActivePopup_004053e4",
          "0x664C|g_pfnGetActiveWindow",
          "0x6650|g_pfnGetLastActivePopup"
        ],
        "LoD/1.11b": [
          "0x6648|g_pfnMessageBoxA",
          "0x5414|s_user32.dll_00405414",
          "0x5068|PTR_LoadLibraryA_00405068",
          "0x5024|PTR_GetProcAddress_00405024",
          "0x5408|s_MessageBoxA_00405408",
          "0x53F8|s_GetActiveWindow_004053f8",
          "0x53E4|s_GetLastActivePopup_004053e4",
          "0x664C|g_pfnGetActiveWindow",
          "0x6650|g_pfnGetLastActivePopup"
        ],
        "LoD/1.12a": [
          "0x6648|g_pfnMessageBoxA",
          "0x5414|s_user32.dll_00405414",
          "0x5068|PTR_LoadLibraryA_00405068",
          "0x5024|PTR_GetProcAddress_00405024",
          "0x5408|s_MessageBoxA_00405408",
          "0x53F8|s_GetActiveWindow_004053f8",
          "0x53E4|s_GetLastActivePopup_004053e4",
          "0x664C|g_pfnGetActiveWindow",
          "0x6650|g_pfnGetLastActivePopup"
        ],
        "LoD/1.13c": [
          "0x6648|g_pfnMessageBoxA",
          "0x5414|s_user32.dll_00405414",
          "0x5068|PTR_LoadLibraryA_00405068",
          "0x5024|PTR_GetProcAddress_00405024",
          "0x5408|s_MessageBoxA_00405408",
          "0x53F8|s_GetActiveWindow_004053f8",
          "0x53E4|s_GetLastActivePopup_004053e4",
          "0x664C|g_pfnGetActiveWindow",
          "0x6650|g_pfnGetLastActivePopup"
        ],
        "LoD/1.13d": [
          "0x6648|g_pfnMessageBoxA",
          "0x5414|s_user32.dll_00405414",
          "0x5068|PTR_LoadLibraryA_00405068",
          "0x5024|PTR_GetProcAddress_00405024",
          "0x5408|s_MessageBoxA_00405408",
          "0x53F8|s_GetActiveWindow_004053f8",
          "0x53E4|s_GetLastActivePopup_004053e4",
          "0x664C|g_pfnGetActiveWindow",
          "0x6650|g_pfnGetLastActivePopup"
        ],
        "LoD/1.14a": [
          "0x6648|g_pfnMessageBoxA",
          "0x5414|s_user32.dll_00405414",
          "0x5068|PTR_LoadLibraryA_00405068",
          "0x5024|PTR_GetProcAddress_00405024",
          "0x5408|s_MessageBoxA_00405408",
          "0x53F8|s_GetActiveWindow_004053f8",
          "0x53E4|s_GetLastActivePopup_004053e4",
          "0x664C|g_pfnGetActiveWindow",
          "0x6650|g_pfnGetLastActivePopup"
        ],
        "LoD/1.14b": [
          "0x6648|g_pfnMessageBoxA",
          "0x5414|s_user32.dll_00405414",
          "0x5068|PTR_LoadLibraryA_00405068",
          "0x5024|PTR_GetProcAddress_00405024",
          "0x5408|s_MessageBoxA_00405408",
          "0x53F8|s_GetActiveWindow_004053f8",
          "0x53E4|s_GetLastActivePopup_004053e4",
          "0x664C|g_pfnGetActiveWindow",
          "0x6650|g_pfnGetLastActivePopup"
        ],
        "LoD/1.14c": [
          "0x6648|g_pfnMessageBoxA",
          "0x5414|s_user32.dll_00405414",
          "0x5068|PTR_LoadLibraryA_00405068",
          "0x5024|PTR_GetProcAddress_00405024",
          "0x5408|s_MessageBoxA_00405408",
          "0x53F8|s_GetActiveWindow_004053f8",
          "0x53E4|s_GetLastActivePopup_004053e4",
          "0x664C|g_pfnGetActiveWindow",
          "0x6650|g_pfnGetLastActivePopup"
        ],
        "LoD/1.14d": [
          "0x6648|g_pfnMessageBoxA",
          "0x5414|s_user32.dll_00405414",
          "0x5068|PTR_LoadLibraryA_00405068",
          "0x5024|PTR_GetProcAddress_00405024",
          "0x5408|s_MessageBoxA_00405408",
          "0x53F8|s_GetActiveWindow_004053f8",
          "0x53E4|s_GetLastActivePopup_004053e4",
          "0x664C|g_pfnGetActiveWindow",
          "0x6650|g_pfnGetLastActivePopup"
        ]
      }
    },
    "diablo ii.exe__strncpy": {
      "addresses": {
        "LoD/1.07": "0x00403B80",
        "LoD/1.08": "0x00403B80",
        "LoD/1.09": "0x00403B80",
        "LoD/1.09b": "0x00403B80",
        "LoD/1.09d": "0x00403B80",
        "LoD/1.10": "0x00403B80",
        "LoD/1.11": "0x00403B80",
        "LoD/1.11b": "0x00403B80",
        "LoD/1.12a": "0x00403B80",
        "LoD/1.13c": "0x00403B80",
        "LoD/1.13d": "0x00403B80",
        "LoD/1.14a": "0x00403B80",
        "LoD/1.14b": "0x00403B80",
        "LoD/1.14c": "0x00403B80",
        "LoD/1.14d": "0x00403B80"
      },
      "rvas": {
        "LoD/1.07": "0x3B80",
        "LoD/1.08": "0x3B80",
        "LoD/1.09": "0x3B80",
        "LoD/1.09b": "0x3B80",
        "LoD/1.09d": "0x3B80",
        "LoD/1.10": "0x3B80",
        "LoD/1.11": "0x3B80",
        "LoD/1.11b": "0x3B80",
        "LoD/1.12a": "0x3B80",
        "LoD/1.13c": "0x3B80",
        "LoD/1.13d": "0x3B80",
        "LoD/1.14a": "0x3B80",
        "LoD/1.14b": "0x3B80",
        "LoD/1.14c": "0x3B80",
        "LoD/1.14d": "0x3B80"
      },
      "sizes": {
        "LoD/1.07": 254,
        "LoD/1.08": 254,
        "LoD/1.09": 254,
        "LoD/1.09b": 254,
        "LoD/1.09d": 254,
        "LoD/1.10": 254,
        "LoD/1.11": 254,
        "LoD/1.11b": 254,
        "LoD/1.12a": 254,
        "LoD/1.13c": 254,
        "LoD/1.13d": 254,
        "LoD/1.14a": 254,
        "LoD/1.14b": 254,
        "LoD/1.14c": 254,
        "LoD/1.14d": 254
      },
      "name": "_strncpy",
      "signature": "char * _strncpy(char * _Dest, char * _Source, size_t _Count)",
      "calling_convention": "__cdecl",
      "return_type": "char *",
      "comment": "Library Function - Single Match\n _strncpy\n\nLibraries: Visual Studio 1998 Debug, Visual Studio 1998 Release",
      "name_source": "LoD/1.07",
      "method": "CON",
      "index": "CON:b35d7544ccb06f0fede567c578bacd51",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "60fb4369558c571ee3e9892006835a82",
        "CFG": "1cca209eac1c43a753e574cbe330b905",
        "PRO": "5dfddeed7b00a61835a5cf192d4d7c3e",
        "CAL": null,
        "CON": "b35d7544ccb06f0fede567c578bacd51",
        "APS": null
      },
      "callers": {
        "LoD/1.07": [
          "DisplayRuntimeError|0x402789"
        ],
        "LoD/1.08": [
          "DisplayRuntimeError|0x402789"
        ],
        "LoD/1.09": [
          "DisplayRuntimeError|0x402789"
        ],
        "LoD/1.09b": [
          "DisplayRuntimeError|0x402789"
        ],
        "LoD/1.09d": [
          "DisplayRuntimeError|0x402789"
        ],
        "LoD/1.10": [
          "DisplayRuntimeError|0x402789"
        ],
        "LoD/1.11": [
          "DisplayRuntimeError|0x402789"
        ],
        "LoD/1.11b": [
          "DisplayRuntimeError|0x402789"
        ],
        "LoD/1.12a": [
          "DisplayRuntimeError|0x402789"
        ],
        "LoD/1.13c": [
          "DisplayRuntimeError|0x402789"
        ],
        "LoD/1.13d": [
          "DisplayRuntimeError|0x402789"
        ],
        "LoD/1.14a": [
          "DisplayRuntimeError|0x402789"
        ],
        "LoD/1.14b": [
          "DisplayRuntimeError|0x402789"
        ],
        "LoD/1.14c": [
          "DisplayRuntimeError|0x402789"
        ],
        "LoD/1.14d": [
          "DisplayRuntimeError|0x402789"
        ]
      },
      "instruction_counts": {
        "LoD/1.07": 109,
        "LoD/1.08": 109,
        "LoD/1.09": 109,
        "LoD/1.09b": 109,
        "LoD/1.09d": 109,
        "LoD/1.10": 109,
        "LoD/1.11": 109,
        "LoD/1.11b": 109,
        "LoD/1.12a": 109,
        "LoD/1.13c": 109,
        "LoD/1.13d": 109,
        "LoD/1.14a": 109,
        "LoD/1.14b": 109,
        "LoD/1.14c": 109,
        "LoD/1.14d": 109
      },
      "stack_frame_sizes": {
        "LoD/1.07": 16,
        "LoD/1.08": 16,
        "LoD/1.09": 16,
        "LoD/1.09b": 16,
        "LoD/1.09d": 16,
        "LoD/1.10": 16,
        "LoD/1.11": 16,
        "LoD/1.11b": 16,
        "LoD/1.12a": 16,
        "LoD/1.13c": 16,
        "LoD/1.13d": 16,
        "LoD/1.14a": 16,
        "LoD/1.14b": 16,
        "LoD/1.14c": 16,
        "LoD/1.14d": 16
      },
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
        "LoD/1.13d": 35,
        "LoD/1.14a": 35,
        "LoD/1.14b": 35,
        "LoD/1.14c": 35,
        "LoD/1.14d": 35
      },
      "loop_counts": {
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
        "LoD/1.13d": 9,
        "LoD/1.14a": 9,
        "LoD/1.14b": 9,
        "LoD/1.14c": 9,
        "LoD/1.14d": 9
      },
      "mnemonic_hashes": {
        "LoD/1.07": "60fb4369558c571ee3e9892006835a82",
        "LoD/1.08": "60fb4369558c571ee3e9892006835a82",
        "LoD/1.09": "60fb4369558c571ee3e9892006835a82",
        "LoD/1.09b": "60fb4369558c571ee3e9892006835a82",
        "LoD/1.09d": "60fb4369558c571ee3e9892006835a82",
        "LoD/1.10": "60fb4369558c571ee3e9892006835a82",
        "LoD/1.11": "60fb4369558c571ee3e9892006835a82",
        "LoD/1.11b": "60fb4369558c571ee3e9892006835a82",
        "LoD/1.12a": "60fb4369558c571ee3e9892006835a82",
        "LoD/1.13c": "60fb4369558c571ee3e9892006835a82",
        "LoD/1.13d": "60fb4369558c571ee3e9892006835a82",
        "LoD/1.14a": "60fb4369558c571ee3e9892006835a82",
        "LoD/1.14b": "60fb4369558c571ee3e9892006835a82",
        "LoD/1.14c": "60fb4369558c571ee3e9892006835a82",
        "LoD/1.14d": "60fb4369558c571ee3e9892006835a82"
      },
      "constants": {
        "LoD/1.07": [
          65535,
          16711680
        ],
        "LoD/1.08": [
          65535,
          16711680
        ],
        "LoD/1.09": [
          65535,
          16711680
        ],
        "LoD/1.09b": [
          65535,
          16711680
        ],
        "LoD/1.09d": [
          65535,
          16711680
        ],
        "LoD/1.10": [
          65535,
          16711680
        ],
        "LoD/1.11": [
          65535,
          16711680
        ],
        "LoD/1.11b": [
          65535,
          16711680
        ],
        "LoD/1.12a": [
          65535,
          16711680
        ],
        "LoD/1.13c": [
          65535,
          16711680
        ],
        "LoD/1.13d": [
          65535,
          16711680
        ],
        "LoD/1.14a": [
          65535,
          16711680
        ],
        "LoD/1.14b": [
          65535,
          16711680
        ],
        "LoD/1.14c": [
          65535,
          16711680
        ],
        "LoD/1.14d": [
          65535,
          16711680
        ]
      },
      "globals": {
        "LoD/1.07": [
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.08": [
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.09": [
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.09b": [
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.09d": [
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.10": [
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.11": [
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.11b": [
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.12a": [
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.13c": [
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.13d": [
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.14a": [
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.14b": [
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.14c": [
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.14d": [
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|"
        ]
      }
    },
    "diablo ii.exe_AllocateStackSpace": {
      "addresses": {
        "LoD/1.07": "0x00403C80",
        "LoD/1.08": "0x00403C80",
        "LoD/1.09": "0x00403C80",
        "LoD/1.09b": "0x00403C80",
        "LoD/1.09d": "0x00403C80",
        "LoD/1.10": "0x00403C80",
        "LoD/1.11": "0x00403C80",
        "LoD/1.11b": "0x00403C80",
        "LoD/1.12a": "0x00403C80",
        "LoD/1.13c": "0x00403C80",
        "LoD/1.13d": "0x00403C80",
        "LoD/1.14a": "0x00403C80",
        "LoD/1.14b": "0x00403C80",
        "LoD/1.14c": "0x00403C80",
        "LoD/1.14d": "0x00403C80"
      },
      "rvas": {
        "LoD/1.07": "0x3C80",
        "LoD/1.08": "0x3C80",
        "LoD/1.09": "0x3C80",
        "LoD/1.09b": "0x3C80",
        "LoD/1.09d": "0x3C80",
        "LoD/1.10": "0x3C80",
        "LoD/1.11": "0x3C80",
        "LoD/1.11b": "0x3C80",
        "LoD/1.12a": "0x3C80",
        "LoD/1.13c": "0x3C80",
        "LoD/1.13d": "0x3C80",
        "LoD/1.14a": "0x3C80",
        "LoD/1.14b": "0x3C80",
        "LoD/1.14c": "0x3C80",
        "LoD/1.14d": "0x3C80"
      },
      "sizes": {
        "LoD/1.07": 47,
        "LoD/1.08": 47,
        "LoD/1.09": 47,
        "LoD/1.09b": 47,
        "LoD/1.09d": 47,
        "LoD/1.10": 47,
        "LoD/1.11": 47,
        "LoD/1.11b": 47,
        "LoD/1.12a": 47,
        "LoD/1.13c": 47,
        "LoD/1.13d": 47,
        "LoD/1.14a": 47,
        "LoD/1.14b": 47,
        "LoD/1.14c": 47,
        "LoD/1.14d": 47
      },
      "name": "AllocateStackSpace",
      "signature": "void AllocateStackSpace(void)",
      "calling_convention": "__stdcall",
      "return_type": "void",
      "comment": "Dynamically allocates stack space with page probing to ensure proper memory commitment.\n\nAlgorithm:\n1. Initialize stack pointer to current position plus 8 bytes (beyond return address and saved ECX)\n2. Check if requested allocation size exceeds one page (0x1000 bytes)\n3. If multi-page allocation needed, enter probing loop:\n   - Subtract one page (0x1000 bytes) from stack pointer\n   - Subtract one page from remaining allocation size\n   - Touch memory at stack pointer to trigger page commitment\n   - Repeat until remaining size is less than one page\n4. Subtract final remaining bytes from stack pointer\n5. Touch memory at final stack position to commit last page\n6. Update ESP register to new stack pointer position\n7. Restore original ECX and return address from saved stack frame\n8. Return to caller with stack space allocated and committed\n\nParameters:\ndwStackSize (uint) - Number of bytes to allocate on stack\n\nReturns:\nvoid - No return value, modifies stack pointer directly\n\nSpecial Cases:\n- Single page allocations (\u2264 0xFFF bytes) skip the probing loop\n- Memory touches use TEST instruction to trigger page faults for uncommitted pages\n- Stack grows downward, so allocation decreases stack pointer\n- Function preserves ECX register across call\n\nMagic Numbers Reference:\n0x1000 (4096) - Windows page size for stack probing\n0xFFF (4095) - Maximum single-page allocation without probing\n\nError Handling:\n- No explicit error handling - relies on Windows page fault mechanism\n- Invalid memory access triggers system page fault handler\n- Stack overflow protection handled by system guard pages",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:2a518bd4b0b93e6cf2e2d91eb6ff7bf6",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "2a518bd4b0b93e6cf2e2d91eb6ff7bf6",
        "CFG": "3045bd7efe0c8474877fb5b5055e4bc3",
        "PRO": "c71205845eb17fcc2718f716924d07ee",
        "CAL": null,
        "CON": null,
        "APS": null
      },
      "callers": {
        "LoD/1.07": [
          "LocaleMapStringWithConversion|0x4028DC",
          "GetCharacterTypeInfo|0x402B2B"
        ],
        "LoD/1.08": [
          "LocaleMapStringWithConversion|0x4028DC",
          "GetCharacterTypeInfo|0x402B2B"
        ],
        "LoD/1.09": [
          "GetCharacterTypeInfo|0x402B2B",
          "LocaleMapStringWithConversion|0x4028DC"
        ],
        "LoD/1.09b": [
          "LocaleMapStringWithConversion|0x4028DC",
          "GetCharacterTypeInfo|0x402B2B"
        ],
        "LoD/1.09d": [
          "LocaleMapStringWithConversion|0x4028DC",
          "GetCharacterTypeInfo|0x402B2B"
        ],
        "LoD/1.10": [
          "LocaleMapStringWithConversion|0x4028DC",
          "GetCharacterTypeInfo|0x402B2B"
        ],
        "LoD/1.11": [
          "LocaleMapStringWithConversion|0x4028DC",
          "GetCharacterTypeInfo|0x402B2B"
        ],
        "LoD/1.11b": [
          "LocaleMapStringWithConversion|0x4028DC",
          "GetCharacterTypeInfo|0x402B2B"
        ],
        "LoD/1.12a": [
          "GetCharacterTypeInfo|0x402B2B",
          "LocaleMapStringWithConversion|0x4028DC"
        ],
        "LoD/1.13c": [
          "LocaleMapStringWithConversion|0x4028DC",
          "GetCharacterTypeInfo|0x402B2B"
        ],
        "LoD/1.13d": [
          "LocaleMapStringWithConversion|0x4028DC",
          "GetCharacterTypeInfo|0x402B2B"
        ],
        "LoD/1.14a": [
          "LocaleMapStringWithConversion|0x4028DC",
          "GetCharacterTypeInfo|0x402B2B"
        ],
        "LoD/1.14b": [
          "LocaleMapStringWithConversion|0x4028DC",
          "GetCharacterTypeInfo|0x402B2B"
        ],
        "LoD/1.14c": [
          "LocaleMapStringWithConversion|0x4028DC",
          "GetCharacterTypeInfo|0x402B2B"
        ],
        "LoD/1.14d": [
          "LocaleMapStringWithConversion|0x4028DC",
          "GetCharacterTypeInfo|0x402B2B"
        ]
      },
      "instruction_counts": {
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
        "LoD/1.13d": 17,
        "LoD/1.14a": 17,
        "LoD/1.14b": 17,
        "LoD/1.14c": 17,
        "LoD/1.14d": 17
      },
      "stack_frame_sizes": {
        "LoD/1.07": 4096,
        "LoD/1.08": 4096,
        "LoD/1.09": 4096,
        "LoD/1.09b": 4096,
        "LoD/1.09d": 4096,
        "LoD/1.10": 4096,
        "LoD/1.11": 4096,
        "LoD/1.11b": 4096,
        "LoD/1.12a": 4096,
        "LoD/1.13c": 4096,
        "LoD/1.13d": 4096,
        "LoD/1.14a": 4096,
        "LoD/1.14b": 4096,
        "LoD/1.14c": 4096,
        "LoD/1.14d": 4096
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
        "LoD/1.13d": 3,
        "LoD/1.14a": 3,
        "LoD/1.14b": 3,
        "LoD/1.14c": 3,
        "LoD/1.14d": 3
      },
      "loop_counts": {
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
        "LoD/1.13d": 1,
        "LoD/1.14a": 1,
        "LoD/1.14b": 1,
        "LoD/1.14c": 1,
        "LoD/1.14d": 1
      },
      "mnemonic_hashes": {
        "LoD/1.07": "2a518bd4b0b93e6cf2e2d91eb6ff7bf6",
        "LoD/1.08": "2a518bd4b0b93e6cf2e2d91eb6ff7bf6",
        "LoD/1.09": "2a518bd4b0b93e6cf2e2d91eb6ff7bf6",
        "LoD/1.09b": "2a518bd4b0b93e6cf2e2d91eb6ff7bf6",
        "LoD/1.09d": "2a518bd4b0b93e6cf2e2d91eb6ff7bf6",
        "LoD/1.10": "2a518bd4b0b93e6cf2e2d91eb6ff7bf6",
        "LoD/1.11": "2a518bd4b0b93e6cf2e2d91eb6ff7bf6",
        "LoD/1.11b": "2a518bd4b0b93e6cf2e2d91eb6ff7bf6",
        "LoD/1.12a": "2a518bd4b0b93e6cf2e2d91eb6ff7bf6",
        "LoD/1.13c": "2a518bd4b0b93e6cf2e2d91eb6ff7bf6",
        "LoD/1.13d": "2a518bd4b0b93e6cf2e2d91eb6ff7bf6",
        "LoD/1.14a": "2a518bd4b0b93e6cf2e2d91eb6ff7bf6",
        "LoD/1.14b": "2a518bd4b0b93e6cf2e2d91eb6ff7bf6",
        "LoD/1.14c": "2a518bd4b0b93e6cf2e2d91eb6ff7bf6",
        "LoD/1.14d": "2a518bd4b0b93e6cf2e2d91eb6ff7bf6"
      },
      "constants": {
        "LoD/1.07": [
          4096
        ],
        "LoD/1.08": [
          4096
        ],
        "LoD/1.09": [
          4096
        ],
        "LoD/1.09b": [
          4096
        ],
        "LoD/1.09d": [
          4096
        ],
        "LoD/1.10": [
          4096
        ],
        "LoD/1.11": [
          4096
        ],
        "LoD/1.11b": [
          4096
        ],
        "LoD/1.12a": [
          4096
        ],
        "LoD/1.13c": [
          4096
        ],
        "LoD/1.13d": [
          4096
        ],
        "LoD/1.14a": [
          4096
        ],
        "LoD/1.14b": [
          4096
        ],
        "LoD/1.14c": [
          4096
        ],
        "LoD/1.14d": [
          4096
        ]
      },
      "globals": {
        "LoD/1.07": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFBFF004|",
          "0xFFFFFFFFFFBFFFFC|",
          "0xFFFFFFFFFFC00000|"
        ],
        "LoD/1.08": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFBFF004|",
          "0xFFFFFFFFFFBFFFFC|",
          "0xFFFFFFFFFFC00000|"
        ],
        "LoD/1.09": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFBFF004|",
          "0xFFFFFFFFFFBFFFFC|",
          "0xFFFFFFFFFFC00000|"
        ],
        "LoD/1.09b": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFBFF004|",
          "0xFFFFFFFFFFBFFFFC|",
          "0xFFFFFFFFFFC00000|"
        ],
        "LoD/1.09d": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFBFF004|",
          "0xFFFFFFFFFFBFFFFC|",
          "0xFFFFFFFFFFC00000|"
        ],
        "LoD/1.10": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFBFF004|",
          "0xFFFFFFFFFFBFFFFC|",
          "0xFFFFFFFFFFC00000|"
        ],
        "LoD/1.11": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFBFF004|",
          "0xFFFFFFFFFFBFFFFC|",
          "0xFFFFFFFFFFC00000|"
        ],
        "LoD/1.11b": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFBFF004|",
          "0xFFFFFFFFFFBFFFFC|",
          "0xFFFFFFFFFFC00000|"
        ],
        "LoD/1.12a": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFBFF004|",
          "0xFFFFFFFFFFBFFFFC|",
          "0xFFFFFFFFFFC00000|"
        ],
        "LoD/1.13c": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFBFF004|",
          "0xFFFFFFFFFFBFFFFC|",
          "0xFFFFFFFFFFC00000|"
        ],
        "LoD/1.13d": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFBFF004|",
          "0xFFFFFFFFFFBFFFFC|",
          "0xFFFFFFFFFFC00000|"
        ],
        "LoD/1.14a": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFBFF004|",
          "0xFFFFFFFFFFBFFFFC|",
          "0xFFFFFFFFFFC00000|"
        ],
        "LoD/1.14b": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFBFF004|",
          "0xFFFFFFFFFFBFFFFC|",
          "0xFFFFFFFFFFC00000|"
        ],
        "LoD/1.14c": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFBFF004|",
          "0xFFFFFFFFFFBFFFFC|",
          "0xFFFFFFFFFFC00000|"
        ],
        "LoD/1.14d": [
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFBFF004|",
          "0xFFFFFFFFFFBFFFFC|",
          "0xFFFFFFFFFFC00000|"
        ]
      }
    },
    "diablo ii.exe__memset": {
      "addresses": {
        "LoD/1.07": "0x00403CB0",
        "LoD/1.08": "0x00403CB0",
        "LoD/1.09": "0x00403CB0",
        "LoD/1.09b": "0x00403CB0",
        "LoD/1.09d": "0x00403CB0",
        "LoD/1.10": "0x00403CB0",
        "LoD/1.11": "0x00403CB0",
        "LoD/1.11b": "0x00403CB0",
        "LoD/1.12a": "0x00403CB0",
        "LoD/1.13c": "0x00403CB0",
        "LoD/1.13d": "0x00403CB0",
        "LoD/1.14a": "0x00403CB0",
        "LoD/1.14b": "0x00403CB0",
        "LoD/1.14c": "0x00403CB0",
        "LoD/1.14d": "0x00403CB0"
      },
      "rvas": {
        "LoD/1.07": "0x3CB0",
        "LoD/1.08": "0x3CB0",
        "LoD/1.09": "0x3CB0",
        "LoD/1.09b": "0x3CB0",
        "LoD/1.09d": "0x3CB0",
        "LoD/1.10": "0x3CB0",
        "LoD/1.11": "0x3CB0",
        "LoD/1.11b": "0x3CB0",
        "LoD/1.12a": "0x3CB0",
        "LoD/1.13c": "0x3CB0",
        "LoD/1.13d": "0x3CB0",
        "LoD/1.14a": "0x3CB0",
        "LoD/1.14b": "0x3CB0",
        "LoD/1.14c": "0x3CB0",
        "LoD/1.14d": "0x3CB0"
      },
      "sizes": {
        "LoD/1.07": 88,
        "LoD/1.08": 88,
        "LoD/1.09": 88,
        "LoD/1.09b": 88,
        "LoD/1.09d": 88,
        "LoD/1.10": 88,
        "LoD/1.11": 88,
        "LoD/1.11b": 88,
        "LoD/1.12a": 88,
        "LoD/1.13c": 88,
        "LoD/1.13d": 88,
        "LoD/1.14a": 88,
        "LoD/1.14b": 88,
        "LoD/1.14c": 88,
        "LoD/1.14d": 88
      },
      "name": "_memset",
      "signature": "void * _memset(void * _Dst, int _Val, size_t _Size)",
      "calling_convention": "__cdecl",
      "return_type": "void *",
      "comment": "Library Function - Single Match\n _memset\n\nLibraries: Visual Studio 1998 Debug, Visual Studio 1998 Release",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:b99d3962c0b26901db87269607fbf85a",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "b99d3962c0b26901db87269607fbf85a",
        "CFG": "b10def2481331b1b779206ec56a43f38",
        "PRO": "e29656b1d5576c12f534a0f00ea1c858",
        "CAL": null,
        "CON": null,
        "APS": null
      },
      "callers": {
        "LoD/1.07": [
          "GetCharacterTypeInfo|0x402B2B"
        ],
        "LoD/1.08": [
          "GetCharacterTypeInfo|0x402B2B"
        ],
        "LoD/1.09": [
          "GetCharacterTypeInfo|0x402B2B"
        ],
        "LoD/1.09b": [
          "GetCharacterTypeInfo|0x402B2B"
        ],
        "LoD/1.09d": [
          "GetCharacterTypeInfo|0x402B2B"
        ],
        "LoD/1.10": [
          "GetCharacterTypeInfo|0x402B2B"
        ],
        "LoD/1.11": [
          "GetCharacterTypeInfo|0x402B2B"
        ],
        "LoD/1.11b": [
          "GetCharacterTypeInfo|0x402B2B"
        ],
        "LoD/1.12a": [
          "GetCharacterTypeInfo|0x402B2B"
        ],
        "LoD/1.13c": [
          "GetCharacterTypeInfo|0x402B2B"
        ],
        "LoD/1.13d": [
          "GetCharacterTypeInfo|0x402B2B"
        ],
        "LoD/1.14a": [
          "GetCharacterTypeInfo|0x402B2B"
        ],
        "LoD/1.14b": [
          "GetCharacterTypeInfo|0x402B2B"
        ],
        "LoD/1.14c": [
          "GetCharacterTypeInfo|0x402B2B"
        ],
        "LoD/1.14d": [
          "GetCharacterTypeInfo|0x402B2B"
        ]
      },
      "instruction_counts": {
        "LoD/1.07": 40,
        "LoD/1.08": 40,
        "LoD/1.09": 40,
        "LoD/1.09b": 40,
        "LoD/1.09d": 40,
        "LoD/1.10": 40,
        "LoD/1.11": 40,
        "LoD/1.11b": 40,
        "LoD/1.12a": 40,
        "LoD/1.13c": 40,
        "LoD/1.13d": 40,
        "LoD/1.14a": 40,
        "LoD/1.14b": 40,
        "LoD/1.14c": 40,
        "LoD/1.14d": 40
      },
      "stack_frame_sizes": {
        "LoD/1.07": 16,
        "LoD/1.08": 16,
        "LoD/1.09": 16,
        "LoD/1.09b": 16,
        "LoD/1.09d": 16,
        "LoD/1.10": 16,
        "LoD/1.11": 16,
        "LoD/1.11b": 16,
        "LoD/1.12a": 16,
        "LoD/1.13c": 16,
        "LoD/1.13d": 16,
        "LoD/1.14a": 16,
        "LoD/1.14b": 16,
        "LoD/1.14c": 16,
        "LoD/1.14d": 16
      },
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
        "LoD/1.13d": 10,
        "LoD/1.14a": 10,
        "LoD/1.14b": 10,
        "LoD/1.14c": 10,
        "LoD/1.14d": 10
      },
      "loop_counts": {
        "LoD/1.07": 2,
        "LoD/1.08": 2,
        "LoD/1.09": 2,
        "LoD/1.09b": 2,
        "LoD/1.09d": 2,
        "LoD/1.10": 2,
        "LoD/1.11": 2,
        "LoD/1.11b": 2,
        "LoD/1.12a": 2,
        "LoD/1.13c": 2,
        "LoD/1.13d": 2,
        "LoD/1.14a": 2,
        "LoD/1.14b": 2,
        "LoD/1.14c": 2,
        "LoD/1.14d": 2
      },
      "mnemonic_hashes": {
        "LoD/1.07": "b99d3962c0b26901db87269607fbf85a",
        "LoD/1.08": "b99d3962c0b26901db87269607fbf85a",
        "LoD/1.09": "b99d3962c0b26901db87269607fbf85a",
        "LoD/1.09b": "b99d3962c0b26901db87269607fbf85a",
        "LoD/1.09d": "b99d3962c0b26901db87269607fbf85a",
        "LoD/1.10": "b99d3962c0b26901db87269607fbf85a",
        "LoD/1.11": "b99d3962c0b26901db87269607fbf85a",
        "LoD/1.11b": "b99d3962c0b26901db87269607fbf85a",
        "LoD/1.12a": "b99d3962c0b26901db87269607fbf85a",
        "LoD/1.13c": "b99d3962c0b26901db87269607fbf85a",
        "LoD/1.13d": "b99d3962c0b26901db87269607fbf85a",
        "LoD/1.14a": "b99d3962c0b26901db87269607fbf85a",
        "LoD/1.14b": "b99d3962c0b26901db87269607fbf85a",
        "LoD/1.14c": "b99d3962c0b26901db87269607fbf85a",
        "LoD/1.14d": "b99d3962c0b26901db87269607fbf85a"
      },
      "globals": {
        "LoD/1.07": [
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ],
        "LoD/1.08": [
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ],
        "LoD/1.09": [
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ],
        "LoD/1.09b": [
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ],
        "LoD/1.09d": [
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ],
        "LoD/1.10": [
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ],
        "LoD/1.11": [
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ],
        "LoD/1.11b": [
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ],
        "LoD/1.12a": [
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ],
        "LoD/1.13c": [
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ],
        "LoD/1.13d": [
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ],
        "LoD/1.14a": [
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ],
        "LoD/1.14b": [
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ],
        "LoD/1.14c": [
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ],
        "LoD/1.14d": [
          "0xFFFFFFFFFFC0000C|",
          "0xFFFFFFFFFFC00004|",
          "0xFFFFFFFFFFC00008|"
        ]
      }
    },
    "diablo ii.exe_InvokeCallbackHandler": {
      "addresses": {
        "LoD/1.07": "0x00403D08",
        "LoD/1.08": "0x00403D08",
        "LoD/1.09": "0x00403D08",
        "LoD/1.09b": "0x00403D08",
        "LoD/1.09d": "0x00403D08",
        "LoD/1.10": "0x00403D08",
        "LoD/1.11": "0x00403D08",
        "LoD/1.11b": "0x00403D08",
        "LoD/1.12a": "0x00403D08",
        "LoD/1.13c": "0x00403D08",
        "LoD/1.13d": "0x00403D08",
        "LoD/1.14a": "0x00403D08",
        "LoD/1.14b": "0x00403D08",
        "LoD/1.14c": "0x00403D08",
        "LoD/1.14d": "0x00403D08"
      },
      "rvas": {
        "LoD/1.07": "0x3D08",
        "LoD/1.08": "0x3D08",
        "LoD/1.09": "0x3D08",
        "LoD/1.09b": "0x3D08",
        "LoD/1.09d": "0x3D08",
        "LoD/1.10": "0x3D08",
        "LoD/1.11": "0x3D08",
        "LoD/1.11b": "0x3D08",
        "LoD/1.12a": "0x3D08",
        "LoD/1.13c": "0x3D08",
        "LoD/1.13d": "0x3D08",
        "LoD/1.14a": "0x3D08",
        "LoD/1.14b": "0x3D08",
        "LoD/1.14c": "0x3D08",
        "LoD/1.14d": "0x3D08"
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
        "LoD/1.13d": 27,
        "LoD/1.14a": 27,
        "LoD/1.14b": 27,
        "LoD/1.14c": 27,
        "LoD/1.14d": 27
      },
      "name": "InvokeCallbackHandler",
      "signature": "int InvokeCallbackHandler(int nParameter)",
      "calling_convention": "__cdecl",
      "return_type": "int",
      "comment": "Setting prototype: int InvokeCallbackHandler(int nParameter)",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:ee4facdaccbd6fc5f3297fd5b85b73c2",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "ee4facdaccbd6fc5f3297fd5b85b73c2",
        "CFG": "b52f56e126e2d946dea5881aec08bc73",
        "PRO": "eba25aa4a7ad5f2a92814c91aa869f28",
        "CAL": null,
        "CON": null,
        "APS": null
      },
      "callers": {
        "LoD/1.07": [
          "__nh_malloc|0x402F02"
        ],
        "LoD/1.08": [
          "__nh_malloc|0x402F02"
        ],
        "LoD/1.09": [
          "__nh_malloc|0x402F02"
        ],
        "LoD/1.09b": [
          "__nh_malloc|0x402F02"
        ],
        "LoD/1.09d": [
          "__nh_malloc|0x402F02"
        ],
        "LoD/1.10": [
          "__nh_malloc|0x402F02"
        ],
        "LoD/1.11": [
          "__nh_malloc|0x402F02"
        ],
        "LoD/1.11b": [
          "__nh_malloc|0x402F02"
        ],
        "LoD/1.12a": [
          "__nh_malloc|0x402F02"
        ],
        "LoD/1.13c": [
          "__nh_malloc|0x402F02"
        ],
        "LoD/1.13d": [
          "__nh_malloc|0x402F02"
        ],
        "LoD/1.14a": [
          "__nh_malloc|0x402F02"
        ],
        "LoD/1.14b": [
          "__nh_malloc|0x402F02"
        ],
        "LoD/1.14c": [
          "__nh_malloc|0x402F02"
        ],
        "LoD/1.14d": [
          "__nh_malloc|0x402F02"
        ]
      },
      "instruction_counts": {
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
        "LoD/1.13d": 13,
        "LoD/1.14a": 13,
        "LoD/1.14b": 13,
        "LoD/1.14c": 13,
        "LoD/1.14d": 13
      },
      "stack_frame_sizes": {
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
        "LoD/1.13d": 8,
        "LoD/1.14a": 8,
        "LoD/1.14b": 8,
        "LoD/1.14c": 8,
        "LoD/1.14d": 8
      },
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
        "LoD/1.13d": 4,
        "LoD/1.14a": 4,
        "LoD/1.14b": 4,
        "LoD/1.14c": 4,
        "LoD/1.14d": 4
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
        "LoD/1.13d": 0,
        "LoD/1.14a": 0,
        "LoD/1.14b": 0,
        "LoD/1.14c": 0,
        "LoD/1.14d": 0
      },
      "mnemonic_hashes": {
        "LoD/1.07": "ee4facdaccbd6fc5f3297fd5b85b73c2",
        "LoD/1.08": "ee4facdaccbd6fc5f3297fd5b85b73c2",
        "LoD/1.09": "ee4facdaccbd6fc5f3297fd5b85b73c2",
        "LoD/1.09b": "ee4facdaccbd6fc5f3297fd5b85b73c2",
        "LoD/1.09d": "ee4facdaccbd6fc5f3297fd5b85b73c2",
        "LoD/1.10": "ee4facdaccbd6fc5f3297fd5b85b73c2",
        "LoD/1.11": "ee4facdaccbd6fc5f3297fd5b85b73c2",
        "LoD/1.11b": "ee4facdaccbd6fc5f3297fd5b85b73c2",
        "LoD/1.12a": "ee4facdaccbd6fc5f3297fd5b85b73c2",
        "LoD/1.13c": "ee4facdaccbd6fc5f3297fd5b85b73c2",
        "LoD/1.13d": "ee4facdaccbd6fc5f3297fd5b85b73c2",
        "LoD/1.14a": "ee4facdaccbd6fc5f3297fd5b85b73c2",
        "LoD/1.14b": "ee4facdaccbd6fc5f3297fd5b85b73c2",
        "LoD/1.14c": "ee4facdaccbd6fc5f3297fd5b85b73c2",
        "LoD/1.14d": "ee4facdaccbd6fc5f3297fd5b85b73c2"
      },
      "globals": {
        "LoD/1.07": [
          "0x6658|g_pfnCallbackHandler",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.08": [
          "0x6658|g_pfnCallbackHandler",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.09": [
          "0x6658|g_pfnCallbackHandler",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.09b": [
          "0x6658|g_pfnCallbackHandler",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.09d": [
          "0x6658|g_pfnCallbackHandler",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.10": [
          "0x6658|g_pfnCallbackHandler",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.11": [
          "0x6658|g_pfnCallbackHandler",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.11b": [
          "0x6658|g_pfnCallbackHandler",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.12a": [
          "0x6658|g_pfnCallbackHandler",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.13c": [
          "0x6658|g_pfnCallbackHandler",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.13d": [
          "0x6658|g_pfnCallbackHandler",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.14a": [
          "0x6658|g_pfnCallbackHandler",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.14b": [
          "0x6658|g_pfnCallbackHandler",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.14c": [
          "0x6658|g_pfnCallbackHandler",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.14d": [
          "0x6658|g_pfnCallbackHandler",
          "0xFFFFFFFFFFC00004|"
        ]
      }
    },
    "diablo ii.exe_RtlUnwind": {
      "addresses": {
        "LoD/1.07": "0x00404066",
        "LoD/1.08": "0x00404066",
        "LoD/1.09": "0x00404066",
        "LoD/1.09b": "0x00404066",
        "LoD/1.09d": "0x00404066",
        "LoD/1.10": "0x00404066",
        "LoD/1.11": "0x00404066",
        "LoD/1.11b": "0x00404066",
        "LoD/1.12a": "0x00404066",
        "LoD/1.13c": "0x00404066",
        "LoD/1.13d": "0x00404066",
        "LoD/1.14a": "0x00404066",
        "LoD/1.14b": "0x00404066",
        "LoD/1.14c": "0x00404066",
        "LoD/1.14d": "0x00404066"
      },
      "rvas": {
        "LoD/1.07": "0x4066",
        "LoD/1.08": "0x4066",
        "LoD/1.09": "0x4066",
        "LoD/1.09b": "0x4066",
        "LoD/1.09d": "0x4066",
        "LoD/1.10": "0x4066",
        "LoD/1.11": "0x4066",
        "LoD/1.11b": "0x4066",
        "LoD/1.12a": "0x4066",
        "LoD/1.13c": "0x4066",
        "LoD/1.13d": "0x4066",
        "LoD/1.14a": "0x4066",
        "LoD/1.14b": "0x4066",
        "LoD/1.14c": "0x4066",
        "LoD/1.14d": "0x4066"
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
        "LoD/1.13d": 6,
        "LoD/1.14a": 6,
        "LoD/1.14b": 6,
        "LoD/1.14c": 6,
        "LoD/1.14d": 6
      },
      "name": "RtlUnwind",
      "signature": "void RtlUnwind(PVOID TargetFrame, PVOID TargetIp, PEXCEPTION_RECORD ExceptionRecord, PVOID ReturnValue)",
      "calling_convention": "__stdcall",
      "return_type": "void",
      "name_source": "LoD/1.07",
      "method": "MNE",
      "index": "MNE:e3e7225badfcf3c2e051c42d71d7237a",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "e3e7225badfcf3c2e051c42d71d7237a",
        "CFG": "aecf32697ffe0ec80fa581bb7d6ebc2e",
        "PRO": "8e99e48039a137206e6ffe8f75bf57a9",
        "CAL": null,
        "CON": null,
        "APS": null
      },
      "callers": {
        "LoD/1.07": [
          "GlobalUnwind2|0x402580"
        ],
        "LoD/1.08": [
          "GlobalUnwind2|0x402580"
        ],
        "LoD/1.09": [
          "GlobalUnwind2|0x402580"
        ],
        "LoD/1.09b": [
          "GlobalUnwind2|0x402580"
        ],
        "LoD/1.09d": [
          "GlobalUnwind2|0x402580"
        ],
        "LoD/1.10": [
          "GlobalUnwind2|0x402580"
        ],
        "LoD/1.11": [
          "GlobalUnwind2|0x402580"
        ],
        "LoD/1.11b": [
          "GlobalUnwind2|0x402580"
        ],
        "LoD/1.12a": [
          "GlobalUnwind2|0x402580"
        ],
        "LoD/1.13c": [
          "GlobalUnwind2|0x402580"
        ],
        "LoD/1.13d": [
          "GlobalUnwind2|0x402580"
        ],
        "LoD/1.14a": [
          "GlobalUnwind2|0x402580"
        ],
        "LoD/1.14b": [
          "GlobalUnwind2|0x402580"
        ],
        "LoD/1.14c": [
          "GlobalUnwind2|0x402580"
        ],
        "LoD/1.14d": [
          "GlobalUnwind2|0x402580"
        ]
      },
      "instruction_counts": {
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
        "LoD/1.13d": 1,
        "LoD/1.14a": 1,
        "LoD/1.14b": 1,
        "LoD/1.14c": 1,
        "LoD/1.14d": 1
      },
      "stack_frame_sizes": {
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
        "LoD/1.13d": 20,
        "LoD/1.14a": 20,
        "LoD/1.14b": 20,
        "LoD/1.14c": 20,
        "LoD/1.14d": 20
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
        "LoD/1.13d": 1,
        "LoD/1.14a": 1,
        "LoD/1.14b": 1,
        "LoD/1.14c": 1,
        "LoD/1.14d": 1
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
        "LoD/1.13d": 0,
        "LoD/1.14a": 0,
        "LoD/1.14b": 0,
        "LoD/1.14c": 0,
        "LoD/1.14d": 0
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
        "LoD/1.13d": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.14a": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.14b": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.14c": "e3e7225badfcf3c2e051c42d71d7237a",
        "LoD/1.14d": "e3e7225badfcf3c2e051c42d71d7237a"
      }
    },
    "diablo ii.exe__strstr": {
      "addresses": {
        "LoD/1.08": "0x00401C00",
        "LoD/1.09": "0x00401C00",
        "LoD/1.09b": "0x00401C00",
        "LoD/1.09d": "0x00401C00",
        "LoD/1.10": "0x00401C00",
        "LoD/1.11": "0x00401C00",
        "LoD/1.11b": "0x00401C00",
        "LoD/1.12a": "0x00401C00",
        "LoD/1.13c": "0x00401C00",
        "LoD/1.13d": "0x00401C00",
        "LoD/1.14a": "0x00401C00",
        "LoD/1.14b": "0x00401C00",
        "LoD/1.14c": "0x00401C00",
        "LoD/1.14d": "0x00401C00"
      },
      "rvas": {
        "LoD/1.08": "0x1C00",
        "LoD/1.09": "0x1C00",
        "LoD/1.09b": "0x1C00",
        "LoD/1.09d": "0x1C00",
        "LoD/1.10": "0x1C00",
        "LoD/1.11": "0x1C00",
        "LoD/1.11b": "0x1C00",
        "LoD/1.12a": "0x1C00",
        "LoD/1.13c": "0x1C00",
        "LoD/1.13d": "0x1C00",
        "LoD/1.14a": "0x1C00",
        "LoD/1.14b": "0x1C00",
        "LoD/1.14c": "0x1C00",
        "LoD/1.14d": "0x1C00"
      },
      "sizes": {
        "LoD/1.08": 128,
        "LoD/1.09": 128,
        "LoD/1.09b": 128,
        "LoD/1.09d": 128,
        "LoD/1.10": 128,
        "LoD/1.11": 128,
        "LoD/1.11b": 128,
        "LoD/1.12a": 128,
        "LoD/1.13c": 128,
        "LoD/1.13d": 128,
        "LoD/1.14a": 128,
        "LoD/1.14b": 128,
        "LoD/1.14c": 128,
        "LoD/1.14d": 128
      },
      "name": "_strstr",
      "signature": "char * _strstr(char * _Str, char * _SubStr)",
      "calling_convention": "__cdecl",
      "return_type": "char *",
      "comment": "Library Function - Single Match\n _strstr\n\nLibraries: Visual Studio 1998 Debug, Visual Studio 1998 Release",
      "name_source": "LoD/1.08",
      "method": "MNE",
      "index": "MNE:3c60546d8cfb6e92d20e0cc9dd281ae9",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "3c60546d8cfb6e92d20e0cc9dd281ae9",
        "CFG": "716e8aa637b8b0b883d37e30aaff9bbb",
        "PRO": "858f2f80185d26d23fec7b662bab6b38",
        "CAL": null,
        "CON": null,
        "APS": null
      },
      "callees": {
        "LoD/1.08": [
          "FUN_00402cd6|0x402CD6"
        ],
        "LoD/1.09": [
          "FUN_00402cd6|0x402CD6"
        ],
        "LoD/1.09b": [
          "FUN_00402cd6|0x402CD6"
        ],
        "LoD/1.09d": [
          "FUN_00402cd6|0x402CD6"
        ],
        "LoD/1.10": [
          "FUN_00402cd6|0x402CD6"
        ],
        "LoD/1.11": [
          "FUN_00402cd6|0x402CD6"
        ],
        "LoD/1.11b": [
          "FUN_00402cd6|0x402CD6"
        ],
        "LoD/1.12a": [
          "FUN_00402cd6|0x402CD6"
        ],
        "LoD/1.13c": [
          "FUN_00402cd6|0x402CD6"
        ],
        "LoD/1.13d": [
          "FUN_00402cd6|0x402CD6"
        ],
        "LoD/1.14a": [
          "FUN_00402cd6|0x402CD6"
        ],
        "LoD/1.14b": [
          "FUN_00402cd6|0x402CD6"
        ],
        "LoD/1.14c": [
          "FUN_00402cd6|0x402CD6"
        ],
        "LoD/1.14d": [
          "FUN_00402cd6|0x402CD6"
        ]
      },
      "callers": {
        "LoD/1.08": [
          "FUN_0040146d|0x40146D"
        ],
        "LoD/1.09": [
          "FUN_0040146d|0x40146D"
        ],
        "LoD/1.09b": [
          "FUN_0040146d|0x40146D"
        ],
        "LoD/1.09d": [
          "FUN_0040146d|0x40146D"
        ],
        "LoD/1.10": [
          "FUN_0040146d|0x40146D"
        ],
        "LoD/1.11": [
          "FUN_0040146d|0x40146D"
        ],
        "LoD/1.11b": [
          "FUN_0040146d|0x40146D"
        ],
        "LoD/1.12a": [
          "FUN_0040146d|0x40146D"
        ],
        "LoD/1.13c": [
          "FUN_0040146d|0x40146D"
        ],
        "LoD/1.13d": [
          "FUN_0040146d|0x40146D"
        ],
        "LoD/1.14a": [
          "FUN_0040146d|0x40146D"
        ],
        "LoD/1.14b": [
          "FUN_0040146d|0x40146D"
        ],
        "LoD/1.14c": [
          "FUN_0040146d|0x40146D"
        ],
        "LoD/1.14d": [
          "FUN_0040146d|0x40146D"
        ]
      },
      "instruction_counts": {
        "LoD/1.08": 66,
        "LoD/1.09": 66,
        "LoD/1.09b": 66,
        "LoD/1.09d": 66,
        "LoD/1.10": 66,
        "LoD/1.11": 66,
        "LoD/1.11b": 66,
        "LoD/1.12a": 66,
        "LoD/1.13c": 66,
        "LoD/1.13d": 66,
        "LoD/1.14a": 66,
        "LoD/1.14b": 66,
        "LoD/1.14c": 66,
        "LoD/1.14d": 66
      },
      "stack_frame_sizes": {
        "LoD/1.08": 12,
        "LoD/1.09": 12,
        "LoD/1.09b": 12,
        "LoD/1.09d": 12,
        "LoD/1.10": 12,
        "LoD/1.11": 12,
        "LoD/1.11b": 12,
        "LoD/1.12a": 12,
        "LoD/1.13c": 12,
        "LoD/1.13d": 12,
        "LoD/1.14a": 12,
        "LoD/1.14b": 12,
        "LoD/1.14c": 12,
        "LoD/1.14d": 12
      },
      "basic_block_counts": {
        "LoD/1.08": 18,
        "LoD/1.09": 18,
        "LoD/1.09b": 18,
        "LoD/1.09d": 18,
        "LoD/1.10": 18,
        "LoD/1.11": 18,
        "LoD/1.11b": 18,
        "LoD/1.12a": 18,
        "LoD/1.13c": 18,
        "LoD/1.13d": 18,
        "LoD/1.14a": 18,
        "LoD/1.14b": 18,
        "LoD/1.14c": 18,
        "LoD/1.14d": 18
      },
      "loop_counts": {
        "LoD/1.08": 5,
        "LoD/1.09": 5,
        "LoD/1.09b": 5,
        "LoD/1.09d": 5,
        "LoD/1.10": 5,
        "LoD/1.11": 5,
        "LoD/1.11b": 5,
        "LoD/1.12a": 5,
        "LoD/1.13c": 5,
        "LoD/1.13d": 5,
        "LoD/1.14a": 5,
        "LoD/1.14b": 5,
        "LoD/1.14c": 5,
        "LoD/1.14d": 5
      },
      "mnemonic_hashes": {
        "LoD/1.08": "3c60546d8cfb6e92d20e0cc9dd281ae9",
        "LoD/1.09": "3c60546d8cfb6e92d20e0cc9dd281ae9",
        "LoD/1.09b": "3c60546d8cfb6e92d20e0cc9dd281ae9",
        "LoD/1.09d": "3c60546d8cfb6e92d20e0cc9dd281ae9",
        "LoD/1.10": "3c60546d8cfb6e92d20e0cc9dd281ae9",
        "LoD/1.11": "3c60546d8cfb6e92d20e0cc9dd281ae9",
        "LoD/1.11b": "3c60546d8cfb6e92d20e0cc9dd281ae9",
        "LoD/1.12a": "3c60546d8cfb6e92d20e0cc9dd281ae9",
        "LoD/1.13c": "3c60546d8cfb6e92d20e0cc9dd281ae9",
        "LoD/1.13d": "3c60546d8cfb6e92d20e0cc9dd281ae9",
        "LoD/1.14a": "3c60546d8cfb6e92d20e0cc9dd281ae9",
        "LoD/1.14b": "3c60546d8cfb6e92d20e0cc9dd281ae9",
        "LoD/1.14c": "3c60546d8cfb6e92d20e0cc9dd281ae9",
        "LoD/1.14d": "3c60546d8cfb6e92d20e0cc9dd281ae9"
      },
      "globals": {
        "LoD/1.08": [
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.09": [
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.09b": [
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.09d": [
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.10": [
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.11": [
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.11b": [
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.12a": [
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.13c": [
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.13d": [
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.14a": [
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.14b": [
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.14c": [
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|"
        ],
        "LoD/1.14d": [
          "0xFFFFFFFFFFC00008|",
          "0xFFFFFFFFFFC00004|"
        ]
      }
    },
    "diablo ii.exe_DecrementValue": {
      "addresses": {
        "LoD/1.08": "0x00402CC0",
        "LoD/1.09": "0x00402CC0",
        "LoD/1.09b": "0x00402CC0",
        "LoD/1.09d": "0x00402CC0",
        "LoD/1.10": "0x00402CC0",
        "LoD/1.11": "0x00402CC0",
        "LoD/1.11b": "0x00402CC0",
        "LoD/1.12a": "0x00402CC0",
        "LoD/1.13c": "0x00402CC0",
        "LoD/1.13d": "0x00402CC0",
        "LoD/1.14a": "0x00402CC0",
        "LoD/1.14b": "0x00402CC0",
        "LoD/1.14c": "0x00402CC0",
        "LoD/1.14d": "0x00402CC0"
      },
      "rvas": {
        "LoD/1.08": "0x2CC0",
        "LoD/1.09": "0x2CC0",
        "LoD/1.09b": "0x2CC0",
        "LoD/1.09d": "0x2CC0",
        "LoD/1.10": "0x2CC0",
        "LoD/1.11": "0x2CC0",
        "LoD/1.11b": "0x2CC0",
        "LoD/1.12a": "0x2CC0",
        "LoD/1.13c": "0x2CC0",
        "LoD/1.13d": "0x2CC0",
        "LoD/1.14a": "0x2CC0",
        "LoD/1.14b": "0x2CC0",
        "LoD/1.14c": "0x2CC0",
        "LoD/1.14d": "0x2CC0"
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
        "LoD/1.13d": 5,
        "LoD/1.14a": 5,
        "LoD/1.14b": 5,
        "LoD/1.14c": 5,
        "LoD/1.14d": 5
      },
      "name": "DecrementValue",
      "signature": "int DecrementValue(void)",
      "calling_convention": "__fastcall",
      "return_type": "int",
      "comment": "Decrements an integer value by 1 and returns the result.\n\nAlgorithm:\n1. Ignore the first parameter (unused placeholder for fastcall convention)\n2. Load the second parameter value into a register\n3. Subtract 1 from the value using LEA instruction\n4. Return the decremented result\n\nParameters:\nnUnused - int: Unused parameter (fastcall ECX register placeholder)\nnValue - int: The integer value to decrement\n\nReturns:\nint: The input value decreased by 1\n\nSpecial Cases:\n- Function ignores the first parameter completely\n- Uses LEA instruction for efficient decrement: LEA EAX,[EDX + -0x1]\n- Contains orphaned POP EBX instruction from compiler optimization\n\nError Handling:\nNone - this is a simple arithmetic helper function",
      "name_source": "LoD/1.08",
      "method": "MNE",
      "index": "MNE:3ecdb5e459e29b4117490dc114e98574",
      "indexes": {
        "EXP": null,
        "STR": null,
        "API": null,
        "MNE": "3ecdb5e459e29b4117490dc114e98574",
        "CFG": "57474f13ec5a3b3413d2cc571b545409",
        "PRO": "c81df70c1b97172a537e995055b0c6bd",
        "CAL": null,
        "CON": null,
        "APS": null
      },
      "instruction_counts": {
        "LoD/1.08": 3,
        "LoD/1.09": 3,
        "LoD/1.09b": 3,
        "LoD/1.09d": 3,
        "LoD/1.10": 3,
        "LoD/1.11": 3,
        "LoD/1.11b": 3,
        "LoD/1.12a": 3,
        "LoD/1.13c": 3,
        "LoD/1.13d": 3,
        "LoD/1.14a": 3,
        "LoD/1.14b": 3,
        "LoD/1.14c": 3,
        "LoD/1.14d": 3
      },
      "stack_frame_sizes": {
        "LoD/1.08": 4,
        "LoD/1.09": 4,
        "LoD/1.09b": 4,
        "LoD/1.09d": 4,
        "LoD/1.10": 4,
        "LoD/1.11": 4,
        "LoD/1.11b": 4,
        "LoD/1.12a": 4,
        "LoD/1.13c": 4,
        "LoD/1.13d": 4,
        "LoD/1.14a": 4,
        "LoD/1.14b": 4,
        "LoD/1.14c": 4,
        "LoD/1.14d": 4
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
        "LoD/1.13d": 1,
        "LoD/1.14a": 1,
        "LoD/1.14b": 1,
        "LoD/1.14c": 1,
        "LoD/1.14d": 1
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
        "LoD/1.13d": 0,
        "LoD/1.14a": 0,
        "LoD/1.14b": 0,
        "LoD/1.14c": 0,
        "LoD/1.14d": 0
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
        "LoD/1.13d": "3ecdb5e459e29b4117490dc114e98574",
        "LoD/1.14a": "3ecdb5e459e29b4117490dc114e98574",
        "LoD/1.14b": "3ecdb5e459e29b4117490dc114e98574",
        "LoD/1.14c": "3ecdb5e459e29b4117490dc114e98574",
        "LoD/1.14d": "3ecdb5e459e29b4117490dc114e98574"
      }
    }
  }
};

if (typeof FUNCTION_DATA === 'undefined') FUNCTION_DATA = {};
FUNCTION_DATA['Diablo II.exe'] = FUNCTIONS_Diablo_II_exe;
