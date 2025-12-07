#!/usr/bin/env python3
"""
Diablo 2 Function Database Tool

This tool compiles known D2 functions from the modding community and creates
a structured database for cross-referencing with Ghidra analysis.

Sources:
- d2bs project (blizzhackers/d2bs): D2Ptrs.h, D2Structs.h
- OpenD2 project (eezstreet/OpenD2): D2DataTables.hpp, D2Shared.hpp
- Phrozen Keep modding community documentation

The function offsets are relative to the base address:
- For DLLs (1.00-1.13d): Each DLL has its own base address
- For Game.exe (1.14+): All functions merged into single executable (base 0x400000)
"""

import json
import os
import re
from dataclasses import dataclass, asdict
from typing import Optional, List, Dict

# Database of known D2 functions from d2bs D2Ptrs.h (1.14d offsets)
# Format: (dll_name, function_name, offset, signature, calling_convention)
KNOWN_FUNCTIONS_1_14D = [
    # D2CLIENT Functions
    ("D2CLIENT", "GetQuestInfo", 0xB32D0, "void* __stdcall (void)", "__stdcall"),
    ("D2CLIENT", "SubmitItem", 0xB2370, "void __fastcall (DWORD dwItemId)", "__fastcall"),
    ("D2CLIENT", "Transmute", 0x8A0D0, "void __fastcall (void)", "__fastcall"),
    ("D2CLIENT", "FindClientSideUnit", 0x63990, "UnitAny* __fastcall (DWORD dwId, DWORD dwType)", "__fastcall"),
    ("D2CLIENT", "FindServerSideUnit", 0x639B0, "UnitAny* __fastcall (DWORD dwId, DWORD dwType)", "__fastcall"),
    ("D2CLIENT", "GetCurrentInteractingNPC", 0xB1620, "UnitAny* __fastcall (void)", "__fastcall"),
    ("D2CLIENT", "GetSelectedUnit", 0x67A10, "UnitAny* __stdcall ()", "__stdcall"),
    ("D2CLIENT", "GetCursorItem", 0x680A0, "UnitAny* __fastcall (void)", "__fastcall"),
    ("D2CLIENT", "SetSelectedUnit_I", 0x66DE0, "void __fastcall (UnitAny* pUnit)", "__fastcall"),
    ("D2CLIENT", "GetItemName", 0x8C060, "BOOL __fastcall (UnitAny* pItem, wchar_t* wBuffer, DWORD dwSize)", "__fastcall"),
    ("D2CLIENT", "LoadItemDesc", 0x8DD90, "BOOL __stdcall (UnitAny* pItem, int type)", "__stdcall"),
    ("D2CLIENT", "GetMonsterOwner", 0x79150, "DWORD __fastcall (DWORD nMonsterId)", "__fastcall"),
    ("D2CLIENT", "GetUnitHPPercent", 0x79080, "DWORD __fastcall (DWORD dwUnitId)", "__fastcall"),
    ("D2CLIENT", "InitInventory", 0x845A0, "void __fastcall (void)", "__fastcall"),
    ("D2CLIENT", "SetUIVar", 0x55F20, "DWORD __fastcall (DWORD varno, DWORD howset, DWORD unknown1)", "__fastcall"),
    ("D2CLIENT", "GetUnitX", 0x5ADF0, "int __fastcall (UnitAny* pUnit)", "__fastcall"),
    ("D2CLIENT", "GetUnitY", 0x5AE20, "int __fastcall (UnitAny* pUnit)", "__fastcall"),
    ("D2CLIENT", "ShopAction", 0xB3870, "void __fastcall (UnitAny* pNpc, UnitAny* pItem, DWORD dwSell, DWORD unk, DWORD dwItemCost, DWORD dwMode, DWORD _2, DWORD _3)", "__fastcall"),
    ("D2CLIENT", "CloseNPCInteract", 0xB3F10, "void __fastcall (void)", "__fastcall"),
    ("D2CLIENT", "CloseInteract", 0x4C6B0, "void __fastcall (void)", "__fastcall"),
    ("D2CLIENT", "GetAutomapSize", 0x5A710, "DWORD __stdcall (void)", "__stdcall"),
    ("D2CLIENT", "NewAutomapCell", 0x57C30, "AutomapCell* __fastcall ()", "__fastcall"),
    ("D2CLIENT", "AddAutomapCell", 0x57B00, "void __fastcall (AutomapCell* aCell, AutomapCell** node)", "__fastcall"),
    ("D2CLIENT", "RevealAutomapRoom", 0x58F40, "void __stdcall (Room1* pRoom1, DWORD dwClipFlag, AutomapLayer* aLayer)", "__stdcall"),
    ("D2CLIENT", "InitAutomapLayer_I", 0x58D40, "AutomapLayer* __fastcall (DWORD nLayerNo)", "__fastcall"),
    ("D2CLIENT", "ClickMap", 0x62D00, "void __fastcall (DWORD MouseFlag, DWORD x, DWORD y, DWORD Type)", "__fastcall"),
    ("D2CLIENT", "LeftClickItem_I", 0x8FFE0, "void __stdcall (UnitAny* pPlayer, Inventory* pInventory, int x, int y, DWORD dwClickType, InventoryLayout* pLayout, DWORD Location)", "__stdcall"),
    ("D2CLIENT", "GetMouseXOffset", 0x5AFC0, "DWORD __fastcall (VOID)", "__fastcall"),
    ("D2CLIENT", "GetMouseYOffset", 0x5AFB0, "DWORD __fastcall (VOID)", "__fastcall"),
    ("D2CLIENT", "PrintGameString", 0x9E3A0, "void __fastcall (wchar_t* wMessage, int nColor)", "__fastcall"),
    ("D2CLIENT", "PrintPartyString", 0x9E5C0, "void __fastcall (wchar_t* wMessage, int nColor)", "__fastcall"),
    ("D2CLIENT", "LeaveParty", 0x79FC0, "void __fastcall (void)", "__fastcall"),
    ("D2CLIENT", "AcceptTrade", 0xB9070, "void __fastcall (void)", "__fastcall"),
    ("D2CLIENT", "CancelTrade", 0xB90B0, "void __fastcall (void)", "__fastcall"),
    ("D2CLIENT", "TradeOK", 0xB8A30, "void __stdcall (void)", "__stdcall"),
    ("D2CLIENT", "GetDifficulty", 0x4DCD0, "BYTE __stdcall ()", "__stdcall"),
    ("D2CLIENT", "ExitGame", 0x4DD60, "void __fastcall (void)", "__fastcall"),
    ("D2CLIENT", "GetUiVar_I", 0x538D0, "DWORD __fastcall (DWORD dwVarNo)", "__fastcall"),
    ("D2CLIENT", "DrawRectFrame", 0x52E50, "VOID __fastcall (DWORD Rect)", "__fastcall"),
    ("D2CLIENT", "PerformGoldDialogAction", 0x54080, "void __fastcall (void)", "__fastcall"),
    ("D2CLIENT", "GetPlayerUnit", 0x63DD0, "UnitAny* __stdcall ()", "__stdcall"),
    ("D2CLIENT", "ClearScreen", 0xB4620, "void __fastcall (void)", "__fastcall"),
    ("D2CLIENT", "CloseNPCTalk", 0xA17D0, "DWORD __stdcall (void* unk)", "__stdcall"),
    ("D2CLIENT", "TestPvpFlag", 0xDC440, "DWORD __fastcall (DWORD dwUnitId1, DWORD dwUnitId2, DWORD dwFlag)", "__fastcall"),
    ("D2CLIENT", "GetGameLanguageCode", 0x125150, "DWORD __fastcall ()", "__fastcall"),
    
    # D2COMMON Functions
    ("D2COMMON", "InitLevel", 0x2424A0, "void __stdcall (Level* pLevel)", "__stdcall"),
    ("D2COMMON", "UnloadAct", 0x21AFD3, "unsigned __stdcall (Act* pAct)", "__stdcall"),
    ("D2COMMON", "GetObjectTxt", 0x240E90, "ObjectTxt* __stdcall (DWORD objno)", "__stdcall"),
    ("D2COMMON", "LoadAct", 0x2194A0, "Act* __stdcall (DWORD ActNumber, DWORD MapId, DWORD Unk, DWORD Unk_2, DWORD Unk_3, DWORD Unk_4, DWORD TownLevelId, DWORD Func_1, DWORD Func_2)", "__stdcall"),
    ("D2COMMON", "GetLevelText", 0x21DB70, "LevelTxt* __stdcall (DWORD levelno)", "__stdcall"),
    ("D2COMMON", "GetItemText", 0x2335F0, "ItemTxt* __stdcall (DWORD itemno)", "__stdcall"),
    ("D2COMMON", "GetLayer", 0x21E470, "AutomapLayer2* __fastcall (DWORD dwLevelNo)", "__fastcall"),
    ("D2COMMON", "GetLevel", 0x242AE0, "Level* __fastcall (ActMisc* pMisc, DWORD dwLevelNo)", "__fastcall"),
    ("D2COMMON", "GetStatList", 0x2257D0, "StatList* __stdcall (UnitAny* pUnit, DWORD dwUnk, DWORD dwMaxEntries)", "__stdcall"),
    ("D2COMMON", "CopyStatList", 0x225C90, "DWORD __stdcall (StatList* pStatList, Stat* pStatArray, DWORD dwMaxEntries)", "__stdcall"),
    ("D2COMMON", "GetUnitStat", 0x225480, "DWORD __stdcall (UnitAny* pUnit, DWORD dwStat, DWORD dwStat2)", "__stdcall"),
    ("D2COMMON", "GetUnitState", 0x239DF0, "int __stdcall (UnitAny* pUnit, DWORD dwStateNo)", "__stdcall"),
    ("D2COMMON", "CheckUnitCollision", 0x222AA0, "DWORD __stdcall (UnitAny* pUnitA, UnitAny* pUnitB, DWORD dwBitMask)", "__stdcall"),
    ("D2COMMON", "GetRoomFromUnit", 0x220BB0, "Room1* __stdcall (UnitAny* ptUnit)", "__stdcall"),
    ("D2COMMON", "GetSkillLevel", 0x2442A0, "INT __stdcall (UnitAny* pUnit, Skill* pSkill, BOOL bTotal)", "__stdcall"),
    ("D2COMMON", "GetItemLevelRequirement", 0x22BA60, "DWORD __stdcall (UnitAny* pItem, UnitAny* pPlayer)", "__stdcall"),
    ("D2COMMON", "GetItemPrice", 0x22FDC0, "DWORD __stdcall (UnitAny* MyUnit, UnitAny* pItem, DWORD U1_, DWORD U2_, DWORD U3_, DWORD U4_)", "__stdcall"),
    ("D2COMMON", "GetRepairCost", 0x22FE60, "DWORD __stdcall (DWORD _1, UnitAny* pUnit, DWORD dwNpcId, DWORD dwDifficulty, DWORD dwItemPriceList, DWORD _2)", "__stdcall"),
    ("D2COMMON", "GetItemMagicalMods", 0x233EE0, "char* __stdcall (WORD wPrefixNum)", "__stdcall"),
    ("D2COMMON", "GetItemFromInventory", 0x23B2C0, "UnitAny* __stdcall (Inventory* inv)", "__stdcall"),
    ("D2COMMON", "GetNextItemFromInventory", 0x23DFA0, "UnitAny* __stdcall (UnitAny* pItem)", "__stdcall"),
    ("D2COMMON", "GenerateOverheadMsg", 0x261110, "OverheadMsg* __stdcall (DWORD dwUnk, CHAR* szMsg, DWORD dwTrigger)", "__stdcall"),
    ("D2COMMON", "FixOverheadMsg", 0x261230, "VOID __stdcall (OverheadMsg* pMsg, DWORD dwUnk)", "__stdcall"),
    ("D2COMMON", "AddRoomData", 0x21A070, "void __stdcall (Act* ptAct, int LevelId, int Xpos, int Ypos, Room1* pRoom)", "__stdcall"),
    ("D2COMMON", "RemoveRoomData", 0x21A0C0, "void __stdcall (Act* ptAct, int LevelId, int Xpos, int Ypos, Room1* pRoom)", "__stdcall"),
    ("D2COMMON", "GetQuestFlag", 0x25C310, "int __stdcall (void* QuestInfo, DWORD dwAct, DWORD dwQuest)", "__stdcall"),
    ("D2COMMON", "MapToAbsScreen", 0x243260, "void __stdcall (long* pX, long* pY)", "__stdcall"),
    ("D2COMMON", "AbsScreenToMap", 0x243510, "void __stdcall (long* ptMouseX, long* ptMouseY)", "__stdcall"),
    ("D2COMMON", "CheckWaypoint", 0x260E50, "DWORD __stdcall (DWORD WaypointTable, DWORD dwLevelId)", "__stdcall"),
    ("D2COMMON", "IsTownByLevelNo", 0x21AAF0, "BOOL __stdcall (DWORD dwLevelNo)", "__stdcall"),
    ("D2COMMON", "GetLevelNoFromRoom", 0x21A1B0, "BOOL __stdcall (Room1* pRoom1)", "__stdcall"),
    ("D2COMMON", "FindRoom1", 0x219DA3, "Room1* __stdcall (Act* pAct, int x, int y)", "__stdcall"),
    ("D2COMMON", "GetItemPalette", 0x22C100, "int __stdcall (UnitAny* pPlayer, UnitAny* pItem, BYTE* pColor, int nTransType)", "__stdcall"),
    ("D2COMMON", "GetMissileOwnerUnit", 0x639D0, "UnitAny* __fastcall (UnitAny* pMissile)", "__fastcall"),
    
    # D2NET Functions
    ("D2NET", "SendPacket", 0x12AE50, "void __stdcall (size_t aLen, DWORD arg1, BYTE* aPacket)", "__stdcall"),
    ("D2NET", "ReceivePacket", 0x12AEB0, "void __fastcall (BYTE* aPacket, DWORD aLen)", "__fastcall"),
    ("D2NET", "ReceivePacket_I", 0x12B920, "void __fastcall (BYTE* aPacket, DWORD aLen, int* arg3)", "__fastcall"),
    
    # D2GFX Functions
    ("D2GFX", "DrawRectangle", 0xF6300, "void __stdcall (int X1, int Y1, int X2, int Y2, DWORD dwColor, DWORD dwTrans)", "__stdcall"),
    ("D2GFX", "DrawLine", 0xF6380, "void __stdcall (int X1, int Y1, int X2, int Y2, DWORD dwColor, DWORD dwUnk)", "__stdcall"),
    ("D2GFX", "DrawAutomapCell2", 0xF6480, "void __stdcall (CellContext* context, DWORD xpos, DWORD ypos, DWORD bright2, DWORD bright, BYTE* coltab)", "__stdcall"),
    ("D2GFX", "GetHwnd", 0xF59A0, "HWND __stdcall (void)", "__stdcall"),
    ("D2GFX", "GetScreenSize", 0xF5160, "DWORD __stdcall ()", "__stdcall"),
    
    # D2MULTI Functions
    ("D2MULTI", "DoChat", 0x42810, "void __fastcall (void)", "__fastcall"),
    ("D2MULTI", "PrintChannelText_", 0x47AB0, "void __fastcall (int unused, char* szText, DWORD dwColor)", "__fastcall"),
    
    # D2CMP Functions
    ("D2CMP", "InitCellFile", 0x201340, "VOID __stdcall (LPVOID File, CellFile** Out, LPSTR SourceFile, DWORD Line, DWORD FileVersion, LPSTR Filename)", "__stdcall"),
    ("D2CMP", "DeleteCellFile", 0x201A50, "void __stdcall (CellFile* File)", "__stdcall"),
    
    # D2LANG Functions
    ("D2LANG", "GetLocaleText", 0x124A30, "wchar_t* __fastcall (WORD nLocaleTxtNo)", "__fastcall"),
    
    # D2WIN Functions
    ("D2WIN", "SetControlText", 0xFF5A0, "void* __fastcall (Control* box, const wchar_t* txt)", "__fastcall"),
    ("D2WIN", "DrawSprites", 0xF9870, "void __fastcall (void)", "__fastcall"),
    ("D2WIN", "LoadCellFile", 0xFA9B0, "CellFile* __fastcall (const char* szFile, int Type)", "__fastcall"),
    ("D2WIN", "TakeScreenshot", 0xFA7A0, "void __fastcall ()", "__fastcall"),
    ("D2WIN", "DrawText", 0x102320, "void __fastcall (const wchar_t* wStr, int xPos, int yPos, DWORD dwColor, DWORD dwUnk)", "__fastcall"),
    ("D2WIN", "GetTextSize", 0x102520, "DWORD __fastcall (wchar_t* wStr, DWORD* dwWidth, DWORD* dwFileNo)", "__fastcall"),
    ("D2WIN", "SetTextSize", 0x102EF0, "DWORD __fastcall (DWORD dwSize)", "__fastcall"),
    ("D2WIN", "DestroyEditBox", 0xFDAA0, "DWORD __fastcall (Control* box)", "__fastcall"),
    ("D2WIN", "DestroyControl", 0xF95C0, "VOID __stdcall (Control* pControl)", "__stdcall"),
    ("D2WIN", "SetEditBoxCallback", 0xFDAD0, "VOID __fastcall (Control* pControl, BOOL(__stdcall* FunCallBack)(Control*, DWORD, char*))", "__fastcall"),
    ("D2WIN", "SelectEditBoxText", 0xFDD00, "void __fastcall (Control* box)", "__fastcall"),
    ("D2WIN", "InitMPQ", 0x117332, "DWORD __fastcall (const char* mpqfile, char* mpqname, int v4, int v5)", "__fastcall"),
    
    # D2GAME Functions
    ("D2GAME", "Rand", 0x5C370, "DWORD __fastcall (DWORD* seed)", "__fastcall"),
]

# Global variables from d2bs (1.14d offsets)
KNOWN_GLOBALS_1_14D = [
    ("D2CLIENT", "ScreenSizeX", 0x31146C, "DWORD"),
    ("D2CLIENT", "ScreenSizeY", 0x311470, "DWORD"),
    ("D2CLIENT", "CursorHoverX", 0x321E4C, "DWORD"),
    ("D2CLIENT", "CursorHoverY", 0x321E50, "DWORD"),
    ("D2CLIENT", "MouseY", 0x3A6AAC, "DWORD"),
    ("D2CLIENT", "MouseX", 0x3A6AB0, "DWORD"),
    ("D2CLIENT", "AutomapOn", 0x3A27E8, "DWORD"),
    ("D2CLIENT", "AutomapMode", 0x311254, "int"),
    ("D2CLIENT", "AutomapLayer", 0x3A5164, "AutomapLayer*"),
    ("D2CLIENT", "MercReviveCost", 0x3C0DD0, "DWORD"),
    ("D2CLIENT", "ServerSideUnitHashTables", 0x3A5E70, "UnitHashTable"),
    ("D2CLIENT", "ClientSideUnitHashTables", 0x3A5270, "UnitHashTable"),
    ("D2CLIENT", "GoldDialogAction", 0x3A279C, "DWORD"),
    ("D2CLIENT", "GoldDialogAmount", 0x3A2A68, "DWORD"),
    ("D2CLIENT", "NPCMenu", 0x326C48, "NPCMenu*"),
    ("D2CLIENT", "NPCMenuAmount", 0x325A74, "DWORD"),
    ("D2CLIENT", "Ping", 0x3A04A4, "DWORD"),
    ("D2CLIENT", "Skip", 0x3A04B0, "DWORD"),
    ("D2CLIENT", "FPS", 0x3BB390, "DWORD"),
    ("D2CLIENT", "Lang", 0x3BB5DC, "DWORD"),
    ("D2CLIENT", "PlayerUnit", 0x3A6A70, "UnitAny*"),
    ("D2CLIENT", "SelectedInvItem", 0x3BCBF4, "UnitAny*"),
    ("D2CLIENT", "PlayerUnitList", 0x3BB5C0, "RosterUnit*"),
    ("D2CLIENT", "bWeapSwitch", 0x3BCC4C, "DWORD"),
    ("D2CLIENT", "bTradeAccepted", 0x3BCE18, "DWORD"),
    ("D2CLIENT", "bTradeBlock", 0x3BCE28, "DWORD"),
    ("D2CLIENT", "ExpCharFlag", 0x3A04F4, "DWORD"),
    ("D2CLIENT", "MapId", 0x3A0638, "DWORD"),
    ("D2CLIENT", "AlwaysRun", 0x3A0660, "DWORD"),
    ("D2CLIENT", "NoPickUp", 0x3A6A90, "DWORD"),
    ("D2CLIENT", "GameInfo", 0x3A0438, "GameStructInfo*"),
    ("D2CLIENT", "WaypointTable", 0x3BF081, "DWORD"),
    
    ("D2COMMON", "sgptDataTable", 0x344304, "DWORD"),
    
    ("D2WIN", "FirstControl", 0x3D55BC, "Control*"),
    ("D2WIN", "FocusedControl", 0x3D55CC, "Control*"),
    
    ("D2MULTI", "ChatBoxMsg", 0x37AE40, "char*"),
    ("D2MULTI", "GameListControl", 0x398BC0, "Control*"),
    ("D2MULTI", "ChatInputBox", 0x398C80, "DWORD*"),
    
    ("D2LAUNCH", "BnData", 0x3795D4, "BnetData*"),
    
    ("BNCLIENT", "ClassicKey", 0x482744, "char*"),
    ("BNCLIENT", "XPacKey", 0x48274C, "char*"),
    ("BNCLIENT", "KeyOwner", 0x482750, "char*"),
]


@dataclass
class D2Function:
    """Represents a D2 function entry"""
    module: str
    name: str
    offset: int
    signature: str
    calling_convention: str
    version: str
    absolute_address: Optional[int] = None
    verified: bool = False
    verification_note: str = ""
    
    @property
    def full_name(self) -> str:
        return f"{self.module}_{self.name}"
    
    def calculate_absolute_address(self, base_address: int) -> int:
        self.absolute_address = base_address + self.offset
        return self.absolute_address


@dataclass
class D2Global:
    """Represents a D2 global variable entry"""
    module: str
    name: str
    offset: int
    type_name: str
    version: str
    absolute_address: Optional[int] = None


class D2FunctionDatabase:
    """Database of known D2 functions from the modding community"""
    
    def __init__(self):
        self.functions: Dict[str, D2Function] = {}
        self.globals: Dict[str, D2Global] = {}
        
    def load_1_14d_database(self):
        """Load the 1.14d function database from d2bs"""
        # Base address for Game.exe in 1.14d
        base_address = 0x400000
        
        for entry in KNOWN_FUNCTIONS_1_14D:
            module, name, offset, signature, calling_conv = entry
            func = D2Function(
                module=module,
                name=name,
                offset=offset,
                signature=signature,
                calling_convention=calling_conv,
                version="1.14d"
            )
            func.calculate_absolute_address(base_address)
            key = f"{module}_{name}"
            self.functions[key] = func
            
        for entry in KNOWN_GLOBALS_1_14D:
            module, name, offset, type_name = entry
            glob = D2Global(
                module=module,
                name=name,
                offset=offset,
                type_name=type_name,
                version="1.14d"
            )
            glob.absolute_address = base_address + offset
            key = f"{module}_{name}"
            self.globals[key] = glob
            
    def get_functions_by_module(self, module: str) -> List[D2Function]:
        """Get all functions for a specific module"""
        return [f for f in self.functions.values() if f.module == module]
    
    def get_function_by_address(self, address: int) -> Optional[D2Function]:
        """Find a function by its absolute address"""
        for func in self.functions.values():
            if func.absolute_address == address:
                return func
        return None
    
    def export_to_json(self, filepath: str):
        """Export the database to JSON format"""
        data = {
            "metadata": {
                "source": "d2bs project (blizzhackers/d2bs)",
                "version": "1.14d",
                "base_address": "0x400000",
                "description": "Diablo 2 function database from modding community"
            },
            "functions": [asdict(f) for f in self.functions.values()],
            "globals": [asdict(g) for g in self.globals.values()]
        }
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"Exported {len(self.functions)} functions and {len(self.globals)} globals to {filepath}")
        
    def export_to_ghidra_script(self, filepath: str):
        """Export function definitions as a Ghidra script for renaming"""
        script_lines = [
            "// Ghidra script to apply D2 function names from modding community",
            "// Source: d2bs project (blizzhackers/d2bs)",
            "// Version: 1.14d",
            "",
            "import ghidra.program.model.symbol.SourceType;",
            "import ghidra.program.model.listing.Function;",
            "",
            "public class ApplyD2FunctionNames extends GhidraScript {",
            "    @Override",
            "    public void run() throws Exception {",
            "        FunctionManager fm = currentProgram.getFunctionManager();",
            ""
        ]
        
        for func in self.functions.values():
            if func.absolute_address:
                addr_str = f"0x{func.absolute_address:08X}"
                script_lines.append(
                    f'        renameFunction(fm, toAddr({addr_str}), "{func.full_name}");'
                )
        
        script_lines.extend([
            "    }",
            "",
            "    private void renameFunction(FunctionManager fm, Address addr, String name) {",
            "        Function func = fm.getFunctionAt(addr);",
            "        if (func != null) {",
            "            try {",
            "                func.setName(name, SourceType.USER_DEFINED);",
            "                println(\"Renamed function at \" + addr + \" to \" + name);",
            "            } catch (Exception e) {",
            "                println(\"Failed to rename function at \" + addr + \": \" + e.getMessage());",
            "            }",
            "        } else {",
            "            println(\"No function found at \" + addr);",
            "        }",
            "    }",
            "}",
        ])
        
        with open(filepath, 'w') as f:
            f.write('\n'.join(script_lines))
        
        print(f"Exported Ghidra script to {filepath}")
        
    def print_summary(self):
        """Print a summary of the database"""
        print("\n=== D2 Function Database Summary ===")
        print(f"Total functions: {len(self.functions)}")
        print(f"Total globals: {len(self.globals)}")
        print("\nFunctions by module:")
        
        module_counts = {}
        for func in self.functions.values():
            module_counts[func.module] = module_counts.get(func.module, 0) + 1
        
        for module, count in sorted(module_counts.items()):
            print(f"  {module}: {count} functions")
            
        print("\nGlobals by module:")
        module_counts = {}
        for glob in self.globals.values():
            module_counts[glob.module] = module_counts.get(glob.module, 0) + 1
            
        for module, count in sorted(module_counts.items()):
            print(f"  {module}: {count} globals")


def main():
    """Main function to generate the D2 function database"""
    db = D2FunctionDatabase()
    db.load_1_14d_database()
    db.print_summary()
    
    # Export paths
    base_path = os.path.dirname(os.path.abspath(__file__))
    reports_path = os.path.join(os.path.dirname(base_path), "reports", "data")
    
    # Ensure output directory exists
    os.makedirs(reports_path, exist_ok=True)
    
    # Export to JSON
    json_path = os.path.join(reports_path, "d2_known_functions.json")
    db.export_to_json(json_path)
    
    # Export Ghidra script
    script_path = os.path.join(base_path, "apply_d2_function_names.java")
    db.export_to_ghidra_script(script_path)
    
    print("\n=== Sample Functions (first 10) ===")
    for i, func in enumerate(list(db.functions.values())[:10]):
        print(f"{func.module}_{func.name}: 0x{func.absolute_address:08X} - {func.calling_convention}")


if __name__ == "__main__":
    main()
