// D2 Known Functions Database - JavaScript data file for d2_report_viewer.html
// Generated from d2bs project (blizzhackers/d2bs)
// Version: 1.14d

const D2_KNOWN_FUNCTIONS = {
  metadata: {
    source: 'd2bs project (blizzhackers/d2bs)',
    version: '1.14d',
    base_address: '0x400000',
    description: 'Diablo 2 function database from modding community',
    total_functions: 105,
    total_globals: 42
  },
  functions: [
    // D2CLIENT Functions (45 total)
    {
      module: 'D2CLIENT',
      name: 'GetQuestInfo',
      offset: '0xB32D0',
      absolute: '0x004B32D0',
      signature: 'void* __stdcall (void)',
      calling_convention: '__stdcall'
    },
    {
      module: 'D2CLIENT',
      name: 'SubmitItem',
      offset: '0xB2370',
      absolute: '0x004B2370',
      signature: 'void __fastcall (DWORD dwItemId)',
      calling_convention: '__fastcall'
    },
    {
      module: 'D2CLIENT',
      name: 'Transmute',
      offset: '0x8A0D0',
      absolute: '0x0048A0D0',
      signature: 'void __fastcall (void)',
      calling_convention: '__fastcall'
    },
    {
      module: 'D2CLIENT',
      name: 'FindClientSideUnit',
      offset: '0x63990',
      absolute: '0x00463990',
      signature: 'UnitAny* __fastcall (DWORD dwId, DWORD dwType)',
      calling_convention: '__fastcall'
    },
    {
      module: 'D2CLIENT',
      name: 'FindServerSideUnit',
      offset: '0x639B0',
      absolute: '0x004639B0',
      signature: 'UnitAny* __fastcall (DWORD dwId, DWORD dwType)',
      calling_convention: '__fastcall'
    },
    {
      module: 'D2CLIENT',
      name: 'GetCurrentInteractingNPC',
      offset: '0xB1620',
      absolute: '0x004B1620',
      signature: 'UnitAny* __fastcall (void)',
      calling_convention: '__fastcall'
    },
    {
      module: 'D2CLIENT',
      name: 'GetSelectedUnit',
      offset: '0x67A10',
      absolute: '0x00467A10',
      signature: 'UnitAny* __stdcall ()',
      calling_convention: '__stdcall'
    },
    {
      module: 'D2CLIENT',
      name: 'GetCursorItem',
      offset: '0x680A0',
      absolute: '0x004680A0',
      signature: 'UnitAny* __fastcall (void)',
      calling_convention: '__fastcall'
    },
    {
      module: 'D2CLIENT',
      name: 'SetSelectedUnit_I',
      offset: '0x66DE0',
      absolute: '0x00466DE0',
      signature: 'void __fastcall (UnitAny* pUnit)',
      calling_convention: '__fastcall'
    },
    {
      module: 'D2CLIENT',
      name: 'GetItemName',
      offset: '0x8C060',
      absolute: '0x0048C060',
      signature:
        'BOOL __fastcall (UnitAny* pItem, wchar_t* wBuffer, DWORD dwSize)',
      calling_convention: '__fastcall'
    },
    {
      module: 'D2CLIENT',
      name: 'LoadItemDesc',
      offset: '0x8DD90',
      absolute: '0x0048DD90',
      signature: 'BOOL __stdcall (UnitAny* pItem, int type)',
      calling_convention: '__stdcall'
    },
    {
      module: 'D2CLIENT',
      name: 'GetMonsterOwner',
      offset: '0x79150',
      absolute: '0x00479150',
      signature: 'DWORD __fastcall (DWORD nMonsterId)',
      calling_convention: '__fastcall'
    },
    {
      module: 'D2CLIENT',
      name: 'GetUnitHPPercent',
      offset: '0x79080',
      absolute: '0x00479080',
      signature: 'DWORD __fastcall (DWORD dwUnitId)',
      calling_convention: '__fastcall'
    },
    {
      module: 'D2CLIENT',
      name: 'InitInventory',
      offset: '0x845A0',
      absolute: '0x004845A0',
      signature: 'void __fastcall (void)',
      calling_convention: '__fastcall'
    },
    {
      module: 'D2CLIENT',
      name: 'SetUIVar',
      offset: '0x55F20',
      absolute: '0x00455F20',
      signature: 'DWORD __fastcall (DWORD varno, DWORD howset, DWORD unknown1)',
      calling_convention: '__fastcall'
    },
    {
      module: 'D2CLIENT',
      name: 'GetUnitX',
      offset: '0x5ADF0',
      absolute: '0x0045ADF0',
      signature: 'int __fastcall (UnitAny* pUnit)',
      calling_convention: '__fastcall'
    },
    {
      module: 'D2CLIENT',
      name: 'GetUnitY',
      offset: '0x5AE20',
      absolute: '0x0045AE20',
      signature: 'int __fastcall (UnitAny* pUnit)',
      calling_convention: '__fastcall'
    },
    {
      module: 'D2CLIENT',
      name: 'ShopAction',
      offset: '0xB3870',
      absolute: '0x004B3870',
      signature: 'void __fastcall (...)',
      calling_convention: '__fastcall'
    },
    {
      module: 'D2CLIENT',
      name: 'CloseNPCInteract',
      offset: '0xB3F10',
      absolute: '0x004B3F10',
      signature: 'void __fastcall (void)',
      calling_convention: '__fastcall'
    },
    {
      module: 'D2CLIENT',
      name: 'CloseInteract',
      offset: '0x4C6B0',
      absolute: '0x0044C6B0',
      signature: 'void __fastcall (void)',
      calling_convention: '__fastcall'
    },
    {
      module: 'D2CLIENT',
      name: 'GetAutomapSize',
      offset: '0x5A710',
      absolute: '0x0045A710',
      signature: 'DWORD __stdcall (void)',
      calling_convention: '__stdcall'
    },
    {
      module: 'D2CLIENT',
      name: 'NewAutomapCell',
      offset: '0x57C30',
      absolute: '0x00457C30',
      signature: 'AutomapCell* __fastcall ()',
      calling_convention: '__fastcall'
    },
    {
      module: 'D2CLIENT',
      name: 'AddAutomapCell',
      offset: '0x57B00',
      absolute: '0x00457B00',
      signature: 'void __fastcall (AutomapCell* aCell, AutomapCell** node)',
      calling_convention: '__fastcall'
    },
    {
      module: 'D2CLIENT',
      name: 'RevealAutomapRoom',
      offset: '0x58F40',
      absolute: '0x00458F40',
      signature:
        'void __stdcall (Room1* pRoom1, DWORD dwClipFlag, AutomapLayer* aLayer)',
      calling_convention: '__stdcall'
    },
    {
      module: 'D2CLIENT',
      name: 'InitAutomapLayer_I',
      offset: '0x58D40',
      absolute: '0x00458D40',
      signature: 'AutomapLayer* __fastcall (DWORD nLayerNo)',
      calling_convention: '__fastcall'
    },
    {
      module: 'D2CLIENT',
      name: 'ClickMap',
      offset: '0x62D00',
      absolute: '0x00462D00',
      signature:
        'void __fastcall (DWORD MouseFlag, DWORD x, DWORD y, DWORD Type)',
      calling_convention: '__fastcall'
    },
    {
      module: 'D2CLIENT',
      name: 'LeftClickItem_I',
      offset: '0x8FFE0',
      absolute: '0x0048FFE0',
      signature: 'void __stdcall (...)',
      calling_convention: '__stdcall'
    },
    {
      module: 'D2CLIENT',
      name: 'GetMouseXOffset',
      offset: '0x5AFC0',
      absolute: '0x0045AFC0',
      signature: 'DWORD __fastcall (VOID)',
      calling_convention: '__fastcall'
    },
    {
      module: 'D2CLIENT',
      name: 'GetMouseYOffset',
      offset: '0x5AFB0',
      absolute: '0x0045AFB0',
      signature: 'DWORD __fastcall (VOID)',
      calling_convention: '__fastcall'
    },
    {
      module: 'D2CLIENT',
      name: 'PrintGameString',
      offset: '0x9E3A0',
      absolute: '0x0049E3A0',
      signature: 'void __fastcall (wchar_t* wMessage, int nColor)',
      calling_convention: '__fastcall'
    },
    {
      module: 'D2CLIENT',
      name: 'PrintPartyString',
      offset: '0x9E5C0',
      absolute: '0x0049E5C0',
      signature: 'void __fastcall (wchar_t* wMessage, int nColor)',
      calling_convention: '__fastcall'
    },
    {
      module: 'D2CLIENT',
      name: 'LeaveParty',
      offset: '0x79FC0',
      absolute: '0x00479FC0',
      signature: 'void __fastcall (void)',
      calling_convention: '__fastcall'
    },
    {
      module: 'D2CLIENT',
      name: 'AcceptTrade',
      offset: '0xB9070',
      absolute: '0x004B9070',
      signature: 'void __fastcall (void)',
      calling_convention: '__fastcall'
    },
    {
      module: 'D2CLIENT',
      name: 'CancelTrade',
      offset: '0xB90B0',
      absolute: '0x004B90B0',
      signature: 'void __fastcall (void)',
      calling_convention: '__fastcall'
    },
    {
      module: 'D2CLIENT',
      name: 'TradeOK',
      offset: '0xB8A30',
      absolute: '0x004B8A30',
      signature: 'void __stdcall (void)',
      calling_convention: '__stdcall'
    },
    {
      module: 'D2CLIENT',
      name: 'GetDifficulty',
      offset: '0x4DCD0',
      absolute: '0x0044DCD0',
      signature: 'BYTE __stdcall ()',
      calling_convention: '__stdcall'
    },
    {
      module: 'D2CLIENT',
      name: 'ExitGame',
      offset: '0x4DD60',
      absolute: '0x0044DD60',
      signature: 'void __fastcall (void)',
      calling_convention: '__fastcall'
    },
    {
      module: 'D2CLIENT',
      name: 'GetUiVar_I',
      offset: '0x538D0',
      absolute: '0x004538D0',
      signature: 'DWORD __fastcall (DWORD dwVarNo)',
      calling_convention: '__fastcall'
    },
    {
      module: 'D2CLIENT',
      name: 'DrawRectFrame',
      offset: '0x52E50',
      absolute: '0x00452E50',
      signature: 'VOID __fastcall (DWORD Rect)',
      calling_convention: '__fastcall'
    },
    {
      module: 'D2CLIENT',
      name: 'PerformGoldDialogAction',
      offset: '0x54080',
      absolute: '0x00454080',
      signature: 'void __fastcall (void)',
      calling_convention: '__fastcall'
    },
    {
      module: 'D2CLIENT',
      name: 'GetPlayerUnit',
      offset: '0x63DD0',
      absolute: '0x00463DD0',
      signature: 'UnitAny* __stdcall ()',
      calling_convention: '__stdcall'
    },
    {
      module: 'D2CLIENT',
      name: 'ClearScreen',
      offset: '0xB4620',
      absolute: '0x004B4620',
      signature: 'void __fastcall (void)',
      calling_convention: '__fastcall'
    },
    {
      module: 'D2CLIENT',
      name: 'CloseNPCTalk',
      offset: '0xA17D0',
      absolute: '0x004A17D0',
      signature: 'DWORD __stdcall (void* unk)',
      calling_convention: '__stdcall'
    },
    {
      module: 'D2CLIENT',
      name: 'TestPvpFlag',
      offset: '0xDC440',
      absolute: '0x004DC440',
      signature:
        'DWORD __fastcall (DWORD dwUnitId1, DWORD dwUnitId2, DWORD dwFlag)',
      calling_convention: '__fastcall'
    },
    {
      module: 'D2CLIENT',
      name: 'GetGameLanguageCode',
      offset: '0x125150',
      absolute: '0x00525150',
      signature: 'DWORD __fastcall ()',
      calling_convention: '__fastcall'
    },

    // D2COMMON Functions (34 total)
    {
      module: 'D2COMMON',
      name: 'InitLevel',
      offset: '0x2424A0',
      absolute: '0x006424A0',
      signature: 'void __stdcall (Level* pLevel)',
      calling_convention: '__stdcall'
    },
    {
      module: 'D2COMMON',
      name: 'UnloadAct',
      offset: '0x21AFD3',
      absolute: '0x0061AFD3',
      signature: 'unsigned __stdcall (Act* pAct)',
      calling_convention: '__stdcall'
    },
    {
      module: 'D2COMMON',
      name: 'GetObjectTxt',
      offset: '0x240E90',
      absolute: '0x00640E90',
      signature: 'ObjectTxt* __stdcall (DWORD objno)',
      calling_convention: '__stdcall'
    },
    {
      module: 'D2COMMON',
      name: 'LoadAct',
      offset: '0x2194A0',
      absolute: '0x006194A0',
      signature: 'Act* __stdcall (...)',
      calling_convention: '__stdcall'
    },
    {
      module: 'D2COMMON',
      name: 'GetLevelText',
      offset: '0x21DB70',
      absolute: '0x0061DB70',
      signature: 'LevelTxt* __stdcall (DWORD levelno)',
      calling_convention: '__stdcall'
    },
    {
      module: 'D2COMMON',
      name: 'GetItemText',
      offset: '0x2335F0',
      absolute: '0x006335F0',
      signature: 'ItemTxt* __stdcall (DWORD itemno)',
      calling_convention: '__stdcall'
    },
    {
      module: 'D2COMMON',
      name: 'GetLayer',
      offset: '0x21E470',
      absolute: '0x0061E470',
      signature: 'AutomapLayer2* __fastcall (DWORD dwLevelNo)',
      calling_convention: '__fastcall'
    },
    {
      module: 'D2COMMON',
      name: 'GetLevel',
      offset: '0x242AE0',
      absolute: '0x00642AE0',
      signature: 'Level* __fastcall (ActMisc* pMisc, DWORD dwLevelNo)',
      calling_convention: '__fastcall'
    },
    {
      module: 'D2COMMON',
      name: 'GetStatList',
      offset: '0x2257D0',
      absolute: '0x006257D0',
      signature:
        'StatList* __stdcall (UnitAny* pUnit, DWORD dwUnk, DWORD dwMaxEntries)',
      calling_convention: '__stdcall'
    },
    {
      module: 'D2COMMON',
      name: 'CopyStatList',
      offset: '0x225C90',
      absolute: '0x00625C90',
      signature:
        'DWORD __stdcall (StatList* pStatList, Stat* pStatArray, DWORD dwMaxEntries)',
      calling_convention: '__stdcall'
    },
    {
      module: 'D2COMMON',
      name: 'GetUnitStat',
      offset: '0x225480',
      absolute: '0x00625480',
      signature:
        'DWORD __stdcall (UnitAny* pUnit, DWORD dwStat, DWORD dwStat2)',
      calling_convention: '__stdcall'
    },
    {
      module: 'D2COMMON',
      name: 'GetUnitState',
      offset: '0x239DF0',
      absolute: '0x00639DF0',
      signature: 'int __stdcall (UnitAny* pUnit, DWORD dwStateNo)',
      calling_convention: '__stdcall'
    },
    {
      module: 'D2COMMON',
      name: 'CheckUnitCollision',
      offset: '0x222AA0',
      absolute: '0x00622AA0',
      signature:
        'DWORD __stdcall (UnitAny* pUnitA, UnitAny* pUnitB, DWORD dwBitMask)',
      calling_convention: '__stdcall'
    },
    {
      module: 'D2COMMON',
      name: 'GetRoomFromUnit',
      offset: '0x220BB0',
      absolute: '0x00620BB0',
      signature: 'Room1* __stdcall (UnitAny* ptUnit)',
      calling_convention: '__stdcall'
    },
    {
      module: 'D2COMMON',
      name: 'GetSkillLevel',
      offset: '0x2442A0',
      absolute: '0x006442A0',
      signature: 'INT __stdcall (UnitAny* pUnit, Skill* pSkill, BOOL bTotal)',
      calling_convention: '__stdcall'
    },
    {
      module: 'D2COMMON',
      name: 'GetItemLevelRequirement',
      offset: '0x22BA60',
      absolute: '0x0062BA60',
      signature: 'DWORD __stdcall (UnitAny* pItem, UnitAny* pPlayer)',
      calling_convention: '__stdcall'
    },
    {
      module: 'D2COMMON',
      name: 'GetItemPrice',
      offset: '0x22FDC0',
      absolute: '0x0062FDC0',
      signature: 'DWORD __stdcall (...)',
      calling_convention: '__stdcall'
    },
    {
      module: 'D2COMMON',
      name: 'GetRepairCost',
      offset: '0x22FE60',
      absolute: '0x0062FE60',
      signature: 'DWORD __stdcall (...)',
      calling_convention: '__stdcall'
    },
    {
      module: 'D2COMMON',
      name: 'GetItemMagicalMods',
      offset: '0x233EE0',
      absolute: '0x00633EE0',
      signature: 'char* __stdcall (WORD wPrefixNum)',
      calling_convention: '__stdcall'
    },
    {
      module: 'D2COMMON',
      name: 'GetItemFromInventory',
      offset: '0x23B2C0',
      absolute: '0x0063B2C0',
      signature: 'UnitAny* __stdcall (Inventory* inv)',
      calling_convention: '__stdcall'
    },
    {
      module: 'D2COMMON',
      name: 'GetNextItemFromInventory',
      offset: '0x23DFA0',
      absolute: '0x0063DFA0',
      signature: 'UnitAny* __stdcall (UnitAny* pItem)',
      calling_convention: '__stdcall'
    },
    {
      module: 'D2COMMON',
      name: 'GenerateOverheadMsg',
      offset: '0x261110',
      absolute: '0x00661110',
      signature:
        'OverheadMsg* __stdcall (DWORD dwUnk, CHAR* szMsg, DWORD dwTrigger)',
      calling_convention: '__stdcall'
    },
    {
      module: 'D2COMMON',
      name: 'FixOverheadMsg',
      offset: '0x261230',
      absolute: '0x00661230',
      signature: 'VOID __stdcall (OverheadMsg* pMsg, DWORD dwUnk)',
      calling_convention: '__stdcall'
    },
    {
      module: 'D2COMMON',
      name: 'AddRoomData',
      offset: '0x21A070',
      absolute: '0x0061A070',
      signature:
        'void __stdcall (Act* ptAct, int LevelId, int Xpos, int Ypos, Room1* pRoom)',
      calling_convention: '__stdcall'
    },
    {
      module: 'D2COMMON',
      name: 'RemoveRoomData',
      offset: '0x21A0C0',
      absolute: '0x0061A0C0',
      signature:
        'void __stdcall (Act* ptAct, int LevelId, int Xpos, int Ypos, Room1* pRoom)',
      calling_convention: '__stdcall'
    },
    {
      module: 'D2COMMON',
      name: 'GetQuestFlag',
      offset: '0x25C310',
      absolute: '0x0065C310',
      signature: 'int __stdcall (void* QuestInfo, DWORD dwAct, DWORD dwQuest)',
      calling_convention: '__stdcall'
    },
    {
      module: 'D2COMMON',
      name: 'MapToAbsScreen',
      offset: '0x243260',
      absolute: '0x00643260',
      signature: 'void __stdcall (long* pX, long* pY)',
      calling_convention: '__stdcall'
    },
    {
      module: 'D2COMMON',
      name: 'AbsScreenToMap',
      offset: '0x243510',
      absolute: '0x00643510',
      signature: 'void __stdcall (long* ptMouseX, long* ptMouseY)',
      calling_convention: '__stdcall'
    },
    {
      module: 'D2COMMON',
      name: 'CheckWaypoint',
      offset: '0x260E50',
      absolute: '0x00660E50',
      signature: 'DWORD __stdcall (DWORD WaypointTable, DWORD dwLevelId)',
      calling_convention: '__stdcall'
    },
    {
      module: 'D2COMMON',
      name: 'IsTownByLevelNo',
      offset: '0x21AAF0',
      absolute: '0x0061AAF0',
      signature: 'BOOL __stdcall (DWORD dwLevelNo)',
      calling_convention: '__stdcall'
    },
    {
      module: 'D2COMMON',
      name: 'GetLevelNoFromRoom',
      offset: '0x21A1B0',
      absolute: '0x0061A1B0',
      signature: 'BOOL __stdcall (Room1* pRoom1)',
      calling_convention: '__stdcall'
    },
    {
      module: 'D2COMMON',
      name: 'FindRoom1',
      offset: '0x219DA3',
      absolute: '0x00619DA3',
      signature: 'Room1* __stdcall (Act* pAct, int x, int y)',
      calling_convention: '__stdcall'
    },
    {
      module: 'D2COMMON',
      name: 'GetItemPalette',
      offset: '0x22C100',
      absolute: '0x0062C100',
      signature:
        'int __stdcall (UnitAny* pPlayer, UnitAny* pItem, BYTE* pColor, int nTransType)',
      calling_convention: '__stdcall'
    },
    {
      module: 'D2COMMON',
      name: 'GetMissileOwnerUnit',
      offset: '0x639D0',
      absolute: '0x004639D0',
      signature: 'UnitAny* __fastcall (UnitAny* pMissile)',
      calling_convention: '__fastcall'
    },

    // D2NET Functions (3 total)
    {
      module: 'D2NET',
      name: 'SendPacket',
      offset: '0x12AE50',
      absolute: '0x0052AE50',
      signature: 'void __stdcall (size_t aLen, DWORD arg1, BYTE* aPacket)',
      calling_convention: '__stdcall'
    },
    {
      module: 'D2NET',
      name: 'ReceivePacket',
      offset: '0x12AEB0',
      absolute: '0x0052AEB0',
      signature: 'void __fastcall (BYTE* aPacket, DWORD aLen)',
      calling_convention: '__fastcall'
    },
    {
      module: 'D2NET',
      name: 'ReceivePacket_I',
      offset: '0x12B920',
      absolute: '0x0052B920',
      signature: 'void __fastcall (BYTE* aPacket, DWORD aLen, int* arg3)',
      calling_convention: '__fastcall'
    },

    // D2GFX Functions (5 total)
    {
      module: 'D2GFX',
      name: 'DrawRectangle',
      offset: '0xF6300',
      absolute: '0x004F6300',
      signature:
        'void __stdcall (int X1, int Y1, int X2, int Y2, DWORD dwColor, DWORD dwTrans)',
      calling_convention: '__stdcall'
    },
    {
      module: 'D2GFX',
      name: 'DrawLine',
      offset: '0xF6380',
      absolute: '0x004F6380',
      signature:
        'void __stdcall (int X1, int Y1, int X2, int Y2, DWORD dwColor, DWORD dwUnk)',
      calling_convention: '__stdcall'
    },
    {
      module: 'D2GFX',
      name: 'DrawAutomapCell2',
      offset: '0xF6480',
      absolute: '0x004F6480',
      signature: 'void __stdcall (...)',
      calling_convention: '__stdcall'
    },
    {
      module: 'D2GFX',
      name: 'GetHwnd',
      offset: '0xF59A0',
      absolute: '0x004F59A0',
      signature: 'HWND __stdcall (void)',
      calling_convention: '__stdcall'
    },
    {
      module: 'D2GFX',
      name: 'GetScreenSize',
      offset: '0xF5160',
      absolute: '0x004F5160',
      signature: 'DWORD __stdcall ()',
      calling_convention: '__stdcall'
    },

    // D2MULTI Functions (2 total)
    {
      module: 'D2MULTI',
      name: 'DoChat',
      offset: '0x42810',
      absolute: '0x00442810',
      signature: 'void __fastcall (void)',
      calling_convention: '__fastcall'
    },
    {
      module: 'D2MULTI',
      name: 'PrintChannelText_',
      offset: '0x47AB0',
      absolute: '0x00447AB0',
      signature: 'void __fastcall (int unused, char* szText, DWORD dwColor)',
      calling_convention: '__fastcall'
    },

    // D2WIN Functions (12 total)
    {
      module: 'D2WIN',
      name: 'SetControlText',
      offset: '0xFF5A0',
      absolute: '0x004FF5A0',
      signature: 'void* __fastcall (Control* box, const wchar_t* txt)',
      calling_convention: '__fastcall'
    },
    {
      module: 'D2WIN',
      name: 'DrawSprites',
      offset: '0xF9870',
      absolute: '0x004F9870',
      signature: 'void __fastcall (void)',
      calling_convention: '__fastcall'
    },
    {
      module: 'D2WIN',
      name: 'LoadCellFile',
      offset: '0xFA9B0',
      absolute: '0x004FA9B0',
      signature: 'CellFile* __fastcall (const char* szFile, int Type)',
      calling_convention: '__fastcall'
    },
    {
      module: 'D2WIN',
      name: 'TakeScreenshot',
      offset: '0xFA7A0',
      absolute: '0x004FA7A0',
      signature: 'void __fastcall ()',
      calling_convention: '__fastcall'
    },
    {
      module: 'D2WIN',
      name: 'DrawText',
      offset: '0x102320',
      absolute: '0x00502320',
      signature:
        'void __fastcall (const wchar_t* wStr, int xPos, int yPos, DWORD dwColor, DWORD dwUnk)',
      calling_convention: '__fastcall'
    },
    {
      module: 'D2WIN',
      name: 'GetTextSize',
      offset: '0x102520',
      absolute: '0x00502520',
      signature:
        'DWORD __fastcall (wchar_t* wStr, DWORD* dwWidth, DWORD* dwFileNo)',
      calling_convention: '__fastcall'
    },
    {
      module: 'D2WIN',
      name: 'SetTextSize',
      offset: '0x102EF0',
      absolute: '0x00502EF0',
      signature: 'DWORD __fastcall (DWORD dwSize)',
      calling_convention: '__fastcall'
    },
    {
      module: 'D2WIN',
      name: 'DestroyEditBox',
      offset: '0xFDAA0',
      absolute: '0x004FDAA0',
      signature: 'DWORD __fastcall (Control* box)',
      calling_convention: '__fastcall'
    },
    {
      module: 'D2WIN',
      name: 'DestroyControl',
      offset: '0xF95C0',
      absolute: '0x004F95C0',
      signature: 'VOID __stdcall (Control* pControl)',
      calling_convention: '__stdcall'
    },
    {
      module: 'D2WIN',
      name: 'SetEditBoxCallback',
      offset: '0xFDAD0',
      absolute: '0x004FDAD0',
      signature: 'VOID __fastcall (...)',
      calling_convention: '__fastcall'
    },
    {
      module: 'D2WIN',
      name: 'SelectEditBoxText',
      offset: '0xFDD00',
      absolute: '0x004FDD00',
      signature: 'void __fastcall (Control* box)',
      calling_convention: '__fastcall'
    },
    {
      module: 'D2WIN',
      name: 'InitMPQ',
      offset: '0x117332',
      absolute: '0x00517332',
      signature:
        'DWORD __fastcall (const char* mpqfile, char* mpqname, int v4, int v5)',
      calling_convention: '__fastcall'
    },

    // D2LANG Functions (1 total)
    {
      module: 'D2LANG',
      name: 'GetLocaleText',
      offset: '0x124A30',
      absolute: '0x00524A30',
      signature: 'wchar_t* __fastcall (WORD nLocaleTxtNo)',
      calling_convention: '__fastcall'
    },

    // D2CMP Functions (2 total)
    {
      module: 'D2CMP',
      name: 'InitCellFile',
      offset: '0x201340',
      absolute: '0x00601340',
      signature: 'VOID __stdcall (...)',
      calling_convention: '__stdcall'
    },
    {
      module: 'D2CMP',
      name: 'DeleteCellFile',
      offset: '0x201A50',
      absolute: '0x00601A50',
      signature: 'void __stdcall (CellFile* File)',
      calling_convention: '__stdcall'
    },

    // D2GAME Functions (1 total)
    {
      module: 'D2GAME',
      name: 'Rand',
      offset: '0x5C370',
      absolute: '0x0045C370',
      signature: 'DWORD __fastcall (DWORD* seed)',
      calling_convention: '__fastcall'
    }
  ],

  globals: [
    // D2CLIENT Globals
    {
      module: 'D2CLIENT',
      name: 'ScreenSizeX',
      offset: '0x31146C',
      absolute: '0x0071146C',
      type: 'DWORD'
    },
    {
      module: 'D2CLIENT',
      name: 'ScreenSizeY',
      offset: '0x311470',
      absolute: '0x00711470',
      type: 'DWORD'
    },
    {
      module: 'D2CLIENT',
      name: 'MouseX',
      offset: '0x3A6AB0',
      absolute: '0x007A6AB0',
      type: 'DWORD'
    },
    {
      module: 'D2CLIENT',
      name: 'MouseY',
      offset: '0x3A6AAC',
      absolute: '0x007A6AAC',
      type: 'DWORD'
    },
    {
      module: 'D2CLIENT',
      name: 'PlayerUnit',
      offset: '0x3A6A70',
      absolute: '0x007A6A70',
      type: 'UnitAny*'
    },
    {
      module: 'D2CLIENT',
      name: 'AutomapOn',
      offset: '0x3A27E8',
      absolute: '0x007A27E8',
      type: 'DWORD'
    },
    {
      module: 'D2CLIENT',
      name: 'GameInfo',
      offset: '0x3A0438',
      absolute: '0x007A0438',
      type: 'GameStructInfo*'
    },
    {
      module: 'D2CLIENT',
      name: 'Ping',
      offset: '0x3A04A4',
      absolute: '0x007A04A4',
      type: 'DWORD'
    },
    {
      module: 'D2CLIENT',
      name: 'FPS',
      offset: '0x3BB390',
      absolute: '0x007BB390',
      type: 'DWORD'
    },
    {
      module: 'D2CLIENT',
      name: 'ExpCharFlag',
      offset: '0x3A04F4',
      absolute: '0x007A04F4',
      type: 'DWORD'
    },

    // D2COMMON Globals
    {
      module: 'D2COMMON',
      name: 'sgptDataTable',
      offset: '0x344304',
      absolute: '0x00744304',
      type: 'DWORD'
    }
  ]
}

// Export for use in report viewer
if (typeof window !== 'undefined') {
  window.D2_KNOWN_FUNCTIONS = D2_KNOWN_FUNCTIONS
}
