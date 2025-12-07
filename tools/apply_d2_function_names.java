// Ghidra script to apply D2 function names from modding community
// Source: d2bs project (blizzhackers/d2bs)
// Version: 1.14d

import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.listing.Function;

public class ApplyD2FunctionNames extends GhidraScript {
    @Override
    public void run() throws Exception {
        FunctionManager fm = currentProgram.getFunctionManager();

        renameFunction(fm, toAddr(0x004B32D0), "D2CLIENT_GetQuestInfo");
        renameFunction(fm, toAddr(0x004B2370), "D2CLIENT_SubmitItem");
        renameFunction(fm, toAddr(0x0048A0D0), "D2CLIENT_Transmute");
        renameFunction(fm, toAddr(0x00463990), "D2CLIENT_FindClientSideUnit");
        renameFunction(fm, toAddr(0x004639B0), "D2CLIENT_FindServerSideUnit");
        renameFunction(fm, toAddr(0x004B1620), "D2CLIENT_GetCurrentInteractingNPC");
        renameFunction(fm, toAddr(0x00467A10), "D2CLIENT_GetSelectedUnit");
        renameFunction(fm, toAddr(0x004680A0), "D2CLIENT_GetCursorItem");
        renameFunction(fm, toAddr(0x00466DE0), "D2CLIENT_SetSelectedUnit_I");
        renameFunction(fm, toAddr(0x0048C060), "D2CLIENT_GetItemName");
        renameFunction(fm, toAddr(0x0048DD90), "D2CLIENT_LoadItemDesc");
        renameFunction(fm, toAddr(0x00479150), "D2CLIENT_GetMonsterOwner");
        renameFunction(fm, toAddr(0x00479080), "D2CLIENT_GetUnitHPPercent");
        renameFunction(fm, toAddr(0x004845A0), "D2CLIENT_InitInventory");
        renameFunction(fm, toAddr(0x00455F20), "D2CLIENT_SetUIVar");
        renameFunction(fm, toAddr(0x0045ADF0), "D2CLIENT_GetUnitX");
        renameFunction(fm, toAddr(0x0045AE20), "D2CLIENT_GetUnitY");
        renameFunction(fm, toAddr(0x004B3870), "D2CLIENT_ShopAction");
        renameFunction(fm, toAddr(0x004B3F10), "D2CLIENT_CloseNPCInteract");
        renameFunction(fm, toAddr(0x0044C6B0), "D2CLIENT_CloseInteract");
        renameFunction(fm, toAddr(0x0045A710), "D2CLIENT_GetAutomapSize");
        renameFunction(fm, toAddr(0x00457C30), "D2CLIENT_NewAutomapCell");
        renameFunction(fm, toAddr(0x00457B00), "D2CLIENT_AddAutomapCell");
        renameFunction(fm, toAddr(0x00458F40), "D2CLIENT_RevealAutomapRoom");
        renameFunction(fm, toAddr(0x00458D40), "D2CLIENT_InitAutomapLayer_I");
        renameFunction(fm, toAddr(0x00462D00), "D2CLIENT_ClickMap");
        renameFunction(fm, toAddr(0x0048FFE0), "D2CLIENT_LeftClickItem_I");
        renameFunction(fm, toAddr(0x0045AFC0), "D2CLIENT_GetMouseXOffset");
        renameFunction(fm, toAddr(0x0045AFB0), "D2CLIENT_GetMouseYOffset");
        renameFunction(fm, toAddr(0x0049E3A0), "D2CLIENT_PrintGameString");
        renameFunction(fm, toAddr(0x0049E5C0), "D2CLIENT_PrintPartyString");
        renameFunction(fm, toAddr(0x00479FC0), "D2CLIENT_LeaveParty");
        renameFunction(fm, toAddr(0x004B9070), "D2CLIENT_AcceptTrade");
        renameFunction(fm, toAddr(0x004B90B0), "D2CLIENT_CancelTrade");
        renameFunction(fm, toAddr(0x004B8A30), "D2CLIENT_TradeOK");
        renameFunction(fm, toAddr(0x0044DCD0), "D2CLIENT_GetDifficulty");
        renameFunction(fm, toAddr(0x0044DD60), "D2CLIENT_ExitGame");
        renameFunction(fm, toAddr(0x004538D0), "D2CLIENT_GetUiVar_I");
        renameFunction(fm, toAddr(0x00452E50), "D2CLIENT_DrawRectFrame");
        renameFunction(fm, toAddr(0x00454080), "D2CLIENT_PerformGoldDialogAction");
        renameFunction(fm, toAddr(0x00463DD0), "D2CLIENT_GetPlayerUnit");
        renameFunction(fm, toAddr(0x004B4620), "D2CLIENT_ClearScreen");
        renameFunction(fm, toAddr(0x004A17D0), "D2CLIENT_CloseNPCTalk");
        renameFunction(fm, toAddr(0x004DC440), "D2CLIENT_TestPvpFlag");
        renameFunction(fm, toAddr(0x00525150), "D2CLIENT_GetGameLanguageCode");
        renameFunction(fm, toAddr(0x006424A0), "D2COMMON_InitLevel");
        renameFunction(fm, toAddr(0x0061AFD3), "D2COMMON_UnloadAct");
        renameFunction(fm, toAddr(0x00640E90), "D2COMMON_GetObjectTxt");
        renameFunction(fm, toAddr(0x006194A0), "D2COMMON_LoadAct");
        renameFunction(fm, toAddr(0x0061DB70), "D2COMMON_GetLevelText");
        renameFunction(fm, toAddr(0x006335F0), "D2COMMON_GetItemText");
        renameFunction(fm, toAddr(0x0061E470), "D2COMMON_GetLayer");
        renameFunction(fm, toAddr(0x00642AE0), "D2COMMON_GetLevel");
        renameFunction(fm, toAddr(0x006257D0), "D2COMMON_GetStatList");
        renameFunction(fm, toAddr(0x00625C90), "D2COMMON_CopyStatList");
        renameFunction(fm, toAddr(0x00625480), "D2COMMON_GetUnitStat");
        renameFunction(fm, toAddr(0x00639DF0), "D2COMMON_GetUnitState");
        renameFunction(fm, toAddr(0x00622AA0), "D2COMMON_CheckUnitCollision");
        renameFunction(fm, toAddr(0x00620BB0), "D2COMMON_GetRoomFromUnit");
        renameFunction(fm, toAddr(0x006442A0), "D2COMMON_GetSkillLevel");
        renameFunction(fm, toAddr(0x0062BA60), "D2COMMON_GetItemLevelRequirement");
        renameFunction(fm, toAddr(0x0062FDC0), "D2COMMON_GetItemPrice");
        renameFunction(fm, toAddr(0x0062FE60), "D2COMMON_GetRepairCost");
        renameFunction(fm, toAddr(0x00633EE0), "D2COMMON_GetItemMagicalMods");
        renameFunction(fm, toAddr(0x0063B2C0), "D2COMMON_GetItemFromInventory");
        renameFunction(fm, toAddr(0x0063DFA0), "D2COMMON_GetNextItemFromInventory");
        renameFunction(fm, toAddr(0x00661110), "D2COMMON_GenerateOverheadMsg");
        renameFunction(fm, toAddr(0x00661230), "D2COMMON_FixOverheadMsg");
        renameFunction(fm, toAddr(0x0061A070), "D2COMMON_AddRoomData");
        renameFunction(fm, toAddr(0x0061A0C0), "D2COMMON_RemoveRoomData");
        renameFunction(fm, toAddr(0x0065C310), "D2COMMON_GetQuestFlag");
        renameFunction(fm, toAddr(0x00643260), "D2COMMON_MapToAbsScreen");
        renameFunction(fm, toAddr(0x00643510), "D2COMMON_AbsScreenToMap");
        renameFunction(fm, toAddr(0x00660E50), "D2COMMON_CheckWaypoint");
        renameFunction(fm, toAddr(0x0061AAF0), "D2COMMON_IsTownByLevelNo");
        renameFunction(fm, toAddr(0x0061A1B0), "D2COMMON_GetLevelNoFromRoom");
        renameFunction(fm, toAddr(0x00619DA3), "D2COMMON_FindRoom1");
        renameFunction(fm, toAddr(0x0062C100), "D2COMMON_GetItemPalette");
        renameFunction(fm, toAddr(0x004639D0), "D2COMMON_GetMissileOwnerUnit");
        renameFunction(fm, toAddr(0x0052AE50), "D2NET_SendPacket");
        renameFunction(fm, toAddr(0x0052AEB0), "D2NET_ReceivePacket");
        renameFunction(fm, toAddr(0x0052B920), "D2NET_ReceivePacket_I");
        renameFunction(fm, toAddr(0x004F6300), "D2GFX_DrawRectangle");
        renameFunction(fm, toAddr(0x004F6380), "D2GFX_DrawLine");
        renameFunction(fm, toAddr(0x004F6480), "D2GFX_DrawAutomapCell2");
        renameFunction(fm, toAddr(0x004F59A0), "D2GFX_GetHwnd");
        renameFunction(fm, toAddr(0x004F5160), "D2GFX_GetScreenSize");
        renameFunction(fm, toAddr(0x00442810), "D2MULTI_DoChat");
        renameFunction(fm, toAddr(0x00447AB0), "D2MULTI_PrintChannelText_");
        renameFunction(fm, toAddr(0x00601340), "D2CMP_InitCellFile");
        renameFunction(fm, toAddr(0x00601A50), "D2CMP_DeleteCellFile");
        renameFunction(fm, toAddr(0x00524A30), "D2LANG_GetLocaleText");
        renameFunction(fm, toAddr(0x004FF5A0), "D2WIN_SetControlText");
        renameFunction(fm, toAddr(0x004F9870), "D2WIN_DrawSprites");
        renameFunction(fm, toAddr(0x004FA9B0), "D2WIN_LoadCellFile");
        renameFunction(fm, toAddr(0x004FA7A0), "D2WIN_TakeScreenshot");
        renameFunction(fm, toAddr(0x00502320), "D2WIN_DrawText");
        renameFunction(fm, toAddr(0x00502520), "D2WIN_GetTextSize");
        renameFunction(fm, toAddr(0x00502EF0), "D2WIN_SetTextSize");
        renameFunction(fm, toAddr(0x004FDAA0), "D2WIN_DestroyEditBox");
        renameFunction(fm, toAddr(0x004F95C0), "D2WIN_DestroyControl");
        renameFunction(fm, toAddr(0x004FDAD0), "D2WIN_SetEditBoxCallback");
        renameFunction(fm, toAddr(0x004FDD00), "D2WIN_SelectEditBoxText");
        renameFunction(fm, toAddr(0x00517332), "D2WIN_InitMPQ");
        renameFunction(fm, toAddr(0x0045C370), "D2GAME_Rand");
    }

    private void renameFunction(FunctionManager fm, Address addr, String name) {
        Function func = fm.getFunctionAt(addr);
        if (func != null) {
            try {
                func.setName(name, SourceType.USER_DEFINED);
                println("Renamed function at " + addr + " to " + name);
            } catch (Exception e) {
                println("Failed to rename function at " + addr + ": " + e.getMessage());
            }
        } else {
            println("No function found at " + addr);
        }
    }
}