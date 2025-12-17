# CSV Function Rename Changelog

Applied 30 function renames from d2moo_known_functions.csv

## Summary by Module

### D2Common: 24 renames

- 1.10 0x6FDA6790: `MONSTERS_ApplyClassicScaling` -> `MONSTERS_ApplyClassicScaling`
- 1.10 0x6FDAC270: `PATH_ComputePathOrSlideAlongObstacles` -> `PATH_ComputePathOrSlideAlongObstacles`
- 1.10 0x6FDABAC0: `PATH_FindSubpathWithoutObstacles` -> `PATH_FindSubpathWithoutObstacles`
- 1.10 0x6FDAC170: `PATH_SimplifyToLines` -> `PATH_SimplifyToLines`
- 1.13c 0x6FD5DDC0: `D2Common_10231_Impl` -> `D2Common_10231_Impl`
- 1.13c 0x6FD51250: `DATATBLS_GetSkillsTxtRecord` -> `DATATBLS_GetSkillsTxtRecord`
- 1.13c 0x6FDA3780: `DATATBLS_NewTreasureClassEx` -> `DATATBLS_NewTreasureClassEx`
- 1.13c 0x6FDA4430: `DATATBLS_ParseTreasureClassItem` -> `DATATBLS_ParseTreasureClassItem`
- 1.13c 0x6FDCB220: `PATH_AStar_PopBestScoreForVisit` -> `PATH_AStar_PopBestScoreForVisit`
- 1.13c 0x6FDCB2C0: `PATH_AStar_TargetLocationHasEnoughRoom` -> `PATH_AStar_TargetLocationHasEnoughRoom`
- 1.13c 0x6FDC0650: `PATH_IDAStar_FlushNodeToDynamicPath` -> `PATH_IDAStar_FlushNodeToDynamicPath`
- 1.13c 0x6FDC0BB0: `PATH_IdaStar_ComputePathWithRooms` -> `PATH_IdaStar_ComputePathWithRooms`
- 1.13c 0x6FD85E00: `PATH_PreparePathTargetForPathUpdate` -> `PATH_PreparePathTargetForPathUpdate`
- 1.13c 0x6FD5DC80: `PATH_StopMovement` -> `PATH_StopMovement`
- 1.13c 0x6FD7FAC0: `UNITS_AnimModeAllowsAnimSpeed` -> `UNITS_AnimModeAllowsAnimSpeed`
- 1.13c 0x6FD80BD0: `UNITS_CanAnimModeUseVelocityModifier` -> `UNITS_CanAnimModeUseAttackRate`
- 1.13c 0x6FD80BD0: `UNITS_CanAnimModeUseAttackRate` -> `UNITS_CanAnimModeUseVelocityModifier`
- 1.13c 0x6FD7EF90: `UNITS_IsAnimModeBlocking` -> `UNITS_IsAnimModeBlocking`
- 1.13c 0x6FD7EFC0: `UNITS_IsAnimModeGetHit` -> `UNITS_IsAnimModeGetHit`
- 1.13c 0x6FD7F010: `UNITS_IsAnimModeKnockBack` -> `UNITS_IsAnimModeKnockBack`
- 1.13c 0x6FD80B80: `UNITS_IsSeqAnimSpeedModulatedByFCR` -> `UNITS_IsSeqAnimSpeedModulatedByFCR`
- 1.13c 0x6FD5CEB0: `sub_6FD5CEB0` -> `sub_6FD5CEB0`
- 1.13c 0x6FD5DB70: `sub_6FD5DB70` -> `sub_6FD5DB70`
- 1.13c 0x6FDC0840: `sub_6FDC0840` -> `sub_6FDC0840`

### D2Game: 5 renames

- 1.00 0x100056D0: `GAME_ReceiveDatabaseCharacter` -> `GAME_ReceiveDatabaseCharacter`
- 1.10 0x6FC34A80: `EVENT_FreeEventQueue` -> `EVENT_FreeEventQueue`
- 1.10 0x6FC36280: `GAME_ReceiveDatabaseCharacter` -> `GAME_ReceiveDatabaseCharacter`
- 1.13c 0x6FCAE540: `EVENT_AllocateTimer` -> `EVENT_AllocateTimer`
- 1.13c 0x6FC89B00: `OBJMODE_GetToHitPercentage` -> `OBJMODE_GetToHitPercentage`

### D2Win: 1 renames

- 1.10 0x6F8AFDC0: `D2Win_10043_TEXTBOX_Destroy` -> `D2Win_10043_TEXTBOX_Destroy`

## Renames by Version

### 1.00: 1 renames

- D2Game: `GAME_ReceiveDatabaseCharacter` -> `GAME_ReceiveDatabaseCharacter`

### 1.10: 7 renames

- D2Win: `D2Win_10043_TEXTBOX_Destroy` -> `D2Win_10043_TEXTBOX_Destroy`
- D2Game: `EVENT_FreeEventQueue` -> `EVENT_FreeEventQueue`
- D2Game: `GAME_ReceiveDatabaseCharacter` -> `GAME_ReceiveDatabaseCharacter`
- D2Common: `MONSTERS_ApplyClassicScaling` -> `MONSTERS_ApplyClassicScaling`
- D2Common: `PATH_ComputePathOrSlideAlongObstacles` -> `PATH_ComputePathOrSlideAlongObstacles`
- D2Common: `PATH_FindSubpathWithoutObstacles` -> `PATH_FindSubpathWithoutObstacles`
- D2Common: `PATH_SimplifyToLines` -> `PATH_SimplifyToLines`

### 1.13c: 22 renames

- D2Common: `D2Common_10231_Impl` -> `D2Common_10231_Impl`
- D2Common: `DATATBLS_GetSkillsTxtRecord` -> `DATATBLS_GetSkillsTxtRecord`
- D2Common: `DATATBLS_NewTreasureClassEx` -> `DATATBLS_NewTreasureClassEx`
- D2Common: `DATATBLS_ParseTreasureClassItem` -> `DATATBLS_ParseTreasureClassItem`
- D2Game: `EVENT_AllocateTimer` -> `EVENT_AllocateTimer`
- D2Game: `OBJMODE_GetToHitPercentage` -> `OBJMODE_GetToHitPercentage`
- D2Common: `PATH_AStar_PopBestScoreForVisit` -> `PATH_AStar_PopBestScoreForVisit`
- D2Common: `PATH_AStar_TargetLocationHasEnoughRoom` -> `PATH_AStar_TargetLocationHasEnoughRoom`
- D2Common: `PATH_IDAStar_FlushNodeToDynamicPath` -> `PATH_IDAStar_FlushNodeToDynamicPath`
- D2Common: `PATH_IdaStar_ComputePathWithRooms` -> `PATH_IdaStar_ComputePathWithRooms`
- D2Common: `PATH_PreparePathTargetForPathUpdate` -> `PATH_PreparePathTargetForPathUpdate`
- D2Common: `PATH_StopMovement` -> `PATH_StopMovement`
- D2Common: `UNITS_AnimModeAllowsAnimSpeed` -> `UNITS_AnimModeAllowsAnimSpeed`
- D2Common: `UNITS_CanAnimModeUseVelocityModifier` -> `UNITS_CanAnimModeUseAttackRate`
- D2Common: `UNITS_CanAnimModeUseAttackRate` -> `UNITS_CanAnimModeUseVelocityModifier`
- D2Common: `UNITS_IsAnimModeBlocking` -> `UNITS_IsAnimModeBlocking`
- D2Common: `UNITS_IsAnimModeGetHit` -> `UNITS_IsAnimModeGetHit`
- D2Common: `UNITS_IsAnimModeKnockBack` -> `UNITS_IsAnimModeKnockBack`
- D2Common: `UNITS_IsSeqAnimSpeedModulatedByFCR` -> `UNITS_IsSeqAnimSpeedModulatedByFCR`
- D2Common: `sub_6FD5CEB0` -> `sub_6FD5CEB0`
- D2Common: `sub_6FD5DB70` -> `sub_6FD5DB70`
- D2Common: `sub_6FDC0840` -> `sub_6FDC0840`
