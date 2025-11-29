# Task: Show changed/total file count in version panel

## Goal
Display file counts as "changed / total" in the leftmost version panel to show the scope of changes relative to total files.

## Analysis
- Current: Only shows `change_count` (files changed from previous version)
- Data available: `file_count` already exists in `VERSIONS_DATA` (total files per version)
- Format: "5 / 12" meaning 5 changed out of 12 total files

## Plan
- [x] Update `renderVersionList()` in HTML to display "change_count / file_count"
- [x] Test the display

## Files modified
- `reports/d2_report_viewer.html`
  - Lines 274-294: New `.file-counts` CSS class with styling for changed/separator/total
  - Lines 1072-1092: Updated `renderVersionList()` to show "changed / total" format

## Review
Simple change that adds total file count next to the change count in the version panel. Format is `5 / 12` where green number is files changed and gray number is total files. First versions (no prior version to compare) show `— / 12`. Tooltip also updated to show "X of Y files changed".

