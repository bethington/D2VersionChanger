# Task: Rework Right Panel with File-Type Specific Views

## Goal
Create different views for different file types in the right panel:
1. **DLLs/EXEs**: Show export table with function ordinals/names and addresses across versions
2. **TXT files**: Show read-only text content
3. **HTML files**: Render HTML content
4. **MPQ files**: Placeholder for now
5. **Other files**: Generic placeholder

## DLL Export Table View Design
- Sticky first column (Function Name/Ordinal)
- Sticky header row (Version numbers: 1.00, 1.01, etc.)
- Horizontal scrolling for versions
- Vertical scrolling for functions
- Auto-scroll to selected version column
- Columns: Function Name | 1.00 | 1.01 | ... | 1.14d (addresses in each)

## Plan

### Phase 1: Extract Export Data
- [x] Add `extract_pe_exports()` function to d2_hash_tool.py
- [ ] Update gen_viewer_data.py to collect exports across all versions
- [ ] Create EXPORTS_DATA structure: { filename: { function_name: { version: address } } }

### Phase 2: Build UI
- [ ] Redesign right panel HTML structure for file-type views
- [ ] Add CSS for sticky headers (both row and column)
- [ ] Add DLL export table view
- [ ] Add TXT file view
- [ ] Add HTML file view
- [ ] Add MPQ placeholder
- [ ] Add generic placeholder

### Phase 3: Wire Up
- [ ] Detect file type when file selected
- [ ] Render appropriate view
- [ ] Auto-scroll to selected version column

## Files to modify
- `tools/d2_hash_tool.py` - Add export extraction
- `tools/gen_viewer_data.py` - Generate EXPORTS_DATA
- `reports/d2_report_viewer.html` - New right panel views
