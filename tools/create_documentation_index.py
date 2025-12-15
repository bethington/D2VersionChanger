#!/usr/bin/env python3
"""
Create comprehensive project documentation index.
Generates organized navigation and reference for all project artifacts.
"""

import json
from pathlib import Path
from typing import Dict, List
from datetime import datetime

REPORTS_PATH = Path("reports")
TOOLS_PATH = Path("tools")

# Documentation structure
DOCUMENTATION_STRUCTURE = {
    "overview": {
        "title": "Project Overview",
        "description": "High-level project information and status",
        "files": [
            {"name": "README.md", "description": "Main project documentation (if exists)"},
        ]
    },
    "phase_summaries": {
        "title": "Phase Summaries",
        "description": "Complete documentation of each project phase",
        "files": [
            {"name": "PHASE_2_3_FINAL_SUMMARY.md", "phase": 2, "description": "Phases 2-3: Cross-version analysis foundation"},
            {"name": "PHASE_4_COMPLETE.md", "phase": 4, "description": "Phase 4: Function renaming campaign and Ghidra scripts"},
            {"name": "PHASE_5_COMPLETE.md", "phase": 5, "description": "Phase 5: API definition and module profiles"},
        ]
    },
    "api_documentation": {
        "title": "API Reference Documentation",
        "description": "Formal API specifications by module",
        "files": [
            {"name": "API_D2Game.md", "module": "D2Game", "description": "D2Game module API reference"},
            {"name": "API_D2Client.md", "module": "D2Client", "description": "D2Client module API reference"},
            {"name": "API_D2Common.md", "module": "D2Common", "description": "D2Common utilities API reference"},
            {"name": "API_D2Win.md", "module": "D2Win", "description": "D2Win window management API"},
            {"name": "API_Storm.md", "module": "Storm", "description": "Storm engine core API"},
            {"name": "API_Fog.md", "module": "Fog", "description": "Fog graphics rendering API"},
        ]
    },
    "module_profiles": {
        "title": "Module Profiles",
        "description": "Detailed module characterization and analysis",
        "files": [
            {"name": "MODULE_PROFILE_D2Game.md", "module": "D2Game", "description": "D2Game architecture and dependencies"},
            {"name": "MODULE_PROFILE_D2Client.md", "module": "D2Client", "description": "D2Client architecture and dependencies"},
            {"name": "MODULE_PROFILE_D2Common.md", "module": "D2Common", "description": "D2Common architecture and dependencies"},
            {"name": "MODULE_PROFILE_D2Win.md", "module": "D2Win", "description": "D2Win architecture and dependencies"},
            {"name": "MODULE_PROFILE_Storm.md", "module": "Storm", "description": "Storm architecture and dependencies"},
            {"name": "MODULE_PROFILE_Fog.md", "module": "Fog", "description": "Fog architecture and dependencies"},
        ]
    },
    "methodology_guides": {
        "title": "Methodology & Analysis Guides",
        "description": "Documentation of analysis techniques and methodologies",
        "files": [
            {"name": "FUNCTION_SIGNATURE_GUIDE.md", "description": "Function signature analysis methodology"},
            {"name": "CALLING_CONVENTION_GUIDE.md", "description": "Calling convention inference methodology"},
            {"name": "VERSION_SPECIFIC_VARIATIONS.md", "description": "Version variation patterns and analysis"},
            {"name": "1_10_CROSS_VERSION_INDEX.md", "description": "1.10 cross-version mapping documentation"},
        ]
    },
    "data_files": {
        "title": "Data Files & Reports",
        "description": "JSON data files with structured information",
        "files": [
            {"name": "unified_function_index.json", "size": "66,864 functions", "description": "Master function index across all versions"},
            {"name": "all_version_functions_analysis.json", "size": "572 functions", "description": "All-version function analysis"},
            {"name": "renaming_priority_tiers.json", "description": "Function priority categorization"},
            {"name": "module_renaming_strategies.json", "description": "Per-module renaming strategies"},
            {"name": "function_signature_analysis.json", "description": "Function signature data"},
            {"name": "calling_convention_analysis.json", "description": "Calling convention analysis data"},
            {"name": "api_reference_summary.json", "description": "Complete API reference data"},
            {"name": "module_api_profiles.json", "description": "Module profile data"},
            {"name": "version_profiles.json", "description": "Per-version statistics"},
            {"name": "version_comparisons.json", "description": "Version transition analysis"},
            {"name": "version_timeline.json", "description": "Version release timeline"},
            {"name": "ghidra_scripts_generated.json", "description": "Ghidra script generation report"},
        ]
    },
    "tools": {
        "title": "Analysis Tools",
        "description": "Python tools for analysis and generation",
        "files": [
            {"name": "tools/analyze_all_version_functions.py", "phase": 4, "description": "Analyze all-version functions"},
            {"name": "tools/generate_ghidra_rename_scripts.py", "phase": 4, "description": "Generate 66 Ghidra rename scripts"},
            {"name": "tools/analyze_function_signatures.py", "phase": 4, "description": "Analyze function signatures and types"},
            {"name": "tools/create_version_documentation_indexes.py", "phase": 4, "description": "Create version-specific indexes"},
            {"name": "tools/extract_calling_conventions.py", "phase": 5, "description": "Extract calling conventions"},
            {"name": "tools/build_api_reference.py", "phase": 5, "description": "Build formal API reference"},
            {"name": "tools/create_module_api_profiles.py", "phase": 5, "description": "Create module API profiles"},
        ]
    },
    "ghidra_scripts": {
        "title": "Ghidra Scripts",
        "description": "Automated scripts for Ghidra deployment",
        "files": [
            {"name": "ghidra_scripts/D2VersionChanger_MasterRename.java", "description": "Master script with usage instructions"},
            {"note": "66 additional rename scripts (11 per module x 6 modules)", "total": 66, "description": "Module/version-specific rename scripts"},
        ]
    },
}


def create_documentation_index() -> Dict:
    """Create comprehensive documentation index."""
    index = {
        "title": "D2VersionChanger - Complete Documentation Index",
        "generated": datetime.now().isoformat(),
        "project_status": "Phase 5 Complete - Ready for Phase 6",
        "sections": {},
        "quick_links": {},
        "statistics": {
            "total_documents": 0,
            "total_data_files": 0,
            "total_tools": 0,
            "total_ghidra_scripts": 0,
        }
    }

    # Process each section
    for section_key, section_data in DOCUMENTATION_STRUCTURE.items():
        section_info = {
            "title": section_data["title"],
            "description": section_data["description"],
            "files": section_data.get("files", []),
            "file_count": len(section_data.get("files", [])),
        }

        index["sections"][section_key] = section_info

        # Count files
        if section_key == "data_files":
            index["statistics"]["total_data_files"] += section_info["file_count"]
        elif section_key == "tools":
            index["statistics"]["total_tools"] += section_info["file_count"]
        elif section_key == "ghidra_scripts":
            index["statistics"]["total_ghidra_scripts"] = 67  # 66 + master
        else:
            index["statistics"]["total_documents"] += section_info["file_count"]

    # Create quick links for common documents
    index["quick_links"] = {
        "latest_phase": "PHASE_5_COMPLETE.md",
        "api_overview": "api_reference_summary.json",
        "module_overview": "module_api_profiles.json",
        "version_history": "version_timeline.json",
        "getting_started": "PHASE_5_COMPLETE.md",
    }

    return index


def generate_index_markdown(index: Dict) -> str:
    """Generate Markdown index documentation."""
    md = f"""# D2VersionChanger - Complete Documentation Index

**Generated:** {index['generated']}

**Project Status:** {index['project_status']}

---

## Quick Links

- **Latest Phase:** [Phase 5 Complete Summary](reports/PHASE_5_COMPLETE.md)
- **API Reference:** [API Reference Summary](reports/api_reference_summary.json)
- **Module Profiles:** [Module API Profiles](reports/module_api_profiles.json)
- **Version History:** [Version Timeline](reports/version_timeline.json)
- **Getting Started:** [Phase 5 Summary](reports/PHASE_5_COMPLETE.md)

---

## Documentation Organization

"""

    for section_key, section_data in index["sections"].items():
        md += f"### {section_data['title']}\n\n"
        md += f"{section_data['description']}\n\n"

        if section_data["files"]:
            for file_info in section_data["files"]:
                if "note" in file_info:
                    md += f"- **Note:** {file_info['note']} ({file_info.get('total', '')} files)\n"
                else:
                    filename = file_info.get("name", "Unknown")
                    description = file_info.get("description", "")
                    md += f"- **[{filename}](reports/{filename})** - {description}\n"

        md += "\n"

    md += """---

## Document Statistics

| Category | Count |
|----------|-------|
| Phase Summaries | 3 |
| API References | 6 |
| Module Profiles | 6 |
| Methodology Guides | 4 |
| Data Files | 12 |
| Analysis Tools | 7 |
| Ghidra Scripts | 67 |
| **TOTAL** | **105** |

---

## Navigation by Purpose

### I want to understand the project...
1. Start with [PHASE_5_COMPLETE.md](reports/PHASE_5_COMPLETE.md)
2. Read [PHASE_4_COMPLETE.md](reports/PHASE_4_COMPLETE.md)
3. Review [PHASE_2_3_FINAL_SUMMARY.md](reports/PHASE_2_3_FINAL_SUMMARY.md)

### I want to look up a function's API...
1. Find your module in [API Documentation](#api-documentation)
2. Search for function name in the appropriate API reference
3. Check [Module Profile](reports/module_api_profiles.json) for additional context

### I want to understand module architecture...
1. Read the appropriate [Module Profile](#module-profiles)
2. Check dependencies and interface tiers
3. Reference the [API Documentation](#api-documentation) for function details

### I want to validate functions...
1. Read [FUNCTION_SIGNATURE_GUIDE.md](reports/FUNCTION_SIGNATURE_GUIDE.md)
2. Read [CALLING_CONVENTION_GUIDE.md](reports/CALLING_CONVENTION_GUIDE.md)
3. Use high-confidence functions from Module Profiles first

### I want to deploy Ghidra scripts...
1. Copy scripts from `ghidra_scripts/` directory
2. Read [D2VersionChanger_MasterRename.java](ghidra_scripts/D2VersionChanger_MasterRename.java)
3. Run appropriate script in Ghidra Script Manager

### I want to understand version differences...
1. Read [VERSION_SPECIFIC_VARIATIONS.md](reports/VERSION_SPECIFIC_VARIATIONS.md)
2. Review [version_comparisons.json](reports/version_comparisons.json)
3. Check [version_timeline.json](reports/version_timeline.json)

---

## Data Files Reference

### Core Data
- **unified_function_index.json** - Master index (66,864 functions across 11 versions)
- **all_version_functions_analysis.json** - Analysis of 572 all-version functions

### API Documentation
- **api_reference_summary.json** - Complete API signatures
- **module_api_profiles.json** - Module architecture and tiers
- **calling_convention_analysis.json** - Calling convention data
- **function_signature_analysis.json** - Signature data

### Analysis & Strategy
- **renaming_priority_tiers.json** - Function priority levels
- **module_renaming_strategies.json** - Per-module strategies
- **version_profiles.json** - Per-version function statistics
- **version_comparisons.json** - Version transition analysis
- **version_timeline.json** - Release history

### Ghidra Integration
- **ghidra_scripts_generated.json** - Script generation report

---

## Tools Usage

### Phase 4 Tools (Function Analysis)
```bash
# Analyze all-version functions
python tools/analyze_all_version_functions.py

# Generate Ghidra scripts
python tools/generate_ghidra_rename_scripts.py

# Analyze function signatures
python tools/analyze_function_signatures.py

# Create version documentation
python tools/create_version_documentation_indexes.py
```

### Phase 5 Tools (API Definition)
```bash
# Extract calling conventions
python tools/extract_calling_conventions.py

# Build API reference
python tools/build_api_reference.py

# Create module profiles
python tools/create_module_api_profiles.py
```

---

## Project Statistics

- **Total Functions Analyzed:** 66,864 (across all versions and modules)
- **All-Version Functions:** 572 (present in all 11 versions)
- **Functions Documented:** 572 (100% of all-version functions)
- **Ghidra Scripts Generated:** 66 (+ 1 master = 67 total)
- **Rename Statements:** 6,292
- **Modules Analyzed:** 6 (D2Game, D2Client, D2Common, D2Win, Storm, Fog)
- **Versions Covered:** 11 (1.07 through 1.13d)
- **Documentation Files:** 31 (guides, references, profiles)
- **Data Files:** 12 (JSON reports with structured data)

---

## Key Metrics

### API Coverage
- **Public API Functions:** 103 (18.0%) - High confidence
- **Internal API Functions:** 469 (82.0%) - Medium confidence
- **Average Confidence:** 77.08%

### Module Distribution
| Module | Functions | % |
|--------|-----------|---|
| D2Client | 225 | 39.3% |
| D2Common | 93 | 16.3% |
| D2Game | 84 | 14.7% |
| Fog | 60 | 10.5% |
| D2Win | 58 | 10.1% |
| Storm | 52 | 9.1% |

### Function Categories
| Category | Functions | % |
|----------|-----------|---|
| Utility | 230 | 40.2% |
| Bit Operations | 95 | 16.6% |
| Game Logic | 50 | 8.7% |
| String Operations | 48 | 8.4% |
| Memory Management | 44 | 7.7% |
| Others | 105 | 18.4% |

---

## Getting Started

### For Researchers
1. Read [PHASE_5_COMPLETE.md](reports/PHASE_5_COMPLETE.md)
2. Explore API references for your module of interest
3. Review Module Profiles for architecture understanding

### For Developers
1. Start with [Getting Started Guide](reports/PHASE_5_COMPLETE.md)
2. Use Ghidra scripts for function renaming
3. Reference API documentation for integration

### For Maintainers
1. Review all Phase summaries for project history
2. Use data files for programmatic access
3. Run tools to update documentation

---

## Version Information

- **Project:** D2VersionChanger
- **Last Updated:** 2025-12-13
- **Phase:** 5 (Complete)
- **Status:** Ready for Phase 6

---

## Support & References

- All documentation is in Markdown format for easy reading
- Data files are in JSON format for programmatic access
- Ghidra scripts are Java-based and deploy to Ghidra Script Manager
- Python tools are self-documenting with --help support

For detailed information on any topic, refer to the specific documentation files listed above.

"""

    return md


def main():
    """Main execution."""
    print("=" * 70)
    print("Creating Comprehensive Documentation Index")
    print("=" * 70)

    # Create index
    print("\nGenerating documentation index...")
    index = create_documentation_index()

    # Save JSON index
    index_file = REPORTS_PATH / "DOCUMENTATION_INDEX.json"
    with open(index_file, 'w', encoding='utf-8') as f:
        json.dump(index, f, indent=2)
    print(f"Saved index to {index_file}")

    # Generate Markdown index
    md_content = generate_index_markdown(index)
    md_file = REPORTS_PATH / "DOCUMENTATION_INDEX.md"
    with open(md_file, 'w', encoding='utf-8') as f:
        f.write(md_content)
    print(f"Saved Markdown index to {md_file}")

    # Print summary
    print("\n" + "=" * 70)
    print("DOCUMENTATION INDEX SUMMARY")
    print("=" * 70)

    print(f"\nTotal Documentation Files: {index['statistics']['total_documents']}")
    print(f"Total Data Files: {index['statistics']['total_data_files']}")
    print(f"Total Tools: {index['statistics']['total_tools']}")
    print(f"Total Ghidra Scripts: {index['statistics']['total_ghidra_scripts']}")

    print("\nSections Created:")
    print("-" * 70)
    for section_key, section_data in index["sections"].items():
        print(f"  {section_data['title']}: {section_data['file_count']} files")

    print("\n" + "=" * 70)
    print("DOCUMENTATION INDEX COMPLETE")
    print("=" * 70)
    print(f"\nGenerated {len(index['sections'])} documentation sections")
    print(f"Total indexed items: {sum(s['file_count'] for s in index['sections'].values())} items")


if __name__ == "__main__":
    main()
