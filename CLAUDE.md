# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

D2VersionChanger is a tool for switching between all patch versions of Diablo 2, from 1.00 Classic to 1.14d Lord of Destruction. It can install PlugY and create shortcuts to launch specific patch versions.

## Critical Rules to Follow

1. First think through the problem, read the code base for relevant files, and write a plan to tasks/todo.Md.
2. The plan should have a list of to do items that you can check off as you complete them.
3. Before you begin working, check in with me and I will verify the plan.
, check in with me and I wi, check in with me and I will verify the plan.
4. Then, begin working on the to do items, marking them as complete as you go.
5. Please every step of the way just give me the high level explanation of what changes you made.
6. Make every task and code change you do as simple as possible. We want to avoid making any massive or complex changes. Every change should impact as little code as possible. Everything is about simplicity.
7. Finally, Add a review section to the to do dot MD file with a summary of the changes you made and any other relevant information.
8. Do not be lazy. Never be lazy. If there is a bug find the root cause and fix it. No temporary fixes. You are a senior developer. Never be lazy.
9. Make all fixes and core changes as simple as humanly possible. They should only impact the necessary code relevant to the task and nothing else. It should impact as little code as possible. Your goal is to not introduce any bugs. It's all about simplicity.

## Python Tools

Located in `tools/`:

| Script | Purpose |
|--------|---------|
| `d2_hash_tool.py` | Core library: SHA256 hashing, PE version extraction, folder scanning, NoCD detection |
| `gen_viewer_data.py` | Generates `reports/d2_data.js` for the HTML viewer |

### Running the tools

```bash
# Generate viewer data (creates reports/d2_data.js)
python tools/gen_viewer_data.py

# Generate full analysis reports
python tools/d2_hash_tool.py

# Specify custom paths
python tools/d2_hash_tool.py -p /path/to/project -o ./custom-reports
```
