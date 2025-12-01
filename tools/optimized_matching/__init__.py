"""
Optimized Function Matching Pipeline

A fast, modular approach to matching functions across Diablo 2 versions.
Uses Python-native analysis instead of slow Ghidra MCP calls.

Modules:
    - progress: Progress reporting utilities
    - analysis_engine: Per-version binary analysis
    - matching_engine: Tiered function matching
    - name_propagator: Ghidra name application
    - pipeline_runner: CLI interface
"""

__version__ = "1.0.0"
