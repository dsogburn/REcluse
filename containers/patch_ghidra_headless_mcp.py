"""Disable a Ghidra GUI-dependent analyzer in ghidra-headless-mcp.

Ghidra 12's Windows Resource Reference analyzer calls GhidraScriptUtil from a
PyGhidra/headless process where the GUI BundleHost is not initialized.  Patch
the MCP backend at image-build time so that this one analyzer is disabled after
analysis options are initialized and before analysis starts.
"""

from __future__ import annotations

import sys
from pathlib import Path


MARKER = "# REcluse: disable GUI-dependent Windows resource analyzer"
BEFORE = """\
            manager = AutoAnalysisManager.getAnalysisManager(program)
            manager.initializeOptions()
            manager.reAnalyzeAll(None)
"""
AFTER = """\
            manager = AutoAnalysisManager.getAnalysisManager(program)
            manager.initializeOptions()

            # REcluse: disable GUI-dependent Windows resource analyzer
            options = self._pyghidra.analysis_properties(program)
            resource_analyzer = "WindowsResourceReference"
            option_names = {str(name) for name in options.getOptionNames()}
            if resource_analyzer in option_names:
                options.setBoolean(resource_analyzer, False)

            manager.reAnalyzeAll(None)
"""


def patch_backend(path: Path) -> bool:
    source = path.read_text(encoding="utf-8")
    if MARKER in source:
        return False
    if source.count(BEFORE) != 1:
        raise RuntimeError(
            "Unsupported ghidra-headless-mcp backend: analysis initialization "
            "anchor was not found exactly once"
        )
    path.write_text(source.replace(BEFORE, AFTER), encoding="utf-8")
    return True


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: patch_ghidra_headless_mcp.py PATH_TO_BACKEND.PY", file=sys.stderr)
        return 2
    path = Path(sys.argv[1])
    changed = patch_backend(path)
    print(f"{'Patched' if changed else 'Already patched'} {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
