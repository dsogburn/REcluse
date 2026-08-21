import tempfile
import unittest
from pathlib import Path

from containers.patch_ghidra_headless_mcp import AFTER, BEFORE, MARKER, patch_backend


class PatchGhidraHeadlessMcpTests(unittest.TestCase):
    def test_patch_is_targeted_and_idempotent(self):
        source = f"class Backend:\n    def analyze(self):\n{BEFORE}"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "backend.py"
            path.write_text(source, encoding="utf-8")

            self.assertTrue(patch_backend(path))
            patched = path.read_text(encoding="utf-8")
            self.assertIn(MARKER, patched)
            self.assertIn(AFTER, patched)
            self.assertIn('"WindowsResourceReference"', patched)
            self.assertNotIn(BEFORE, patched)
            self.assertFalse(patch_backend(path))

    def test_patch_fails_closed_when_upstream_anchor_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "backend.py"
            path.write_text("different upstream source", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "anchor"):
                patch_backend(path)


if __name__ == "__main__":
    unittest.main()
