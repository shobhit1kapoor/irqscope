import json
from pathlib import Path
import tempfile
import unittest
import zipfile

from tools.package_release import build_archive


class ReleasePackagingTests(unittest.TestCase):
    def test_archive_is_reproducible_and_fills_metadata_without_mutating_source(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temporary:
            first = Path(temporary) / "one.zip"
            second = Path(temporary) / "two.zip"
            first_hash = build_archive(root, first, "Example Author", "author@example.org",
                                      "https://github.com/example/irqscope")
            second_hash = build_archive(root, second, "Example Author", "author@example.org",
                                       "https://github.com/example/irqscope")

            self.assertEqual(first_hash, second_hash)
            with zipfile.ZipFile(first) as archive:
                manifest = json.loads(archive.read("ida-plugin.json"))
                self.assertEqual(manifest["plugin"]["authors"], [
                    {"name": "Example Author", "email": "author@example.org"}
                ])
                self.assertEqual(manifest["plugin"]["urls"]["repository"],
                                 "https://github.com/example/irqscope")
                self.assertEqual(manifest["plugin"]["idaVersions"], ["9.5"])
                self.assertIn(manifest["plugin"]["logoPath"], archive.namelist())
                self.assertIn("irqscope/protocols.py", archive.namelist())
                self.assertIn("demo/uart-protocol.json", archive.namelist())
                self.assertIn("CHANGELOG.md", archive.namelist())
                self.assertIn("assets/irqscope-logo.svg", archive.namelist())
                self.assertIn("tools/build_demo.py", archive.namelist())
                self.assertFalse(any("__pycache__" in name for name in archive.namelist()))

        source_manifest = json.loads((root / "ida-plugin.json").read_text(encoding="utf-8"))
        self.assertEqual(source_manifest["plugin"]["authors"][0], {
            "name": "shobhit kapoor", "email": "shobhit1kapoor@gmail.com"
        })

    def test_archive_rejects_placeholder_metadata(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError, "actual author"):
                build_archive(Path(__file__).resolve().parents[1], Path(temporary) / "bad.zip",
                              "AUTHOR", "author@example.org", "https://github.com/OWNER/irqscope")

    def test_archive_rejects_missing_or_invalid_author_email(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError, "author email"):
                build_archive(root, Path(temporary) / "bad.zip", "Example Author", "not-an-email",
                              "https://github.com/example/irqscope")


if __name__ == "__main__":
    unittest.main()
