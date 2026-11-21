from pathlib import Path
import struct
import tempfile
import unittest

from tools.build_demo import _functional_elf_sections


class FunctionalELFSectionTests(unittest.TestCase):
    def test_authored_fixtures_expose_expected_functional_sections(self):
        root = Path(__file__).resolve().parents[1]
        symbolized = _functional_elf_sections(root / "demo/irqscope_demo.elf")
        stripped = _functional_elf_sections(root / "demo/irqscope_demo_stripped.elf")

        required = {".isr_vector", ".ARM.exidx", ".text", ".data", ".bss"}
        self.assertTrue(required.issubset(symbolized))
        self.assertIn(".symtab", symbolized)
        self.assertTrue(required.issubset(stripped))
        self.assertNotIn(".symtab", stripped)
        self.assertEqual(symbolized[".text"], stripped[".text"])
        self.assertEqual(symbolized[".isr_vector"], stripped[".isr_vector"])

    def test_rejects_non_elf_input(self):
        with tempfile.TemporaryDirectory() as temporary:
            malformed = Path(temporary) / "not-elf.bin"
            malformed.write_bytes(b"not an ELF")
            with self.assertRaisesRegex(RuntimeError, "not an ELF32"):
                _functional_elf_sections(malformed)

    def test_rejects_truncated_section_table(self):
        header = bytearray(52)
        header[:6] = b"\x7fELF\x01\x01"
        struct.pack_into("<H", header, 18, 40)  # EM_ARM
        struct.pack_into("<I", header, 32, 52)  # e_shoff
        struct.pack_into("<HHH", header, 46, 40, 1, 0)
        with tempfile.TemporaryDirectory() as temporary:
            malformed = Path(temporary) / "truncated.elf"
            malformed.write_bytes(header)
            with self.assertRaisesRegex(RuntimeError, "invalid ELF section table"):
                _functional_elf_sections(malformed)


if __name__ == "__main__":
    unittest.main()
