"""Rebuild or verify IRQScope's authored Cortex-M demo ELFs."""

import argparse
import hashlib
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _tool(name: str, override: str | None) -> str:
    found = override or shutil.which(name)
    if not found:
        raise RuntimeError(f"{name} is required; install LLVM/Clang or pass its path explicitly")
    return found


def _build(root: Path, clang: str, llvm_strip: str, output_dir: Path) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    symbolized = output_dir / "irqscope_demo.elf"
    stripped = output_dir / "irqscope_demo_stripped.elf"
    command = [
        clang,
        "--target=arm-none-eabi", "-mcpu=cortex-m4", "-mthumb", "-O1", "-g",
        "-fdebug-compilation-dir=.",
        "-ffreestanding", "-fno-builtin", "-fno-unwind-tables",
        "-fno-asynchronous-unwind-tables", "-nostdlib", "-fuse-ld=lld",
        "-Wl,-T,demo/irqscope_demo.ld", "-Wl,--build-id=none",
        "demo/startup.S", "demo/irqscope_demo.c", "-o", str(symbolized),
    ]
    subprocess.run(command, cwd=root, check=True)
    subprocess.run([llvm_strip, "--strip-all", "-o", str(stripped), str(symbolized)],
                   cwd=root, check=True)
    return symbolized, stripped


def _verify_shape(objdump: str, symbolized: Path, stripped: Path) -> None:
    sections = subprocess.run([objdump, "-h", str(symbolized)], check=True,
                              capture_output=True, text=True).stdout
    if not re.search(r"\.isr_vector\s+\S+\s+08000000\b", sections, re.IGNORECASE):
        raise RuntimeError("Demo ELF is missing its vector table at 0x08000000")

    disassembly = subprocess.run(
        [objdump, "--disassemble", "--symbolize-operands", str(symbolized)],
        check=True, capture_output=True, text=True,
    ).stdout
    functions = {}
    for match in re.finditer(
            r"(?m)^([0-9a-f]+) <([^>]+)>:\s*\n(.*?)(?=^[0-9a-f]+ <[^>]+>:\s*$|\Z)",
            disassembly, re.IGNORECASE | re.DOTALL):
        functions[match.group(2)] = match.group(3).lower()
    required = {
        "transfer_unsafe", "transfer_masked", "USART_IRQHandler", "NVIC_EnableIRQ",
        "configure_and_acknowledge_foreground",
        "configure_mode_byte_and_acknowledge_fixture",
        "invalid_config_mode_write_fixture",
        "branch_shifted_constant_fixture",
    }
    if not required.issubset(functions):
        raise RuntimeError(f"Demo ELF is missing expected functions: {sorted(required - functions.keys())}")
    masked = functions["transfer_masked"]
    if not all(op in masked for op in ("mrs", "primask", "cpsid", "msr")):
        raise RuntimeError("Masked transaction no longer contains MRS/CPSID/MSR PRIMASK evidence")
    if "cpsid" in functions["transfer_unsafe"]:
        raise RuntimeError("Unmasked transaction unexpectedly contains CPSID")
    if "str.w" not in functions["NVIC_EnableIRQ"] or "lsl" not in functions["NVIC_EnableIRQ"]:
        raise RuntimeError("Demo NVIC wrapper no longer exercises indexed store addressing")
    for name in ("configure_and_acknowledge_foreground", "invalid_config_mode_write_fixture",
                 "USART_IRQHandler", "TIMER_IRQHandler"):
        if not re.search(r"\bstr(?:\.w)?\b", functions.get(name, "")):
            raise RuntimeError(f"Demo function {name} no longer contains an MMIO store")
    byte_fixture = functions["configure_mode_byte_and_acknowledge_fixture"]
    if not re.search(r"\bstrb(?:\.w)?\b", byte_fixture):
        raise RuntimeError("Byte-lane fixture no longer contains a byte store")
    branch_fixture = functions["branch_shifted_constant_fixture"]
    if not all(token in branch_fixture for token in ("cmp", "lsl", "bne", "str")):
        raise RuntimeError("Shifted-comparison fixture no longer contains its branch/store shape")
    if len(re.findall(r"\bstr(?:\.w)?\b", branch_fixture)) != 2:
        raise RuntimeError("Shifted-comparison fixture must retain both branch-specific stores")

    symbols = subprocess.run([objdump, "--syms", str(stripped)], check=True,
                             capture_output=True, text=True).stdout
    if any(name in symbols for name in required):
        raise RuntimeError("Stripped demo ELF unexpectedly retains symbolized function names")


def _functional_elf_sections(path: Path) -> dict[str, tuple[int, bytes]]:
    """Read functional ELF sections, excluding host-specific debug/ABI metadata."""
    data = Path(path).read_bytes()
    if len(data) < 52 or data[:4] != b"\x7fELF" or data[4:6] != b"\x01\x01":
        raise RuntimeError(f"{path} is not an ELF32 little-endian file")
    machine = struct.unpack_from("<H", data, 18)[0]
    if machine != 40:  # EM_ARM
        raise RuntimeError(f"{path} is not an ARM ELF")
    section_offset = struct.unpack_from("<I", data, 32)[0]
    entry_size, count, names_index = struct.unpack_from("<HHH", data, 46)
    if (entry_size < 40 or count == 0 or names_index >= count
            or section_offset + entry_size * count > len(data)):
        raise RuntimeError(f"{path} has an invalid ELF section table")
    headers = [struct.unpack_from("<IIIIIIIIII", data, section_offset + i * entry_size)
               for i in range(count)]
    names_header = headers[names_index]
    names = data[names_header[4]:names_header[4] + names_header[5]]
    if names_header[4] + names_header[5] > len(data):
        raise RuntimeError(f"{path} has an invalid ELF section-name table")
    selected = {".isr_vector", ".ARM.exidx", ".text", ".data", ".bss", ".symtab", ".strtab"}
    result = {}
    for header in headers:
        name_offset, section_type, _, _, offset, size = header[:6]
        if name_offset >= len(names):
            if name_offset == 0:
                continue
            raise RuntimeError(f"{path} has an invalid ELF section name offset")
        end = names.find(b"\0", name_offset)
        if end < 0:
            raise RuntimeError(f"{path} has an unterminated ELF section name")
        name = names[name_offset:end].decode("ascii", "replace")
        if name not in selected:
            continue
        # SHT_NOBITS (8) has a logical size but no bytes in the file.
        if section_type == 8:  # SHT_NOBITS
            section_data = b""
        else:
            if offset + size > len(data):
                raise RuntimeError(f"{path} has an out-of-bounds ELF section")
            section_data = data[offset:offset + size]
        result[name] = (size, section_data)
    required = {".isr_vector", ".ARM.exidx", ".text", ".data", ".bss"}
    if not required.issubset(result):
        raise RuntimeError(f"{path} is missing functional sections: {sorted(required - result.keys())}")
    return result


def build_or_check(root: Path, clang: str, llvm_strip: str, objdump: str,
                   check: bool) -> tuple[str, str]:
    root = Path(root).resolve()
    expected = (root / "demo/irqscope_demo.elf", root / "demo/irqscope_demo_stripped.elf")
    if check:
        with tempfile.TemporaryDirectory(prefix="irqscope-demo-") as temporary:
            generated = _build(root, clang, llvm_strip, Path(temporary))
            _verify_shape(objdump, *generated)
            hashes = tuple(_sha256(path) for path in generated)
            for name, built, checked_in, digest in zip(
                    ("symbolized", "stripped"), generated, expected, hashes):
                if not checked_in.is_file():
                    raise RuntimeError(f"Missing checked-in {name} demo ELF: {checked_in}")
                built_sections = _functional_elf_sections(built)
                checked_sections = _functional_elf_sections(checked_in)
                if built_sections != checked_sections:
                    raise RuntimeError(
                        f"Checked-in {name} demo ELF functional sections differ from a clean build. "
                        f"Regenerate it with `python tools/build_demo.py`; generated SHA-256 {digest}."
                    )
        return hashes[0], hashes[1]

    generated = _build(root, clang, llvm_strip, root / "demo")
    _verify_shape(objdump, *generated)
    return _sha256(generated[0]), _sha256(generated[1])


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--clang", help="Clang executable (default: clang from PATH)")
    parser.add_argument("--llvm-strip", help="llvm-strip executable (default: llvm-strip from PATH)")
    parser.add_argument("--llvm-objdump", help="llvm-objdump executable (default: llvm-objdump from PATH)")
    parser.add_argument("--check", action="store_true",
                        help="rebuild in a temporary directory and compare with checked-in ELFs")
    args = parser.parse_args(argv)
    root = Path(__file__).resolve().parents[1]
    try:
        clang = _tool("clang", args.clang)
        llvm_strip = _tool("llvm-strip", args.llvm_strip)
        objdump = _tool("llvm-objdump", args.llvm_objdump)
        symbolized, stripped = build_or_check(root, clang, llvm_strip, objdump, args.check)
    except (OSError, RuntimeError, subprocess.CalledProcessError) as exc:
        parser.error(str(exc))
    action = "Verified" if args.check else "Built"
    print(f"{action} symbolized demo SHA-256: {symbolized}")
    print(f"{action} stripped demo SHA-256:   {stripped}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
