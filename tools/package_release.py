"""Build a reproducible IRQScope source archive with explicit author metadata."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import zipfile
from urllib.parse import urlparse


INCLUDED_ROOT_FILES = ("ida-plugin.json", "irqscope_plugin.py", "README.md", "CHANGELOG.md", "LICENSE")
INCLUDED_DIRECTORIES = ("irqscope", "docs", "demo", "tests", "assets", "tools")
EXCLUDED_PARTS = {"__pycache__", ".git", ".pytest_cache"}


def _validate_metadata(author: str, author_email: str, repository: str):
    author = (author or "").strip()
    if not author or author.upper() in {"AUTHOR", "OWNER"}:
        raise ValueError("Provide the actual author name with --author")
    author_email = (author_email or "").strip()
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", author_email):
        raise ValueError("Provide a valid author email with --author-email")
    parsed = urlparse((repository or "").strip())
    segments = [part for part in parsed.path.split("/") if part]
    if (parsed.scheme != "https" or parsed.netloc.lower() != "github.com"
            or len(segments) != 2 or any(part.upper() in {"OWNER", "REPO"} for part in segments)):
        raise ValueError("--github-repository must be https://github.com/<owner>/<repo>")
    return author, author_email, f"https://github.com/{segments[0]}/{segments[1]}"


def _archive_files(root: Path):
    files = [root / name for name in INCLUDED_ROOT_FILES]
    for directory in INCLUDED_DIRECTORIES:
        base = root / directory
        if not base.is_dir():
            continue
        files.extend(
            path for path in base.rglob("*")
            if path.is_file()
            and not any(part in EXCLUDED_PARTS for part in path.parts)
            and path.suffix not in {".pyc", ".pyo"}
        )
    return sorted((path for path in files if path.is_file()), key=lambda path: path.relative_to(root).as_posix())


def build_archive(root: Path, archive_path: Path, author: str, author_email: str, repository: str) -> str:
    author, author_email, repository = _validate_metadata(author, author_email, repository)
    root = Path(root).resolve()
    archive_path = Path(archive_path).resolve()
    manifest = json.loads((root / "ida-plugin.json").read_text(encoding="utf-8"))
    plugin = manifest.get("plugin")
    if not isinstance(plugin, dict):
        raise ValueError("ida-plugin.json is missing its plugin descriptor")
    plugin.setdefault("urls", {})["repository"] = repository
    plugin["authors"] = [{"name": author, "email": author_email}]
    manifest_bytes = (json.dumps(manifest, indent=2, ensure_ascii=False) + "\n").encode("utf-8")

    archive_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in _archive_files(root):
            relative = path.relative_to(root).as_posix()
            data = manifest_bytes if relative == "ida-plugin.json" else path.read_bytes()
            info = zipfile.ZipInfo(relative, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    archive_hash = hashlib.sha256(archive_path.read_bytes()).hexdigest()
    sidecar = archive_path.with_suffix(archive_path.suffix + ".sha256")
    sidecar.write_text(f"{archive_hash}  {archive_path.name}\n", encoding="ascii")
    return archive_hash


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--author", required=True, help="Author name for the package manifest")
    parser.add_argument("--author-email", required=True, help="Author email required by HCLI metadata")
    parser.add_argument("--github-repository", required=True,
                        help="Repository URL, for example https://github.com/example/irqscope")
    parser.add_argument("--output-dir", type=Path, default=None)
    args = parser.parse_args(argv)
    root = Path(__file__).resolve().parents[1]
    manifest = json.loads((root / "ida-plugin.json").read_text(encoding="utf-8"))
    version = manifest["plugin"]["version"]
    output_dir = args.output_dir or root / "dist"
    archive = output_dir / f"irqscope-{version}.zip"
    digest = build_archive(root, archive, args.author, args.author_email, args.github_repository)
    print(f"Archive: {archive}")
    print(f"SHA-256: {digest}")
    print("Next validate with HCLI and install in a clean supported IDA build.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
