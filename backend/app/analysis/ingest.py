"""Safe, read-only ingestion of a source tree for static analysis.

Walks a directory and yields text source files only. It NEVER executes, imports,
installs, or evaluates anything from the tree — it only reads bytes. Vendored
dependencies, VCS metadata and build output are skipped so analysis focuses on the
project's own code. Hard limits bound time and memory on large or hostile inputs.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

# Directories that are never the project's own source.
IGNORED_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".idea",
        ".vscode",
        "node_modules",
        "bower_components",
        "vendor",
        "vendored",
        ".venv",
        "venv",
        "env",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        ".next",
        ".nuxt",
        ".svelte-kit",
        "dist",
        "build",
        "out",
        "target",
        "bin",
        "obj",
        ".gradle",
        "coverage",
        "htmlcov",
        ".terraform",
        # Deliberately vulnerable demo apps bundled with SecureAgent. Excluded from ordinary
        # scans (so scanning this repo stays meaningful); `secureagent demo` scans a fixture
        # as its root, which is exempt from directory pruning.
        "demo_fixtures",
    }
)

# Extensions that are binary or otherwise not worth scanning as source text.
BINARY_EXTENSIONS = frozenset(
    {
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".webp",
        ".ico",
        ".bmp",
        ".tiff",
        ".svg",
        ".pdf",
        ".zip",
        ".gz",
        ".tar",
        ".tgz",
        ".bz2",
        ".xz",
        ".7z",
        ".rar",
        ".mp3",
        ".mp4",
        ".mov",
        ".avi",
        ".mkv",
        ".wav",
        ".flac",
        ".ogg",
        ".woff",
        ".woff2",
        ".ttf",
        ".otf",
        ".eot",
        ".so",
        ".dll",
        ".dylib",
        ".class",
        ".jar",
        ".o",
        ".a",
        ".exe",
        ".bin",
        ".pyc",
        ".pyo",
        ".wasm",
        ".node",
        ".lock",
        ".min.js",
        ".min.css",
        ".map",
    }
)

DEFAULT_MAX_FILES = 20_000
DEFAULT_MAX_FILE_BYTES = 2 * 1024 * 1024  # 2 MiB; larger text files are rarely hand-written source
DEFAULT_MAX_TOTAL_BYTES = 500 * 1024 * 1024
_BINARY_SNIFF_BYTES = 4096


@dataclass(frozen=True)
class SourceFile:
    path: Path  # absolute
    relpath: str  # posix, relative to the scanned root
    size: int


@dataclass
class IngestStats:
    files_scanned: int = 0
    bytes_scanned: int = 0
    skipped_binary: int = 0
    skipped_too_large: int = 0
    skipped_dirs: int = 0
    truncated: bool = False
    notes: list[str] = field(default_factory=list)


class IngestError(ValueError):
    pass


def _looks_binary(sample: bytes) -> bool:
    if b"\x00" in sample:
        return True
    if not sample:
        return False
    # High proportion of non-text bytes => treat as binary.
    text_bytes = bytes(range(0x20, 0x7F)) + b"\n\r\t\f\b"
    nontext = sum(b not in text_bytes for b in sample)
    return nontext / len(sample) > 0.30


def iter_source_files(
    root: str | os.PathLike[str],
    *,
    max_files: int = DEFAULT_MAX_FILES,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
    stats: IngestStats | None = None,
) -> Iterator[SourceFile]:
    """Yield text source files under ``root``, enforcing limits. Read-only."""
    root_path = Path(root).resolve(strict=True)
    if not root_path.is_dir():
        raise IngestError(f"Not a directory: {root_path}")
    st = stats if stats is not None else IngestStats()

    for dirpath, dirnames, filenames in os.walk(root_path, followlinks=False):
        # Prune ignored directories in place so os.walk does not descend into them.
        kept = [d for d in dirnames if d not in IGNORED_DIRS and not _is_ignored_hidden(d)]
        st.skipped_dirs += len(dirnames) - len(kept)
        dirnames[:] = kept

        for name in filenames:
            abs_path = Path(dirpath) / name
            if abs_path.is_symlink():  # never follow symlinks out of the tree
                continue
            if _has_binary_extension(name):
                st.skipped_binary += 1
                continue
            try:
                size = abs_path.stat().st_size
            except OSError:
                continue
            if size > max_file_bytes:
                st.skipped_too_large += 1
                continue
            if st.bytes_scanned + size > max_total_bytes:
                st.truncated = True
                st.notes.append("Total-size limit reached; remaining files were not scanned.")
                return
            try:
                with abs_path.open("rb") as fh:
                    if _looks_binary(fh.read(_BINARY_SNIFF_BYTES)):
                        st.skipped_binary += 1
                        continue
            except OSError:
                continue

            st.files_scanned += 1
            st.bytes_scanned += size
            yield SourceFile(
                path=abs_path,
                relpath=abs_path.relative_to(root_path).as_posix(),
                size=size,
            )
            if st.files_scanned >= max_files:
                st.truncated = True
                st.notes.append("File-count limit reached; remaining files were not scanned.")
                return


def read_text(sf: SourceFile) -> str:
    """Decode a source file as UTF-8, replacing undecodable bytes (never raises)."""
    return sf.path.read_text(encoding="utf-8", errors="replace")


def _has_binary_extension(name: str) -> bool:
    lower = name.lower()
    return any(lower.endswith(ext) for ext in BINARY_EXTENSIONS)


def _is_ignored_hidden(dirname: str) -> bool:
    # Skip hidden tooling dirs (.cache, .git already listed) but keep normal ones.
    return dirname.startswith(".") and dirname not in {".github", ".gitlab"}
