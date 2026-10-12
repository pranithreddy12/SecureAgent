"""Zip upload for web audits (ADR-019): bounded body, safe extraction, ephemeral workspace.

The archive is untrusted input. Nothing in it is ever executed; it is unpacked into a private
directory under ``UPLOAD_DIR`` and then audited exactly like a mounted source directory.

Rejected outright: absolute paths, ``..`` components, drive letters, symlinks and other special
entries, encrypted members, more than ``MAX_UPLOAD_FILES`` files, and more than
``MAX_UPLOAD_UNPACKED_MB`` of data -- measured on the bytes actually written, because the sizes a
zip declares can lie (zip bombs).
"""

from __future__ import annotations

import shutil
import stat
import uuid
import zipfile
from pathlib import Path, PurePosixPath

from app.core.config import get_settings

_CHUNK = 64 * 1024


class UploadError(Exception):
    """Maps directly to an HTTP response."""

    def __init__(self, detail: str, status_code: int = 400) -> None:
        super().__init__(detail)
        self.detail = detail
        self.status_code = status_code


def upload_root() -> Path:
    configured = get_settings().upload_dir
    if not configured:
        raise UploadError("Code upload is disabled: the server has no UPLOAD_DIR configured.", 503)
    return Path(configured).resolve()


def _safe_name(raw: str) -> PurePosixPath | None:
    """Return a clean relative path, or ``None`` for an entry that must be skipped (a directory)."""
    name = raw.replace("\\", "/")
    if name.endswith("/"):
        return None
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or (path.parts and ":" in path.parts[0]):
        raise UploadError("The archive contains an unsafe path.")
    if any(part in ("", ".") for part in path.parts[:-1]) or not path.parts:
        raise UploadError("The archive contains an unsafe path.")
    return path


def extract_zip(archive: Path, dest: Path) -> int:
    """Unpack ``archive`` into ``dest`` (created). Returns the number of files written."""
    settings = get_settings()
    max_files = settings.max_upload_files
    max_bytes = settings.max_upload_unpacked_mb * 1024 * 1024
    try:
        zf = zipfile.ZipFile(archive)
    except (zipfile.BadZipFile, OSError):
        raise UploadError("The upload is not a valid zip archive.") from None
    written = total = 0
    with zf:
        members = zf.infolist()
        if len(members) > max_files * 2:
            raise UploadError("The archive contains too many entries.")
        entries: list[tuple[zipfile.ZipInfo, PurePosixPath]] = []
        for info in members:
            kind = stat.S_IFMT(info.external_attr >> 16)  # 0 when the zip carries no file type
            if kind not in (0, stat.S_IFREG, stat.S_IFDIR):
                raise UploadError("The archive contains a symlink or special file.")
            if info.flag_bits & 0x1:
                raise UploadError("Encrypted archives are not supported.")
            rel = _safe_name(info.filename)
            if rel is not None:
                entries.append((info, rel))
        if not entries:
            raise UploadError("The archive contains no files.")
        if len(entries) > max_files:
            raise UploadError(f"The archive has more than {max_files} files.")
        # A single wrapping folder (the usual "project-main/" of a repo download) is flattened.
        tops = {rel.parts[0] for _, rel in entries}
        strip = 1 if len(tops) == 1 and all(len(rel.parts) > 1 for _, rel in entries) else 0
        dest.mkdir(parents=True)
        base = dest.resolve()
        for info, rel in entries:
            target = (base.joinpath(*rel.parts[strip:])).resolve()
            if base not in target.parents:
                raise UploadError("The archive contains an unsafe path.")
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, open(target, "wb") as out:
                while chunk := src.read(_CHUNK):
                    total += len(chunk)
                    if total > max_bytes:
                        raise UploadError(
                            "The archive unpacks to more than "
                            f"{settings.max_upload_unpacked_mb} MB."
                        )
                    out.write(chunk)
            written += 1
    return written


async def save_body(stream, dest: Path) -> int:
    """Write an async byte stream to ``dest``, refusing more than ``MAX_UPLOAD_MB``."""
    limit = get_settings().max_upload_mb * 1024 * 1024
    size = 0
    with open(dest, "wb") as fh:
        async for chunk in stream:
            size += len(chunk)
            if size > limit:
                raise UploadError(
                    f"The upload is larger than {get_settings().max_upload_mb} MB.", 413
                )
            fh.write(chunk)
    return size


def new_workspace(user_id: uuid.UUID) -> Path:
    """A fresh, unguessable directory path for one upload (not yet created)."""
    return upload_root() / str(user_id) / uuid.uuid4().hex


def remove_workspace(path: str) -> None:
    """Delete an uploaded workspace -- only ever something strictly inside the upload root."""
    configured = get_settings().upload_dir
    if not configured:
        return
    root = Path(configured).resolve()
    target = Path(path).resolve()
    if root in target.parents:
        shutil.rmtree(target, ignore_errors=True)
