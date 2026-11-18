"""Shared rules for the runtime UI branding folder.

The registry serves operator-supplied branding files (logos, favicon,
``manifest.json``, ``theme.css``, fonts) from one flat folder at
``{ROOT_PATH}/branding/<name>``. The container entrypoint can also populate
that folder from a base64 tar.gz archive. Both paths apply the same name and
extension rules, defined once here.
"""

import os
import re
import stat
from pathlib import Path

# First URL path segment the branding route owns. Servers and agents cannot be
# registered under it (see url_guard.validate_server_path and agent_models).
BRANDING_PATH_SEGMENT: str = "branding"

# A bare file name: no leading dot (Kubernetes ConfigMap volumes contain
# "..data" and "..<timestamp>" entries that must never be served), no slash.
BRANDING_NAME_PATTERN: re.Pattern[str] = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")

# Allowed extensions (lowercase, with the dot) and the Content-Type served.
BRANDING_CONTENT_TYPES: dict[str, str] = {
    ".json": "application/json",
    ".css": "text/css",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".webp": "image/webp",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".ico": "image/x-icon",
    ".woff2": "font/woff2",
}

# Largest single branding file the registry serves.
MAX_BRANDING_FILE_BYTES: int = 2 * 1024 * 1024

# Archive limits for UI_BRANDING_ARCHIVE_B64. FILES counts accepted branding
# files and TOTAL_BYTES their declared sizes. ENTRIES counts every tar header,
# including the skipped root entry and macOS metadata (each file may carry an
# AppleDouble "._" twin). TAR_BYTES bounds both the decoded .tar.gz and the
# decompressed tar stream: the file payload plus room for headers, pax records
# and block padding, so a gzip bomb stops at a fixed size.
MAX_BRANDING_ARCHIVE_FILES: int = 32
MAX_BRANDING_ARCHIVE_TOTAL_BYTES: int = 2 * 1024 * 1024
MAX_BRANDING_ARCHIVE_ENTRIES: int = 4 * MAX_BRANDING_ARCHIVE_FILES
MAX_BRANDING_ARCHIVE_TAR_BYTES: int = 2 * MAX_BRANDING_ARCHIVE_TOTAL_BYTES

# Served when the file is absent, so the UI never sees a 404 for these.
DEFAULT_BRANDING_FILES: dict[str, bytes] = {
    "manifest.json": b"{}",
    "theme.css": b"",
}

# Stops an SVG opened directly in the browser from running script.
BRANDING_SVG_CSP: str = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; sandbox"

BRANDING_CACHE_CONTROL: str = "public, max-age=300"


class BrandingFileRefusedError(Exception):
    """Raised when a branding file exists but must not be served."""


def branding_content_type(
    name: str,
) -> str | None:
    """Return the Content-Type for an allowed branding file name.

    Args:
        name: Candidate file name, as taken from the URL or an archive member.

    Returns:
        The Content-Type when ``name`` is a bare name matching the name rule
        with an allowed extension, otherwise None.
    """
    if not BRANDING_NAME_PATTERN.fullmatch(name):
        return None
    return BRANDING_CONTENT_TYPES.get(Path(name).suffix.lower())


def branding_response_headers(
    content_type: str,
) -> dict[str, str]:
    """Build the response headers for a branding file.

    Args:
        content_type: The Content-Type being served.

    Returns:
        Cache and nosniff headers, plus a locked-down CSP for SVG.
    """
    headers = {
        "Cache-Control": BRANDING_CACHE_CONTROL,
        "X-Content-Type-Options": "nosniff",
    }
    if content_type == "image/svg+xml":
        headers["Content-Security-Policy"] = BRANDING_SVG_CSP
    return headers


def _resolve_inside(
    base: Path,
    name: str,
) -> Path:
    """Resolve ``base / name`` and require the target to stay inside ``base``.

    Args:
        base: The already-resolved branding folder.
        name: A validated bare branding file name.

    Returns:
        The resolved path, which may not exist.

    Raises:
        BrandingFileRefusedError: If resolving fails or leaves the folder.
    """
    try:
        resolved = (base / name).resolve()
    except (OSError, RuntimeError) as e:
        raise BrandingFileRefusedError(f"cannot resolve path: {e}") from e
    if not resolved.is_relative_to(base) or resolved == base:
        raise BrandingFileRefusedError("resolves outside the branding folder")
    return resolved


def _read_open_file(
    fd: int,
) -> tuple[os.stat_result, bytes]:
    """Check an open descriptor is a small regular file and read all of it.

    Args:
        fd: Descriptor opened read-only.

    Returns:
        The descriptor's stat result and the file contents.

    Raises:
        BrandingFileRefusedError: If it is not a regular file, is too large,
            or cannot be read.
    """
    try:
        stat_result = os.fstat(fd)
        if not stat.S_ISREG(stat_result.st_mode):
            raise BrandingFileRefusedError("not a regular file")
        if stat_result.st_size > MAX_BRANDING_FILE_BYTES:
            raise BrandingFileRefusedError(
                f"file is {stat_result.st_size} bytes, larger than the "
                f"{MAX_BRANDING_FILE_BYTES} byte limit"
            )
        chunks: list[bytes] = []
        remaining = MAX_BRANDING_FILE_BYTES + 1
        while remaining > 0 and (chunk := os.read(fd, remaining)):
            chunks.append(chunk)
            remaining -= len(chunk)
    except OSError as e:
        raise BrandingFileRefusedError(f"cannot read file: {e}") from e
    data = b"".join(chunks)
    # The file can grow after fstat; the cap applies to what was read.
    if len(data) > MAX_BRANDING_FILE_BYTES:
        raise BrandingFileRefusedError(
            f"file grew past the {MAX_BRANDING_FILE_BYTES} byte limit while being read"
        )
    return stat_result, data


def _windows_comparison_path(path: str) -> Path:
    """Normalize the extended-length prefix returned by Windows file handles."""
    unc_prefix = "\\\\?\\UNC\\"
    if path[:len(unc_prefix)].upper() == unc_prefix:
        return Path("\\\\" + path[len(unc_prefix):])
    return Path(path.removeprefix("\\\\?\\"))


def _check_windows_file_path(fd: int, base: Path) -> None:
    """Check the resolved path of the actual open handle before reading it."""
    import ctypes
    import msvcrt
    from ctypes import wintypes

    get_path = ctypes.WinDLL("kernel32", use_last_error=True).GetFinalPathNameByHandleW
    get_path.argtypes = (wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD)
    get_path.restype = wintypes.DWORD
    handle = msvcrt.get_osfhandle(fd)
    required = get_path(handle, None, 0, 0)
    if not required:
        raise BrandingFileRefusedError("cannot resolve the open branding file")
    buffer = ctypes.create_unicode_buffer(required)
    copied = get_path(handle, buffer, len(buffer), 0)
    if not 0 < copied < len(buffer):
        raise BrandingFileRefusedError("cannot resolve the open branding file")
    opened_path = _windows_comparison_path(buffer.value)
    root = _windows_comparison_path(str(base))
    if not opened_path.is_relative_to(root) or opened_path == root:
        raise BrandingFileRefusedError("open file resolves outside the branding folder")


def read_branding_file(
    branding_dir: Path,
    name: str,
) -> bytes:
    """Read a validated branding name from inside the branding folder.

    Symlinks are followed, and the final target must stay inside the resolved
    branding folder. Kubernetes ConfigMap keys are symlinks into a
    ``..<timestamp>/`` directory inside the same folder, so they pass.

    The file is checked and read through one descriptor, so a path swapped
    after the containment check cannot change what is served. The final
    component on POSIX is opened with ``O_NOFOLLOW`` (a symlink swapped in fails) and
    ``O_NONBLOCK`` (a FIFO swapped in cannot hang the worker). A swapped
    parent directory is caught after the open: the name is resolved again and
    must still land inside the folder on the same inode as the descriptor.
    On Windows the open handle is also checked for containment before reading.

    Args:
        branding_dir: The configured branding folder (may not exist).
        name: A name that already passed :func:`branding_content_type`.

    Returns:
        The file contents, at most ``MAX_BRANDING_FILE_BYTES`` long.

    Raises:
        FileNotFoundError: If the file (or the whole folder) does not exist.
        BrandingFileRefusedError: If the file escapes the folder, is not a
            regular file, is too large, changes while being opened, or cannot
            be read.
    """
    try:
        base = branding_dir.resolve()
    except (OSError, RuntimeError) as e:
        raise BrandingFileRefusedError(f"cannot resolve branding folder: {e}") from e
    resolved = _resolve_inside(base, name)

    # FileNotFoundError propagates: the caller serves a default or a 404.
    try:
        if os.name == "nt":
            fd = os.open(resolved, os.O_RDONLY | os.O_BINARY)
        else:
            fd = os.open(resolved, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        raise
    except OSError as e:
        raise BrandingFileRefusedError(f"cannot open file: {e}") from e

    try:
        if os.name == "nt":
            _check_windows_file_path(fd, base)
        stat_result, data = _read_open_file(fd)
    finally:
        os.close(fd)

    try:
        current = _resolve_inside(base, name).stat()
    except OSError as e:
        raise BrandingFileRefusedError(f"file changed while being opened: {e}") from e
    if (current.st_dev, current.st_ino) != (stat_result.st_dev, stat_result.st_ino):
        raise BrandingFileRefusedError("file changed while being opened")
    return data
