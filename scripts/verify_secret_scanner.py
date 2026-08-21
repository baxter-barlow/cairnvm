#!/usr/bin/env python3
"""Scan exact Git trees with a checksum-pinned Gitleaks release and generated canary.

Benign concurrent cold starts are serialized. A hostile same-UID process that mutates the
fixed cache namespace concurrently is outside this verifier's threat model.
"""

from __future__ import annotations

import base64
import fcntl
import hashlib
import os
import platform
import pwd
import secrets
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
import unicodedata
import urllib.error
import urllib.request
import zipfile
import zlib
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from http.client import HTTPMessage
from pathlib import Path, PurePosixPath
from typing import BinaryIO, cast
from urllib.parse import urlsplit

ARCHIVE_DEPTH = "1"
DECODE_DEPTH = "1"
GIT_COMMAND_TIMEOUT_SECONDS = 30
REPOSITORY_SCAN_TIMEOUT_SECONDS = 300
MAX_HISTORY_TREES = 4096
MAX_TREE_ENTRIES = 100_000
MAX_SNAPSHOT_BYTES = 256 * 1024 * 1024
MAX_GIT_OUTPUT_BYTES = 64 * 1024 * 1024
MAX_RELEASE_ARCHIVE_BYTES = 16 * 1024 * 1024
MAX_RELEASE_DECOMPRESSED_BYTES = 32 * 1024 * 1024
MAX_GITLEAKS_BINARY_BYTES = 24 * 1024 * 1024
RELEASE_DOWNLOAD_TIMEOUT_SECONDS = 60
MAX_RELEASE_REDIRECTS = 3
DOWNLOAD_CHUNK_BYTES = 1024 * 1024
GITLEAKS_POLICY = "[extend]\nuseDefault = true\n"
REPOSITORY_CONTROL_FILES = frozenset((".gitleaks.toml", ".gitleaksignore"))
REGULAR_FILE_MODES = frozenset(("100644", "100755"))
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
GITLEAKS_VERSION = "8.30.1"
GITLEAKS_RELEASE_BASE_URL = (
    f"https://github.com/gitleaks/gitleaks/releases/download/v{GITLEAKS_VERSION}"
)
GITLEAKS_RELEASE_HOSTS = frozenset(("github.com", "release-assets.githubusercontent.com"))
GITLEAKS_CACHE_HOME = Path(pwd.getpwuid(os.getuid()).pw_dir)


@dataclass(frozen=True)
class ReleaseAsset:
    filename: str
    sha256: str
    binary_size: int
    archive_size: int
    tar_size: int
    binary_format: str
    machine_code: int


GITLEAKS_RELEASE_ASSETS = {
    ("darwin", "arm64"): ReleaseAsset(
        "gitleaks_8.30.1_darwin_arm64.tar.gz",
        "b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5",
        21_324_882,
        7_897_593,
        21_359_616,
        "macho",
        0x0100000C,
    ),
    ("darwin", "x64"): ReleaseAsset(
        "gitleaks_8.30.1_darwin_x64.tar.gz",
        "dfe101a4db2255fc85120ac7f3d25e4342c3c20cf749f2c20a18081af1952709",
        22_398_576,
        8_359_235,
        22_433_280,
        "macho",
        0x01000007,
    ),
    ("linux", "arm64"): ReleaseAsset(
        "gitleaks_8.30.1_linux_arm64.tar.gz",
        "e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080",
        20_775_096,
        7_601_421,
        20_809_728,
        "elf",
        183,
    ),
    ("linux", "x64"): ReleaseAsset(
        "gitleaks_8.30.1_linux_x64.tar.gz",
        "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb",
        21_958_840,
        8_230_402,
        21_993_472,
        "elf",
        62,
    ),
}


@dataclass(frozen=True)
class GitRepository:
    executable: str
    root: Path
    git_dir: Path
    environment: dict[str, str]
    object_format: str = "sha1"


@dataclass(frozen=True)
class TreeEntry:
    mode: str
    object_id: str
    size: int
    path: str


def _select_release_asset(*, system: str | None = None, machine: str | None = None) -> ReleaseAsset:
    operating_system = (platform.system() if system is None else system).lower()
    architecture = (platform.machine() if machine is None else machine).lower()
    normalized_architecture = {
        "aarch64": "arm64",
        "amd64": "x64",
        "arm64": "arm64",
        "x86_64": "x64",
    }.get(architecture)
    asset = GITLEAKS_RELEASE_ASSETS.get((operating_system, normalized_architecture or ""))
    if asset is None:
        raise RuntimeError("unsupported secret scanner platform")
    return asset


def _cache_root() -> Path:
    return GITLEAKS_CACHE_HOME / ".cache" / "cairnvm" / "gitleaks" / f"v{GITLEAKS_VERSION}"


def _cache_archive_path(asset: ReleaseAsset) -> Path:
    return _cache_root() / asset.filename


def build_canary() -> str:
    """Build a rule-matching token without storing one contiguously in the repository."""

    payload = "".join(("wA9mK2pL", "xN4vRtQz", "Y6bC8dEf", "GhJlM0oP", "q1rS"))
    return "".join(("gh", "p_", payload))


def scanner_environment(isolated_home: Path) -> dict[str, str]:
    """Create a minimal scanner environment without ambient executable controls."""

    return {
        "HOME": str(isolated_home),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": os.defpath,
        "TMPDIR": str(isolated_home),
        "XDG_CONFIG_HOME": str(isolated_home),
    }


def _validate_release_url(url: str) -> None:
    parsed = urlsplit(url)
    try:
        port = parsed.port
    except ValueError as error:
        raise RuntimeError("unsafe secret scanner release URL") from error
    if (
        parsed.scheme != "https"
        or parsed.hostname not in GITLEAKS_RELEASE_HOSTS
        or parsed.username is not None
        or parsed.password is not None
        or port not in (None, 443)
        or not parsed.path.startswith("/")
        or parsed.fragment
    ):
        raise RuntimeError("unsafe secret scanner release URL")


class _ReleaseRedirectHandler(urllib.request.HTTPRedirectHandler):
    max_redirections = MAX_RELEASE_REDIRECTS
    max_repeats = MAX_RELEASE_REDIRECTS

    def redirect_request(  # type: ignore[override]
        self,
        request: urllib.request.Request,
        file_pointer: BinaryIO,
        code: int,
        message: str,
        headers: HTTPMessage,
        new_url: str,
    ) -> urllib.request.Request | None:
        _validate_release_url(new_url)
        redirected = super().redirect_request(
            request,
            file_pointer,
            code,
            message,
            headers,
            new_url,
        )
        if redirected is not None:
            for header in ("Authorization", "Cookie", "Proxy-Authorization"):
                redirected.remove_header(header)
        return redirected


def _remaining_download_timeout(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise RuntimeError("secret scanner release download timed out")
    return remaining


def _copy_download(
    source: BinaryIO,
    destination: BinaryIO,
    *,
    deadline: float,
) -> int:
    total = 0
    while True:
        _remaining_download_timeout(deadline)
        chunk = source.read(min(DOWNLOAD_CHUNK_BYTES, MAX_RELEASE_ARCHIVE_BYTES - total + 1))
        if time.monotonic() > deadline:
            raise RuntimeError("secret scanner release download timed out")
        if not isinstance(chunk, bytes):
            raise RuntimeError("secret scanner release download returned invalid bytes")
        if not chunk:
            return total
        total += len(chunk)
        if total > MAX_RELEASE_ARCHIVE_BYTES:
            raise RuntimeError("secret scanner release archive exceeds the download limit")
        destination.write(chunk)


def _download_release_archive_child(
    asset: ReleaseAsset,
    destination: BinaryIO,
    *,
    deadline: float,
) -> None:
    url = f"{GITLEAKS_RELEASE_BASE_URL}/{asset.filename}"
    _validate_release_url(url)
    request = urllib.request.Request(  # noqa: S310  # URL was restricted to pinned HTTPS hosts.
        url,
        headers={"Accept": "application/octet-stream", "User-Agent": "CairnVM-secret-scanner/1"},
        method="GET",
    )
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        _ReleaseRedirectHandler(),
        urllib.request.HTTPSHandler(),
    )
    try:
        with opener.open(request, timeout=_remaining_download_timeout(deadline)) as response:
            _validate_release_url(response.geturl())
            if response.status != 200:
                raise RuntimeError("secret scanner release download failed")
            raw_length = response.headers.get("Content-Length")
            if raw_length is not None:
                try:
                    content_length = int(raw_length)
                except ValueError as error:
                    raise RuntimeError(
                        "secret scanner release returned an invalid length"
                    ) from error
                if content_length < 0 or content_length > MAX_RELEASE_ARCHIVE_BYTES:
                    raise RuntimeError("secret scanner release archive exceeds the download limit")
            downloaded = _copy_download(
                cast(BinaryIO, response),
                destination,
                deadline=deadline,
            )
            if raw_length is not None and downloaded != content_length:
                raise RuntimeError("secret scanner release length did not match its response")
    except urllib.error.HTTPError as error:
        raise RuntimeError("secret scanner release download failed") from error
    except (OSError, urllib.error.URLError) as error:
        raise RuntimeError("secret scanner release download could not complete") from error

    destination.flush()


def _download_release_archive(
    asset: ReleaseAsset,
    destination: BinaryIO,
    *,
    deadline: float,
) -> None:
    try:
        asset_key = next(
            key for key, candidate in GITLEAKS_RELEASE_ASSETS.items() if candidate == asset
        )
    except StopIteration as error:
        raise RuntimeError("secret scanner release asset is unsupported") from error
    command = [
        sys.executable,
        "-I",
        str(Path(__file__).resolve()),
        "--internal-download",
        *asset_key,
    ]
    try:
        result = subprocess.run(  # noqa: S603  # Runs this trusted script in isolated mode.
            command,
            check=False,
            close_fds=True,
            env={"LANG": "C", "LC_ALL": "C", "PATH": os.defpath},
            stdin=subprocess.DEVNULL,
            stdout=destination,
            stderr=subprocess.DEVNULL,
            timeout=_remaining_download_timeout(deadline),
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RuntimeError("secret scanner release download could not complete") from error
    if result.returncode != 0:
        raise RuntimeError("secret scanner release download failed")
    destination.flush()
    destination.seek(0)
    digest = hashlib.sha256()
    while chunk := destination.read(DOWNLOAD_CHUNK_BYTES):
        digest.update(chunk)
    if digest.hexdigest() != asset.sha256:
        raise RuntimeError("secret scanner release checksum did not match")


def _validate_private_directory(metadata: os.stat_result, *, exact_mode: bool = False) -> None:
    mode = stat.S_IMODE(metadata.st_mode)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or mode & 0o022
        or (exact_mode and mode != 0o700)
    ):
        raise RuntimeError("secret scanner cache directory is unsafe")


@contextmanager
def _open_cache_directory() -> Iterator[tuple[int, Path]]:
    home = GITLEAKS_CACHE_HOME
    if not home.is_absolute():
        raise RuntimeError("secret scanner cache home is unsafe")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
    try:
        directory_fd = os.open(home, flags)
        _validate_private_directory(os.fstat(directory_fd))
        for component in (".cache", "cairnvm", "gitleaks", f"v{GITLEAKS_VERSION}"):
            with suppress(FileExistsError):
                os.mkdir(component, mode=0o700, dir_fd=directory_fd)
            next_fd = os.open(component, flags, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
            _validate_private_directory(
                os.fstat(directory_fd),
                exact_mode=component != ".cache",
            )
    except (OSError, RuntimeError) as error:
        if "directory_fd" in locals():
            os.close(directory_fd)
        raise RuntimeError("secret scanner cache directory is unsafe") from error
    try:
        yield directory_fd, _cache_root()
    finally:
        os.close(directory_fd)


def _validate_archive_metadata(metadata: os.stat_result, expected_size: int | None = None) -> None:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise RuntimeError("secret scanner release archive is not a private regular file")
    if metadata.st_size <= 0 or metadata.st_size > MAX_RELEASE_ARCHIVE_BYTES:
        raise RuntimeError("secret scanner release archive exceeds the size limit")
    if expected_size is not None and metadata.st_size != expected_size:
        raise RuntimeError("secret scanner release archive size did not match")


def _validate_lock_metadata(metadata: os.stat_result) -> None:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise RuntimeError("secret scanner cache lock is unsafe")


@contextmanager
def _open_verified_archive_fd(
    directory_fd: int,
    filename: str,
    expected_sha256: str,
    *,
    expected_size: int | None = None,
) -> Iterator[BinaryIO]:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0)
    try:
        raw_fd = os.open(filename, flags, dir_fd=directory_fd)
    except OSError as error:
        raise RuntimeError("secret scanner release archive is unavailable") from error
    try:
        before = os.fstat(raw_fd)
        _validate_archive_metadata(before, expected_size)
    except Exception:
        os.close(raw_fd)
        raise
    archive = os.fdopen(raw_fd, "rb")
    try:
        digest = hashlib.sha256()
        while chunk := archive.read(DOWNLOAD_CHUNK_BYTES):
            digest.update(chunk)
        after = os.fstat(raw_fd)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ) or digest.hexdigest() != expected_sha256:
            raise RuntimeError("secret scanner release archive checksum did not match")
        archive.seek(0)
        yield archive
    finally:
        archive.close()


@contextmanager
def _open_verified_archive(
    path: Path, expected_sha256: str, *, expected_size: int | None = None
) -> Iterator[BinaryIO]:
    try:
        directory_fd = os.open(
            path.parent,
            os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError as error:
        raise RuntimeError("secret scanner release archive is unavailable") from error
    try:
        with _open_verified_archive_fd(
            directory_fd,
            path.name,
            expected_sha256,
            expected_size=expected_size,
        ) as archive:
            yield archive
    finally:
        os.close(directory_fd)


def _ensure_cached_archive(asset: ReleaseAsset) -> Path:
    deadline = time.monotonic() + RELEASE_DOWNLOAD_TIMEOUT_SECONDS
    with _open_cache_directory() as (directory_fd, cache_root):
        lock_name = ".download.lock"
        lock_fd = os.open(
            lock_name,
            os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=directory_fd,
        )
        try:
            _validate_lock_metadata(os.fstat(lock_fd))
        except RuntimeError:
            os.close(lock_fd)
            raise
        locked = False
        try:
            while True:
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    locked = True
                    break
                except BlockingIOError as error:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise RuntimeError("secret scanner cache lock timed out") from error
                    time.sleep(min(0.05, remaining))
            try:
                with _open_verified_archive_fd(
                    directory_fd,
                    asset.filename,
                    asset.sha256,
                    expected_size=asset.archive_size,
                ):
                    return cache_root / asset.filename
            except RuntimeError as error:
                try:
                    os.stat(asset.filename, dir_fd=directory_fd, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    raise error

            temporary_name = f".{asset.filename}.{secrets.token_hex(12)}.partial"
            temporary_fd = os.open(
                temporary_name,
                os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=directory_fd,
            )
            try:
                with os.fdopen(os.dup(temporary_fd), "w+b") as destination:
                    _download_release_archive(
                        asset,
                        destination,
                        deadline=deadline,
                    )
                    destination.flush()
                    os.fsync(destination.fileno())
                os.lseek(temporary_fd, 0, os.SEEK_SET)
                with os.fdopen(os.dup(temporary_fd), "rb") as downloaded:
                    digest = hashlib.sha256()
                    while chunk := downloaded.read(DOWNLOAD_CHUNK_BYTES):
                        digest.update(chunk)
                _validate_archive_metadata(os.fstat(temporary_fd), asset.archive_size)
                if digest.hexdigest() != asset.sha256:
                    raise RuntimeError("secret scanner release checksum did not match")
                try:
                    os.stat(asset.filename, dir_fd=directory_fd, follow_symlinks=False)
                except FileNotFoundError:
                    os.rename(
                        temporary_name,
                        asset.filename,
                        src_dir_fd=directory_fd,
                        dst_dir_fd=directory_fd,
                    )
                else:
                    with _open_verified_archive_fd(
                        directory_fd,
                        asset.filename,
                        asset.sha256,
                        expected_size=asset.archive_size,
                    ):
                        pass
                    os.unlink(temporary_name, dir_fd=directory_fd)
                os.fsync(directory_fd)
            except Exception:
                with suppress(FileNotFoundError):
                    os.unlink(temporary_name, dir_fd=directory_fd)
                raise
            finally:
                os.close(temporary_fd)
            return cache_root / asset.filename
        finally:
            if locked:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            os.close(lock_fd)


def _decompress_release_archive(
    archive: BinaryIO,
    destination: BinaryIO,
    asset: ReleaseAsset,
) -> None:
    decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
    total = 0
    reached_end = False
    while chunk := archive.read(DOWNLOAD_CHUNK_BYTES):
        pending = chunk
        while pending:
            remaining = MAX_RELEASE_DECOMPRESSED_BYTES - total
            output = decompressor.decompress(pending, remaining + 1)
            total += len(output)
            if total > MAX_RELEASE_DECOMPRESSED_BYTES:
                raise RuntimeError("invalid secret scanner archive")
            destination.write(output)
            pending = decompressor.unconsumed_tail
            if decompressor.unused_data:
                raise RuntimeError("invalid secret scanner archive")
            if decompressor.eof:
                reached_end = True
                if pending or archive.read(1):
                    raise RuntimeError("invalid secret scanner archive")
                break
            if not pending:
                break
        if reached_end:
            break
    if not reached_end:
        raise RuntimeError("invalid secret scanner archive")
    flushed = decompressor.flush()
    total += len(flushed)
    if total > MAX_RELEASE_DECOMPRESSED_BYTES:
        raise RuntimeError("invalid secret scanner archive")
    destination.write(flushed)
    if total != asset.tar_size:
        raise RuntimeError("invalid secret scanner archive")
    destination.flush()
    destination.seek(0)


def _validate_binary_header(scanner: BinaryIO, asset: ReleaseAsset) -> None:
    scanner.seek(0)
    header = scanner.read(32)
    if asset.binary_format == "macho":
        if len(header) < 8 or header[:4] != b"\xcf\xfa\xed\xfe":
            raise RuntimeError("invalid secret scanner archive")
        machine_code = struct.unpack("<I", header[4:8])[0]
    elif asset.binary_format == "elf":
        if len(header) < 20 or header[:6] != b"\x7fELF\x02\x01":
            raise RuntimeError("invalid secret scanner archive")
        machine_code = struct.unpack("<H", header[18:20])[0]
    else:
        raise RuntimeError("invalid secret scanner archive")
    if machine_code != asset.machine_code:
        raise RuntimeError("invalid secret scanner archive")
    scanner.seek(0)


def _parse_tar_octal(field: bytes) -> int:
    value = field.rstrip(b"\0 ").lstrip(b" ")
    if not value or any(character not in b"01234567" for character in value):
        raise RuntimeError("invalid secret scanner archive")
    return int(value, 8)


def _parse_tar_name(field: bytes) -> str:
    if b"\0" in field:
        visible, padding = field.split(b"\0", 1)
        if any(padding):
            raise RuntimeError("invalid secret scanner archive")
    else:
        visible = field
    try:
        return visible.decode("utf-8")
    except UnicodeDecodeError as error:
        raise RuntimeError("invalid secret scanner archive") from error


def _validate_raw_tar(tar_stream: BinaryIO, asset: ReleaseAsset) -> None:
    expected_inventory = (
        ("LICENSE", 0o644, 1_069),
        ("README.md", 0o644, 29_998),
        ("gitleaks", 0o755, asset.binary_size),
    )
    inventory: list[tuple[str, int, int]] = []
    collision_keys: set[str] = set()
    tar_stream.seek(0)
    while True:
        header = tar_stream.read(512)
        if len(header) != 512:
            raise RuntimeError("invalid secret scanner archive")
        if header == bytes(512):
            if tar_stream.read(512) != bytes(512):
                raise RuntimeError("invalid secret scanner archive")
            if any(tar_stream.read()):
                raise RuntimeError("invalid secret scanner archive")
            break
        if len(inventory) >= len(expected_inventory):
            raise RuntimeError("invalid secret scanner archive")
        stored_checksum = _parse_tar_octal(header[148:156])
        checksum_header = header[:148] + (b" " * 8) + header[156:]
        if sum(checksum_header) != stored_checksum:
            raise RuntimeError("invalid secret scanner archive")
        if header[257:263] != b"ustar\0" or header[263:265] != b"00":
            raise RuntimeError("invalid secret scanner archive")
        if header[156:157] not in (b"0", b"\0"):
            raise RuntimeError("invalid secret scanner archive")
        name = _parse_tar_name(header[:100])
        prefix = _parse_tar_name(header[345:500])
        if prefix:
            name = f"{prefix}/{name}"
        pure_name = PurePosixPath(name)
        collision_key = unicodedata.normalize("NFC", name).casefold()
        if (
            not name
            or name.startswith("/")
            or "\\" in name
            or any(part in ("", ".", "..") for part in pure_name.parts)
            or collision_key in collision_keys
        ):
            raise RuntimeError("invalid secret scanner archive")
        collision_keys.add(collision_key)
        mode = _parse_tar_octal(header[100:108])
        size = _parse_tar_octal(header[124:136])
        if size > MAX_GITLEAKS_BINARY_BYTES:
            raise RuntimeError("invalid secret scanner archive")
        inventory.append((name, mode, size))
        if len(tar_stream.read(size)) != size:
            raise RuntimeError("invalid secret scanner archive")
        padding_size = (-size) % 512
        padding = tar_stream.read(padding_size)
        if len(padding) != padding_size or any(padding):
            raise RuntimeError("invalid secret scanner archive")
    if tuple(inventory) != expected_inventory:
        raise RuntimeError("invalid secret scanner archive")
    tar_stream.seek(0)


def _extract_scanner(archive: BinaryIO, destination: Path, asset: ReleaseAsset) -> Path:
    expected_inventory = (
        ("LICENSE", 0o644, 1_069),
        ("README.md", 0o644, 29_998),
        ("gitleaks", 0o755, asset.binary_size),
    )
    try:
        with tempfile.TemporaryFile(mode="w+b", dir=destination) as tar_stream:
            _decompress_release_archive(archive, tar_stream, asset)
            _validate_raw_tar(tar_stream, asset)
            with tarfile.open(fileobj=tar_stream, mode="r:") as release:
                members = release.getmembers()
                inventory = tuple(
                    (member.name, member.mode, member.size)
                    for member in members
                    if member.type in (tarfile.REGTYPE, tarfile.AREGTYPE)
                )
                if (
                    len(members) != len(expected_inventory)
                    or inventory != expected_inventory
                    or any(
                        member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE)
                        or member.pax_headers
                        or member.sparse is not None
                        or member.linkname
                        or member.name.startswith("/")
                        or "\\" in member.name
                        or any(part in ("", ".", "..") for part in PurePosixPath(member.name).parts)
                        for member in members
                    )
                ):
                    raise RuntimeError("invalid secret scanner archive")
                scanner_member = members[2]
                if scanner_member.size <= 0 or scanner_member.size > MAX_GITLEAKS_BINARY_BYTES:
                    raise RuntimeError("invalid secret scanner archive")
                source = release.extractfile(scanner_member)
                if source is None:
                    raise RuntimeError("invalid secret scanner archive")
                scanner_path = destination / "gitleaks"
                output_fd = os.open(
                    scanner_path,
                    os.O_RDWR
                    | os.O_CREAT
                    | os.O_EXCL
                    | os.O_CLOEXEC
                    | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                )
                with os.fdopen(output_fd, "w+b") as output:
                    remaining = scanner_member.size
                    while remaining:
                        chunk = source.read(min(DOWNLOAD_CHUNK_BYTES, remaining))
                        if not chunk:
                            raise RuntimeError("invalid secret scanner archive")
                        output.write(chunk)
                        remaining -= len(chunk)
                    if source.read(1):
                        raise RuntimeError("invalid secret scanner archive")
                    output.flush()
                    os.fsync(output.fileno())
                    _validate_binary_header(output, asset)
                    os.fchmod(output.fileno(), 0o700)
    except (OSError, EOFError, tarfile.TarError, zlib.error) as error:
        raise RuntimeError("invalid secret scanner archive") from error
    return scanner_path


@contextmanager
def _temporary_scanner(archive_path: Path, asset: ReleaseAsset) -> Iterator[Path]:
    with tempfile.TemporaryDirectory(
        prefix=".gitleaks-exec-",
        dir=archive_path.parent,
    ) as temporary:
        destination = Path(temporary)
        destination.chmod(0o700)
        with _open_verified_archive(
            archive_path,
            asset.sha256,
            expected_size=asset.archive_size,
        ) as archive:
            scanner = _extract_scanner(archive, destination, asset)
        yield scanner.resolve(strict=True)


@contextmanager
def _temporary_cached_scanner(asset: ReleaseAsset) -> Iterator[Path]:
    _ensure_cached_archive(asset)
    with (
        _open_cache_directory() as (directory_fd, cache_root),
        tempfile.TemporaryDirectory(prefix=".gitleaks-exec-", dir=cache_root) as temporary,
    ):
        destination = Path(temporary)
        _validate_private_directory(destination.stat(), exact_mode=True)
        with _open_verified_archive_fd(
            directory_fd,
            asset.filename,
            asset.sha256,
            expected_size=asset.archive_size,
        ) as archive:
            scanner = _extract_scanner(archive, destination, asset)
        yield scanner.resolve(strict=True)


def git_environment(isolated_home: Path) -> dict[str, str]:
    """Create a Git environment without ambient selectors or external configuration."""

    environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    environment.update(
        {
            "GIT_ATTR_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "HOME": str(isolated_home),
            "LC_ALL": "C",
            "XDG_CONFIG_HOME": str(isolated_home),
        }
    )
    return environment


def write_scanner_policy(directory: Path) -> Path:
    """Bind scans to the pinned scanner's built-in policy."""

    policy = directory / "policy.toml"
    policy.write_text(GITLEAKS_POLICY, encoding="utf-8")
    policy.chmod(0o600)
    return policy


def _remaining_timeout(deadline: float, maximum: int) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise RuntimeError("secret scanner repository snapshot timed out")
    return min(remaining, float(maximum))


def _run_discovery_git(
    executable: str,
    repository: Path,
    arguments: list[str],
    *,
    environment: dict[str, str],
    deadline: float,
) -> bytes:
    try:
        result = subprocess.run(  # noqa: S603  # Git is resolved to an absolute executable.
            [executable, "--no-pager", "--no-replace-objects", "-C", str(repository), *arguments],
            check=False,
            capture_output=True,
            env=environment,
            timeout=_remaining_timeout(deadline, GIT_COMMAND_TIMEOUT_SECONDS),
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RuntimeError("Git could not resolve the repository boundary") from error
    if result.returncode != 0 or len(result.stdout) > MAX_GIT_OUTPUT_BYTES:
        raise RuntimeError("Git could not resolve the repository boundary")
    return result.stdout


def _open_repository(repository: Path, *, isolated_home: Path, deadline: float) -> GitRepository:
    try:
        requested_root = repository.resolve(strict=True)
    except OSError as error:
        raise RuntimeError("secret scan repository is unavailable") from error
    if not requested_root.is_dir():
        raise RuntimeError("secret scan repository is unavailable")

    executable = shutil.which("git")
    if executable is None:
        raise RuntimeError("Git is unavailable for secret scanning")
    try:
        executable = str(Path(executable).resolve(strict=True))
    except OSError as error:
        raise RuntimeError("Git is unavailable for secret scanning") from error

    environment = git_environment(isolated_home)
    root_output = _run_discovery_git(
        executable,
        requested_root,
        ["rev-parse", "--show-toplevel"],
        environment=environment,
        deadline=deadline,
    )
    git_dir_output = _run_discovery_git(
        executable,
        requested_root,
        ["rev-parse", "--absolute-git-dir"],
        environment=environment,
        deadline=deadline,
    )
    try:
        canonical_root = Path(root_output.decode("utf-8").strip()).resolve(strict=True)
        canonical_git_dir = Path(git_dir_output.decode("utf-8").strip()).resolve(strict=True)
    except (OSError, UnicodeDecodeError) as error:
        raise RuntimeError("Git returned an invalid repository boundary") from error
    if canonical_root != requested_root or not canonical_git_dir.is_dir():
        raise RuntimeError("Git returned an invalid repository boundary")

    repository_boundary = GitRepository(
        executable,
        canonical_root,
        canonical_git_dir,
        environment,
    )
    object_format_output = _captured_stdout(
        _run_bound_git(
            repository_boundary,
            ["rev-parse", "--show-object-format"],
            deadline=deadline,
        )
    )
    try:
        object_format = object_format_output.decode("ascii").strip()
    except UnicodeDecodeError as error:
        raise RuntimeError("Git returned an unsupported object format") from error
    if object_format not in ("sha1", "sha256"):
        raise RuntimeError("Git returned an unsupported object format")
    return GitRepository(
        executable,
        canonical_root,
        canonical_git_dir,
        environment,
        object_format,
    )


def _run_bound_git(
    repository: GitRepository,
    arguments: list[str],
    *,
    deadline: float,
    stdout: int | BinaryIO = subprocess.PIPE,
) -> subprocess.CompletedProcess[bytes]:
    command = [
        repository.executable,
        "--no-pager",
        "--no-replace-objects",
        f"--git-dir={repository.git_dir}",
        f"--work-tree={repository.root}",
        "-c",
        f"core.attributesFile={os.devnull}",
        "-c",
        f"core.excludesFile={os.devnull}",
        "-c",
        "core.fsmonitor=false",
        *arguments,
    ]
    try:
        result = subprocess.run(  # noqa: S603  # Git is resolved to an absolute executable.
            command,
            check=False,
            env=repository.environment,
            stderr=subprocess.PIPE,
            stdout=stdout,
            timeout=_remaining_timeout(deadline, GIT_COMMAND_TIMEOUT_SECONDS),
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RuntimeError("Git could not capture repository content") from error
    if result.returncode != 0:
        raise RuntimeError("Git could not capture repository content")
    if isinstance(result.stdout, bytes) and len(result.stdout) > MAX_GIT_OUTPUT_BYTES:
        raise RuntimeError("Git repository metadata exceeds the scanner limit")
    return result


def _captured_stdout(result: subprocess.CompletedProcess[bytes]) -> bytes:
    if not isinstance(result.stdout, bytes):
        raise RuntimeError("Git did not return captured repository metadata")
    return result.stdout


def _blob_object_id(path: Path, size: int, object_format: str) -> str:
    digest = hashlib.new(object_format)
    digest.update(f"blob {size}\0".encode("ascii"))
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_object_id(value: str) -> None:
    if len(value) not in (40, 64) or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise RuntimeError("Git returned an invalid object identifier")


def _validate_entry_path(raw_path: bytes, collision_keys: set[str]) -> str:
    try:
        path = raw_path.decode("utf-8")
    except UnicodeDecodeError as error:
        raise RuntimeError("Git tree contains a non-UTF-8 path") from error
    pure_path = PurePosixPath(path)
    if (
        not path
        or path.startswith("/")
        or "\\" in path
        or any(part in ("", ".", "..") for part in pure_path.parts)
    ):
        raise RuntimeError("Git tree contains an unsafe path")
    if any(part in REPOSITORY_CONTROL_FILES for part in pure_path.parts):
        raise RuntimeError("repository secret-scanner control file is unsupported")
    collision_key = unicodedata.normalize("NFC", path).casefold()
    if collision_key in collision_keys:
        raise RuntimeError("Git tree contains colliding paths")
    collision_keys.add(collision_key)
    return path


def _list_tree(
    repository: GitRepository, tree: str, *, deadline: float
) -> tuple[list[TreeEntry], int]:
    _validate_object_id(tree)
    result = _run_bound_git(
        repository,
        ["ls-tree", "-rz", "-l", "--full-tree", tree],
        deadline=deadline,
    )
    output = _captured_stdout(result)
    entries: list[TreeEntry] = []
    total_bytes = 0
    collision_keys: set[str] = set()
    records = output.split(b"\0")
    if records[-1] != b"":
        raise RuntimeError("Git returned a malformed tree listing")
    for record in records[:-1]:
        try:
            metadata, raw_path = record.split(b"\t", 1)
            raw_mode, raw_type, raw_object_id, raw_size = metadata.split()
            mode = raw_mode.decode("ascii")
            object_type = raw_type.decode("ascii")
            object_id = raw_object_id.decode("ascii")
            size = int(raw_size)
        except (UnicodeDecodeError, ValueError) as error:
            raise RuntimeError("Git returned a malformed tree listing") from error
        if mode not in REGULAR_FILE_MODES or object_type != "blob" or size < 0:
            raise RuntimeError("Git tree contains an unsupported Git tree entry")
        _validate_object_id(object_id)
        path = _validate_entry_path(raw_path, collision_keys)
        entries.append(TreeEntry(mode, object_id, size, path))
        total_bytes += size
        if len(entries) > MAX_TREE_ENTRIES or total_bytes > MAX_SNAPSHOT_BYTES:
            raise RuntimeError("Git tree exceeds the scanner snapshot limit")
    return entries, total_bytes


def _materialize_tree(
    repository: GitRepository,
    tree: str,
    destination: Path,
    *,
    deadline: float,
) -> tuple[int, int]:
    entries, total_bytes = _list_tree(repository, tree, deadline=deadline)
    destination.mkdir(mode=0o700)
    expected_paths = {entry.path for entry in entries}
    try:
        for entry in entries:
            target = destination.joinpath(*PurePosixPath(entry.path).parts)
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with target.open("xb") as output:
                _run_bound_git(
                    repository,
                    ["cat-file", "blob", entry.object_id],
                    deadline=deadline,
                    stdout=output,
                )
            metadata = target.lstat()
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size != entry.size:
                raise RuntimeError("Git blob materialization did not match the captured tree")
            if _blob_object_id(target, entry.size, repository.object_format) != entry.object_id:
                raise RuntimeError("Git blob materialization did not match its object identifier")
            target.chmod(0o700 if entry.mode == "100755" else 0o600)
    except OSError as error:
        raise RuntimeError("Git tree could not be materialized safely") from error

    actual_paths: set[str] = set()
    for root, directories, files in os.walk(destination, followlinks=False):
        if any(Path(root, directory).is_symlink() for directory in directories):
            raise RuntimeError("Git tree materialization contains a symlink")
        for filename in files:
            path = Path(root, filename)
            if not stat.S_ISREG(path.lstat().st_mode):
                raise RuntimeError("Git tree materialization contains a nonregular file")
            actual_paths.add(path.relative_to(destination).as_posix())
    if actual_paths != expected_paths:
        raise RuntimeError("Git tree materialization entry set did not match")
    return len(entries), total_bytes


def _captured_trees(repository: GitRepository, *, scope: str, deadline: float) -> list[str]:
    if scope == "staged":
        result = _run_bound_git(repository, ["write-tree"], deadline=deadline)
        output = _captured_stdout(result)
        try:
            tree = output.decode("ascii").strip()
        except UnicodeDecodeError as error:
            raise RuntimeError("Git returned an invalid index tree") from error
        _validate_object_id(tree)
        return [tree]

    result = _run_bound_git(
        repository,
        ["log", "--all", "--format=%T", "--no-show-signature"],
        deadline=deadline,
    )
    output = _captured_stdout(result)
    try:
        candidates = output.decode("ascii").splitlines()
    except UnicodeDecodeError as error:
        raise RuntimeError("Git returned an invalid history tree list") from error
    trees: list[str] = []
    seen: set[str] = set()
    for tree in candidates:
        _validate_object_id(tree)
        if tree not in seen:
            seen.add(tree)
            trees.append(tree)
        if len(trees) > MAX_HISTORY_TREES:
            raise RuntimeError("Git history exceeds the scanner tree limit")
    if not trees:
        raise RuntimeError("Git history contains no commit trees")
    return trees


def verify_version(scanner: str, isolated_home: Path) -> None:
    """Require the checksum-pinned executable to identify the locked release."""

    try:
        result = subprocess.run(  # noqa: S603  # Scanner came from a verified release archive.
            [scanner, "version"],
            check=False,
            close_fds=True,
            env=scanner_environment(isolated_home),
            stderr=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RuntimeError("secret scanner version check could not complete") from error
    if result.returncode != 0 or len(result.stdout) > 256:
        raise RuntimeError("secret scanner version check failed")
    try:
        version = result.stdout.decode("ascii").strip()
    except UnicodeDecodeError as error:
        raise RuntimeError("secret scanner version check failed") from error
    if version != GITLEAKS_VERSION:
        raise RuntimeError("secret scanner version did not match the locked release")


def verify_canary(scanner: str) -> None:
    """Require Gitleaks to report exactly one leak-style exit for a synthetic token."""

    with tempfile.TemporaryDirectory(prefix="cairnvm-gitleaks-canary-") as temporary:
        temporary_path = Path(temporary)
        policy = write_scanner_policy(temporary_path)
        source = temporary_path / "canary.zip"
        encoded = base64.b64encode(build_canary().encode("ascii"))
        with zipfile.ZipFile(source, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("canary.txt", encoded)
        try:
            result = subprocess.run(  # noqa: S603  # Scanner is resolved without a shell.
                [
                    scanner,
                    "dir",
                    "--config",
                    str(policy),
                    "--redact",
                    "--no-banner",
                    "--max-archive-depth",
                    ARCHIVE_DEPTH,
                    "--max-decode-depth",
                    DECODE_DEPTH,
                    str(source),
                ],
                check=False,
                close_fds=True,
                env=scanner_environment(temporary_path),
                stderr=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                timeout=30,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise RuntimeError("secret scanner canary could not complete") from error

    if result.returncode != 1:
        raise RuntimeError("secret scanner failed to detect its generated canary")


def _scan_snapshot(scanner: str, snapshot: Path, policy_directory: Path, *, deadline: float) -> int:
    policy = write_scanner_policy(policy_directory)
    disabled_ignore_path = policy_directory / "no-gitleaksignore"
    scanner_home = policy_directory / "home"
    scanner_home.mkdir(mode=0o700, exist_ok=True)
    _validate_private_directory(scanner_home.stat(), exact_mode=True)
    timeout = _remaining_timeout(deadline, REPOSITORY_SCAN_TIMEOUT_SECONDS)
    command = [
        scanner,
        "dir",
        "--config",
        str(policy),
        "--gitleaks-ignore-path",
        str(disabled_ignore_path),
        "--ignore-gitleaks-allow",
        "--redact",
        "--no-banner",
        "--no-color",
        "--max-archive-depth",
        ARCHIVE_DEPTH,
        "--max-decode-depth",
        DECODE_DEPTH,
        "--timeout",
        str(max(1, int(timeout))),
        str(snapshot),
    ]
    try:
        result = subprocess.run(  # noqa: S603  # Scanner is resolved without a shell.
            command,
            check=False,
            close_fds=True,
            env=scanner_environment(scanner_home),
            stderr=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RuntimeError("secret scanner could not scan repository content") from error
    if result.returncode not in (0, 1):
        raise RuntimeError("secret scanner failed while scanning repository content")
    return result.returncode


def scan_repository(scanner: str | Path, *, scope: str, repository: Path = REPOSITORY_ROOT) -> int:
    """Scan the complete canonical index tree or every unique commit tree."""

    if scope not in ("staged", "history"):
        raise RuntimeError(f"unsupported secret scan scope: {scope}")

    deadline = time.monotonic() + REPOSITORY_SCAN_TIMEOUT_SECONDS
    with tempfile.TemporaryDirectory(prefix="cairnvm-gitleaks-snapshot-") as temporary:
        temporary_path = Path(temporary)
        isolated_home = temporary_path / "home"
        snapshot = temporary_path / "snapshot"
        policy_directory = temporary_path / "policy"
        isolated_home.mkdir(mode=0o700)
        snapshot.mkdir(mode=0o700)
        policy_directory.mkdir(mode=0o700)

        git_repository = _open_repository(
            repository,
            isolated_home=isolated_home,
            deadline=deadline,
        )
        trees = _captured_trees(git_repository, scope=scope, deadline=deadline)
        total_entries = 0
        total_bytes = 0
        for index, tree in enumerate(trees):
            destination = snapshot / f"tree-{index:06d}"
            entries, size = _materialize_tree(
                git_repository,
                tree,
                destination,
                deadline=deadline,
            )
            total_entries += entries
            total_bytes += size
            if total_entries > MAX_TREE_ENTRIES or total_bytes > MAX_SNAPSHOT_BYTES:
                raise RuntimeError("Git repository snapshots exceed the scanner limit")

        result = _scan_snapshot(str(scanner), snapshot, policy_directory, deadline=deadline)
        if scope == "staged":
            final_tree = _captured_trees(
                git_repository,
                scope="staged",
                deadline=deadline,
            )[0]
            if final_tree != trees[0]:
                raise RuntimeError("canonical index changed during secret scanning")
        return result


def main() -> int:
    """Verify the scanner, then run the selected staged or history scope over exact trees."""

    try:
        asset = _select_release_asset()
        with _temporary_cached_scanner(asset) as scanner:
            verify_version(str(scanner), scanner.parent)
            verify_canary(str(scanner))
            return scan_repository(
                scanner,
                scope=os.environ.get("CAIRNVM_SECRET_SCAN_SCOPE", "staged"),
                repository=REPOSITORY_ROOT,
            )
    except (OSError, RuntimeError) as error:
        print(str(error), file=sys.stderr)
        return 2


def _internal_download_main(arguments: list[str]) -> int:
    if len(arguments) != 2:
        return 2
    try:
        asset = _select_release_asset(system=arguments[0], machine=arguments[1])
        _download_release_archive_child(
            asset,
            sys.stdout.buffer,
            deadline=time.monotonic() + RELEASE_DOWNLOAD_TIMEOUT_SECONDS,
        )
    except (OSError, RuntimeError):
        return 2
    return 0


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "--internal-download":
        raise SystemExit(_internal_download_main(sys.argv[2:]))
    raise SystemExit(main())
