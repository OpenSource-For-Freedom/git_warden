"""Download, unpack and statically analyze one ``.vsix`` (sandbox side).

Runs INSIDE the hardened sandbox container (see ``sandbox_entry --vsix``). The
archive is fetched only from an allowlisted registry host, unpacked into the
container's tmpfs with zip-slip, size and entry-count guards, and analyzed with
Warden's existing Tier-2 rules plus VS Code extension-specific signals. Nothing
is ever executed: a ``.vsix`` is a zip of JavaScript and a manifest.
"""

from __future__ import annotations

import json
import re
import zipfile
from pathlib import Path, PurePosixPath
from urllib.parse import urljoin, urlsplit

from ..scanning.bash_scanner import BashFinding

# Registry hosts a download (or its redirect) may come from. Open VSX serves the
# API on open-vsx.org and redirects file downloads to the Eclipse Foundation's
# content host (formerly its Azure blob storage).
ALLOWED_HOSTS = ("open-vsx.org", "openvsx.eclipsecontent.org",
                 "openvsxorg.blob.core.windows.net",
                 # Visual Studio Marketplace: the gallery API and its asset CDN
                 # (<publisher>.gallerycdn.vsassets.io / gallery.vsassets.io).
                 "marketplace.visualstudio.com", "gallerycdn.vsassets.io",
                 "gallery.vsassets.io")
MAX_VSIX_BYTES = 150_000_000
MAX_UNPACKED_BYTES = 400_000_000
MAX_ENTRIES = 30_000
_MAX_REDIRECTS = 5

# Directories Warden normally skips as generated output. In an extension the
# compiled entry point lives there (dist/extension.js), so it is first-party code.
_GENERATED_DIRS = {"dist", "out", "build"}
_NATIVE_SUFFIXES = {".exe", ".dll", ".so", ".dylib", ".node", ".bin", ".scr", ".msi"}
_SCRIPT_SUFFIXES = {".ps1", ".bat", ".cmd", ".vbs", ".sh"}
# Contribution points that need no code at all: a pure theme / snippet / grammar
# pack. Such a pack that ALSO ships an activated code entry point is the classic
# disguise (a "theme" that runs a stealer on startup).
_DECLARATIVE_CONTRIBUTES = {"themes", "iconThemes", "productIconThemes", "snippets",
                            "grammars", "languages", "colors", "jsonValidation"}


class VsixError(RuntimeError):
    """The archive could not be fetched or safely unpacked."""


def host_allowed(url: str) -> bool:
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    return parts.scheme == "https" and any(
        host == h or host.endswith("." + h) for h in ALLOWED_HOSTS)


def download(url: str, dest: Path, *, session=None, max_bytes: int = MAX_VSIX_BYTES) -> Path:
    """Stream ``url`` to ``dest``, following redirects only to allowlisted hosts."""
    import requests

    session = session or requests.Session()
    for _ in range(_MAX_REDIRECTS + 1):
        if not host_allowed(url):
            raise VsixError(f"download host not allowlisted: {urlsplit(url).hostname}")
        r = session.get(url, stream=True, allow_redirects=False, timeout=60)
        if r.status_code in (301, 302, 303, 307, 308):
            url = urljoin(url, r.headers.get("Location", ""))
            r.close()
            continue
        if r.status_code != 200:
            raise VsixError(f"download failed: HTTP {r.status_code}")
        total = 0
        with dest.open("wb") as fh:
            for chunk in r.iter_content(64 * 1024):
                total += len(chunk)
                if total > max_bytes:
                    raise VsixError("vsix exceeds size limit")
                fh.write(chunk)
        return dest
    raise VsixError("too many redirects")


def ensure_zip(archive: Path, *, max_bytes: int = MAX_VSIX_BYTES) -> Path:
    """Undo a gzip transfer wrapper the Marketplace sometimes leaves on a .vsix.

    The gallery may serve the package gzip-compressed without a Content-Encoding
    header, so the bytes on disk are gzip, not zip. Decompress (bounded) in place.
    """
    import gzip

    with archive.open("rb") as fh:
        if fh.read(2) != b"\x1f\x8b":
            return archive
    out = archive.with_suffix(".unzipped")
    total = 0
    try:
        with gzip.open(archive, "rb") as src, out.open("wb") as dst:
            while chunk := src.read(64 * 1024):
                total += len(chunk)
                if total > max_bytes:
                    raise VsixError("vsix exceeds size limit")
                dst.write(chunk)
    except OSError as exc:
        raise VsixError("corrupt gzip wrapper") from exc
    out.replace(archive)
    return archive


def safe_extract(archive: Path, dest: Path) -> Path:
    """Unpack a vsix with zip-slip, symlink, bomb and entry-count guards."""
    dest = dest.resolve()
    try:
        zf = zipfile.ZipFile(archive)
    except zipfile.BadZipFile as exc:
        raise VsixError("not a zip archive") from exc
    with zf:
        infos = zf.infolist()
        if len(infos) > MAX_ENTRIES:
            raise VsixError("too many entries")
        if sum(i.file_size for i in infos) > MAX_UNPACKED_BYTES:
            raise VsixError("unpacked size exceeds limit")
        written = 0
        for info in infos:
            name = info.filename.replace("\\", "/")
            p = PurePosixPath(name)
            if (not p.parts or p.is_absolute() or ".." in p.parts
                    or ":" in p.parts[0]):          # drive letter (C:...)
                raise VsixError(f"unsafe path in archive: {name!r}")
            if (info.external_attr >> 16) & 0o170000 == 0o120000:
                continue  # symlink: never materialize
            target = (dest / p).resolve()
            if dest not in target.parents and target != dest:
                raise VsixError(f"path escapes destination: {name!r}")
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            # Count real decompressed bytes: a crafted header can understate size.
            with zf.open(info) as src, target.open("wb") as out:
                while chunk := src.read(64 * 1024):
                    written += len(chunk)
                    if written > MAX_UNPACKED_BYTES:
                        raise VsixError("unpacked size exceeds limit")
                    out.write(chunk)
    return dest


def _load_manifest(root: Path) -> dict:
    try:
        data = json.loads((root / "package.json").read_text(encoding="utf-8", errors="ignore"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _entry_points(manifest: dict) -> list[str]:
    return [str(manifest[k]) for k in ("main", "browser")
            if isinstance(manifest.get(k), str) and manifest.get(k)]


def expose_entry_dirs(root: Path, manifest: dict) -> None:
    """Rename the generated dir holding the entry point so Tier-2 scans it.

    ``dist/`` and ``out/`` are skipped as build output in repositories, but in a
    packaged extension that is where the code that actually runs lives.
    """
    for entry in _entry_points(manifest):
        parts = PurePosixPath(entry.lstrip("./")).parts
        if parts and parts[0] in _GENERATED_DIRS:
            src = root / parts[0]
            if src.is_dir():
                src.rename(root / f"entry_{parts[0]}")


def extension_signals(root: Path, manifest: dict) -> list[BashFinding]:
    """VS Code-specific context signals. None of these confirms on its own."""
    out: list[BashFinding] = []
    events = manifest.get("activationEvents") or []
    if isinstance(events, list):
        eager = [e for e in events if e in ("*", "onStartupFinished")]
        if eager:
            out.append(BashFinding("package.json", 0, "extension", "startup-activation",
                                   f"activationEvents: {eager}"))
    contributes = manifest.get("contributes") or {}
    if (_entry_points(manifest) and isinstance(contributes, dict) and contributes
            and set(contributes) <= _DECLARATIVE_CONTRIBUTES):
        out.append(BashFinding("package.json", 0, "extension", "declarative-pack-with-code",
                               f"contributes only {sorted(contributes)} but ships "
                               f"code entry {_entry_points(manifest)}"))
    for path in root.rglob("*"):
        if not path.is_file() or "node_modules" in path.parts:
            continue
        rel = str(path.relative_to(root)).replace("\\", "/")
        suffix = path.suffix.lower()
        if suffix in _NATIVE_SUFFIXES:
            out.append(BashFinding(rel, 0, "extension", "bundled-native-binary", rel))
        elif suffix in _SCRIPT_SUFFIXES:
            out.append(BashFinding(rel, 0, "extension", "bundled-script", rel))
    return out


_VERSION = re.compile(r"^[0-9A-Za-z.+-]{1,64}$")


def analyze_extension(ext_root: Path, ext_id: str, *, runner=None) -> dict:
    """Tier-2 analysis of an unpacked extension directory; returns wire JSON."""
    import subprocess

    from ..sandbox_entry import _result_to_dict
    from ..scanning.tier2 import analyze_repo

    manifest = _load_manifest(ext_root)
    expose_entry_dirs(ext_root, manifest)
    result = analyze_repo(ext_root, ext_id, runner=runner or subprocess.run)
    signals = extension_signals(ext_root, manifest)
    result.bash_findings = list(result.bash_findings) + signals
    out = _result_to_dict(result)
    version = str(manifest.get("version") or "")
    out["extension"] = {
        "version": version if _VERSION.fullmatch(version) else "",
        "publisher": str(manifest.get("publisher") or "")[:128],
        "activation_events": [str(e)[:80] for e in (manifest.get("activationEvents") or [])
                              if isinstance(e, str)][:20],
        "entry_points": _entry_points(manifest),
        "signals": [f"{s.category}/{s.rule}" for s in signals],
    }
    return out
