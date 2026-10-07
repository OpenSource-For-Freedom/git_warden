"""In-container entrypoint for statically analyzing one unpacked registry package.

Huginn unpacks each new npm / PyPI / RubyGems / crates / Packagist / Go release in
a no-network container and runs this over the unpacked tree (read-only), so the
same Tier-2 rules that confirm malicious repositories and images also judge
packages. Nothing is installed or executed.

    python -m git_warden.package_entry /scan/src --name left-pad --ecosystem npm \
        --work /work

The tree is copied into ``--work`` (a tmpfs) first. In a repository, ``dist/``,
``build/`` and ``out/`` are generated output and skipped; in a published package
they are the code that actually runs, so they are renamed (``pkg_dist`` ...) to
be scanned. Prints one JSON object on stdout.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from .sandbox_entry import _result_to_dict
from .scanning.tier2 import analyze_repo

_GENERATED_DIRS = {"dist", "build", "out"}
_SKIP_COPY = shutil.ignore_patterns(".git", "node_modules")
_MAX_FINDINGS = 200


def expose_package_dirs(root: Path) -> list[str]:
    """Rename generated-output dirs so the scanners read them. Returns what moved."""
    # Deepest first, so a nested dist/ is renamed before its parent path changes.
    for path in sorted(root.rglob("*"), key=lambda p: len(p.parts), reverse=True):
        if path.is_dir() and not path.is_symlink() and path.name in _GENERATED_DIRS:
            target = path.with_name(f"pkg_{path.name}")
            if not target.exists():
                path.rename(target)
    return sorted(str(p.relative_to(root)) for p in root.rglob("pkg_*")
                  if p.is_dir() and p.name[4:] in _GENERATED_DIRS)


def analyze_package(src: Path, name: str, ecosystem: str, work: Path | None = None,
                    *, runner=subprocess.run) -> dict:
    tmp = Path(tempfile.mkdtemp(prefix="pkg-", dir=str(work) if work else None))
    try:
        root = tmp / "pkg"
        shutil.copytree(src, root, symlinks=True, ignore=_SKIP_COPY)
        exposed = expose_package_dirs(root)
        result = analyze_repo(root, f"{ecosystem}:{name}", runner=runner)
        out = _result_to_dict(result)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    out["bash_findings"] = out["bash_findings"][:_MAX_FINDINGS]
    out["package"] = {"name": name, "ecosystem": ecosystem, "exposed_dirs": exposed}
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("src", type=Path)
    ap.add_argument("--name", required=True)
    ap.add_argument("--ecosystem", required=True)
    ap.add_argument("--work", type=Path, default=None)
    args = ap.parse_args(argv)
    if not args.src.is_dir():
        print(json.dumps({"error": f"not a directory: {args.src}"}))
        return 2
    print(json.dumps(analyze_package(args.src, args.name, args.ecosystem, args.work)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
