"""Tests for the malware code-signature engine (novel-repo discovery)."""

from __future__ import annotations

import base64
import json

from git_warden import config
from git_warden.scanning.signatures import extract_code_signatures, load_seed_signatures


def _eval_atob(blob: bytes) -> str:
    return f"module.exports={{}};eval(atob('{base64.b64encode(blob).decode()}'))\n"


def test_extract_code_signatures_finds_eval_atob_stub(tmp_path):
    (tmp_path / "postcss.config.js").write_text(_eval_atob(b"x" * 200), encoding="utf-8")
    sigs = extract_code_signatures(tmp_path)
    assert sigs and all(len(s) >= 48 for s in sigs)
    # The signature is a chunk of the actual base64 payload (searchable on GitHub).
    full = base64.b64encode(b"x" * 200).decode()
    assert sigs[0] in full


def test_extract_ignores_short_atob(tmp_path):
    # A short atob (not a real obfuscated payload) is not a signature.
    (tmp_path / "a.js").write_text("eval(atob('c2hvcnQ='))", encoding="utf-8")
    assert extract_code_signatures(tmp_path) == []


def test_extract_ignores_vendored_and_test_files(tmp_path):
    payload = _eval_atob(b"y" * 200)
    dep = tmp_path / "node_modules" / "pkg"
    dep.mkdir(parents=True)
    (dep / "index.js").write_text(payload, encoding="utf-8")
    (tmp_path / "app.test.js").write_text(payload, encoding="utf-8")
    assert extract_code_signatures(tmp_path) == []


def test_load_seed_signatures(tmp_path):
    p = tmp_path / "sigs.json"
    p.write_text(json.dumps([
        {"name": "a", "query": "foo"}, {"name": "b", "query": "bar"}, {"nope": 1},
    ]), encoding="utf-8")
    assert load_seed_signatures(p) == ["foo", "bar"]


def test_load_seed_signatures_missing_file(tmp_path):
    assert load_seed_signatures(tmp_path / "nope.json") == []


def test_shipped_seed_signatures_load():
    # The version-controlled seed list parses and is non-empty.
    assert len(load_seed_signatures(config.MALWARE_SIGNATURES_PATH)) >= 1
