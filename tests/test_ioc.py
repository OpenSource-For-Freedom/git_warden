"""Tests for IOC extraction from OSM threat text."""

from __future__ import annotations

from git_warden.scanning.ioc import extract_iocs, is_attacker_host

SAMPLE = """
DESTINATION
  - discord-webhook: https://discord.com/api/webhooks/1516798168304586833/OqfteyxjlBFvGTt
EXFIL
  - Network Request to https://python-log.lapxa354.workers.dev/collect
  - mirror on https://github.com/some/repo (benign reference)
INDICATORS (IOCs)
  - payloadFileHash: ff1cebc61b7a24b04edcccf4642bed10e060deda15473c2e12328ea504ea2c52
  - telegram: https://api.telegram.org/bot12345:AAExfilToken/sendMessage
"""


def test_extracts_webhook_domain_hash_telegram():
    iocs = extract_iocs(SAMPLE)
    assert iocs.webhooks.get("discord.com/api/webhooks/1516798168304586833/OqfteyxjlBFvGTt")
    assert iocs.domains.get("python-log.lapxa354.workers.dev")
    assert "ff1cebc61b7a24b04edcccf4642bed10e060deda15473c2e12328ea504ea2c52" in iocs.hashes
    assert iocs.telegram.get("api.telegram.org/bot12345:AAExfilToken")


def test_benign_github_domain_filtered():
    iocs = extract_iocs(SAMPLE)
    assert not iocs.domains.get("github.com")


def test_merge_accumulates_counts():
    a = extract_iocs("exfil to https://evil.example.com/x")
    b = extract_iocs("exfil to https://evil.example.com/y")
    a.merge(b)
    assert a.domains["evil.example.com"] == 2


def test_domain_only_extracted_in_c2_context():
    # A URL mentioned outside an exfil/C2 context is NOT treated as an IOC.
    assert not extract_iocs("see https://docs.example.com/guide").domains.get("docs.example.com")
    assert extract_iocs("exfil to https://evil.example.com").domains.get("evil.example.com")


def test_empty_text_is_safe():
    iocs = extract_iocs(None)
    assert not iocs.searchable()


def test_is_attacker_host_patterns():
    # Ephemeral hosts and suspicious TLDs -> attacker-owned-looking.
    assert is_attacker_host("avamnrwqo7.rbmock.dev")
    assert is_attacker_host("python-log.lapxa354.workers.dev")
    assert is_attacker_host("flipboxstudio.info")
    # eval #10: Pages domains host millions of benign sites -> NOT attacker-host.
    assert not is_attacker_host("ddjidd564.github.io")
    assert not is_attacker_host("someproject.gitlab.io")
    # Corporate/cloud/common domains -> not searched.
    assert not is_attacker_host("management.azure.com")
    assert not is_attacker_host("graph.microsoft.com")
    assert not is_attacker_host("metadata.google.internal")
    assert not is_attacker_host("curl.se")
