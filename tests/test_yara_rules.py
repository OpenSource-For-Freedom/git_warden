"""The YARA rulesets must compile: one bad rule makes yara reject the whole file,
and the scanner then reports "error" on every scan instead of matching."""

from __future__ import annotations

import re
import shutil
import subprocess

import pytest

from git_warden.scanning.yara_rules import RULESETS


def _strings_and_condition(rule: str) -> tuple[set[str], str]:
    strings = set(re.findall(r"^\s*(\$\w+)\s*=", rule, re.M))
    condition = rule.split("condition:", 1)[1]
    return strings, condition


@pytest.mark.parametrize("name", sorted(RULESETS))
def test_every_string_is_referenced_by_the_condition(name):
    # yara refuses a rule with an unreferenced string ("unreferenced string $x").
    for rule in re.split(r"\brule\s+\w+\s*\{", RULESETS[name])[1:]:
        strings, condition = _strings_and_condition(rule)
        wildcards = [w[:-1] for w in re.findall(r"\$\w*\*", condition)]
        for s in strings:
            assert re.search(re.escape(s) + r"\b", condition) or any(
                s.startswith(w) for w in wildcards), f"{name}: {s} is never referenced"


@pytest.mark.skipif(shutil.which("yara") is None, reason="yara CLI not installed")
def test_rules_compile_and_match_the_polinrider_payload(tmp_path):
    rules = tmp_path / "warden.yar"
    rules.write_text("\n".join(RULESETS.values()), encoding="utf-8")
    payload = tmp_path / "index.js"
    payload.write_text("global['_V']='8-st1';var MDy=0;\n", encoding="utf-8")
    result = subprocess.run(["yara", "-w", str(rules), str(payload)],
                            capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    assert "polinrider_payload" in result.stdout
