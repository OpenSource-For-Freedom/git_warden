"""YARA rulesets for the Tier-2 ``yara`` scanner.

Kept as Python strings so they ship inside the package and reach the sandbox
image with it (the repository's config/ and intel/ trees do not resolve after
``pip install``). Only malware-specific rules belong here: a YARA hit confirms a
repository on its own.
"""

from __future__ import annotations

# OSM's multi-variant PolinRider rule (github.com/OpenSourceMalware/PolinRider,
# "YARA Rule (Suggested)", 2026-04-10), unchanged apart from the comment style.
POLINRIDER = r"""
rule polinrider_payload {
    meta:
        description = "PolinRider shuffle-cipher JS payloads, rmcej%otb% (v1) and Cot%3t=shtP (v2)"
        author = "OpenSourceMalware.com"
        date = "2026-04-10"
        severity = "high"

    strings:
        $marker_v1   = "rmcej%otb%"
        $seed1_v1    = "2857687"
        $seed2_v1    = "2667686"
        $varname_v1  = "_$_1e42"
        $global_bang = "global['!']"

        $marker_v2   = "Cot%3t=shtP"
        $seed1_v2    = "1111436"
        $seed2_v2    = "3896884"
        $varname_v2  = "MDy"
        $global_V    = "global['_V']"

        $global_r    = "global['r'] = require"
        $global_m    = "global['m'] = module"

    condition:
        any of ($marker_*) or
        ($global_bang and ($seed1_v1 or $varname_v1)) or
        ($global_V    and ($seed1_v2 or $varname_v2)) or
        ($global_r and $global_m and (any of ($seed*)))
}
"""

RULESETS = {"polinrider": POLINRIDER}
