"""Offline tests for IOC-driven discovery (fake code search)."""

from __future__ import annotations

from collections import Counter

from git_warden.scanning.discovery import RepoHit, build_search_terms, classify_hit, search_iocs
from git_warden.scanning.ioc import IocSet


def _item(full_name, path="src/x.js"):
    owner = full_name.split("/", 1)[0]
    return {
        "repository": {
            "full_name": full_name,
            "owner": {"login": owner},
            "html_url": f"https://github.com/{full_name}",
        },
        "path": path,
    }


class FakeClient:
    def __init__(self, by_term):
        self.by_term = by_term
        self.calls = []            # query only (kept for existing assertions)
        self.page_calls = []       # (query, page) for pagination assertions

    def search_code(self, query, per_page=20, *, page=1, sort=None):
        self.calls.append(query)
        self.page_calls.append((query, page))
        val = self.by_term.get(query, [])
        if isinstance(val, dict):       # {page: [items]} for paginated fakes
            return val.get(page, [])
        return val if page == 1 else []  # a flat list is page-1 only


def test_finds_new_repos_excluding_known():
    client = FakeClient({
        "flipboxstudio.info": [_item("attacker/new-evil"), _item("BishopFox/sliver")],
    })
    hits = search_iocs(client, ["flipboxstudio.info"], known={"bishopfox/sliver"})
    names = {h.full_name for h in hits}
    assert names == {"attacker/new-evil"}  # known repo filtered out


def test_dedupes_repo_across_iocs_and_aggregates_matches():
    shared = _item("attacker/new-evil", path="a.js")
    shared2 = _item("attacker/new-evil", path="b.js")
    client = FakeClient({"webhook-id-123": [shared], "evil.example.com": [shared2]})
    hits = search_iocs(client, ["webhook-id-123", "evil.example.com"], known=set())
    assert len(hits) == 1
    hit = hits[0]
    assert hit.matched_iocs == ["webhook-id-123", "evil.example.com"]
    assert len(hit.paths) == 2  # both files recorded


def test_one_failing_ioc_does_not_abort():
    class Boom(FakeClient):
        def search_code(self, query, per_page=20, *, page=1, sort=None):
            if query == "bad":
                raise RuntimeError("rate limited")
            return super().search_code(query, per_page, page=page, sort=sort)

    client = Boom({"good.example": [_item("attacker/x")]})
    hits = search_iocs(client, ["bad", "good.example"], known=set())
    assert {h.full_name for h in hits} == {"attacker/x"}


def test_rate_limit_backs_off_then_retries_term():
    # An exception carrying retry_after is a throttle: wait, then retry the term.
    class Throttle(RuntimeError):
        retry_after = 30.0

    class Limited(FakeClient):
        def __init__(self, by_term):
            super().__init__(by_term)
            self.first = True

        def search_code(self, query, per_page=20, *, page=1, sort=None):
            if self.first:
                self.first = False
                raise Throttle("secondary rate limit")
            return super().search_code(query, per_page, page=page, sort=sort)

    waits = []
    client = Limited({"good.example": [_item("attacker/x")]})
    hits = search_iocs(client, ["good.example"], known=set(),
                       max_backoff=90.0, sleeper=waits.append)
    assert {h.full_name for h in hits} == {"attacker/x"}  # retry succeeded
    assert waits == [30.0]                                 # waited the requested time


def test_rate_limit_wait_is_capped():
    class Throttle(RuntimeError):
        retry_after = 100000.0

    class Limited(FakeClient):
        def search_code(self, query, per_page=20, *, page=1, sort=None):
            raise Throttle("limited")

    waits = []
    search_iocs(Limited({}), ["x"], known=set(), max_backoff=90.0, sleeper=waits.append)
    assert waits == [90.0]  # capped, not the absurd server value


class FakeCursor:
    """A per-query page cursor for pagination tests (no DB)."""

    def __init__(self, starts=None):
        self.starts = starts or {}
        self.advances = []

    def start(self, query):
        return self.starts.get(query, 1)

    def advance(self, query, *, next_page, exhausted):
        self.advances.append((query, next_page, exhausted))


def test_walks_pages_until_a_short_page_then_marks_exhausted():
    # A query matches thousands of repos; one page re-finds the same top hits.
    # Walking deeper surfaces the rest, and a short page means the query is spent.
    client = FakeClient({"evil.tld": {1: [_item("a/1"), _item("a/2")],
                                      2: [_item("a/3")]}})
    cur = FakeCursor()
    hits = search_iocs(client, ["evil.tld"], known=set(), per_term=2, pages=5, cursor=cur)
    assert {h.full_name for h in hits} == {"a/1", "a/2", "a/3"}
    assert client.page_calls == [("evil.tld", 1), ("evil.tld", 2)]  # stopped at short page
    assert cur.advances == [("evil.tld", 3, True)]                  # exhausted, resume n/a


def test_limited_pages_leave_the_cursor_midway_for_next_run():
    # pages=2 walks only two pages this run; the cursor resumes at page 3 next run,
    # so successive runs advance instead of re-flipping page 1.
    client = FakeClient({"q.tld": {1: [_item("a/1"), _item("a/2")],
                                   2: [_item("a/3"), _item("a/4")],
                                   3: [_item("a/5"), _item("a/6")]}})
    cur = FakeCursor()
    hits = search_iocs(client, ["q.tld"], known=set(), per_term=2, pages=2, cursor=cur)
    assert {h.full_name for h in hits} == {"a/1", "a/2", "a/3", "a/4"}
    assert client.page_calls == [("q.tld", 1), ("q.tld", 2)]
    assert cur.advances == [("q.tld", 3, False)]                    # not exhausted, resume at 3


def test_cursor_resumes_from_a_stored_page():
    client = FakeClient({"z.tld": {5: [_item("a/5")]}})
    cur = FakeCursor(starts={"z.tld": 5})
    hits = search_iocs(client, ["z.tld"], known=set(), per_term=100, pages=1, cursor=cur)
    assert client.page_calls == [("z.tld", 5)]                      # began at 5, not 1
    assert {h.full_name for h in hits} == {"a/5"}


def test_exhausted_term_is_skipped_entirely():
    client = FakeClient({"done.tld": [_item("a/1")]})
    cur = FakeCursor(starts={"done.tld": 0})                        # 0 == fully walked
    hits = search_iocs(client, ["done.tld"], known=set(), pages=3, cursor=cur)
    assert hits == [] and client.page_calls == []                  # never searched
    assert cur.advances == []


def test_package_name_terms_are_quoted():
    client = FakeClient({})
    search_iocs(client, ["@scope/evil-pkg", "foo.workers.dev"], known=set())
    assert client.calls == ['"@scope/evil-pkg"', "foo.workers.dev"]  # scoped quoted, domain not


def test_classify_source_use_overrides_defensive_name():
    # eval #1: a match in executable source means the IOC is USED -> suspicious,
    # even under a defensive-sounding name (attacker can't evade by naming).
    hit = RepoHit("ossf/malicious-packages", "ossf", "", paths=["src/x.js"])
    assert classify_hit(hit) == "suspicious"


def test_classify_config_use_is_suspicious():
    # eval #11: exfil endpoint in config/markup also counts as use.
    hit = RepoHit("attacker/neutral-name", "attacker", "", paths=["config.json"])
    assert classify_hit(hit) == "suspicious"


def test_classify_owner_token_does_not_force_defensive():
    # eval #1: defensive tokens in the OWNER must not veto; repo-name only.
    hit = RepoHit("security-research/evil-stealer", "security-research", "",
                  paths=["main.py"])
    assert classify_hit(hit) == "suspicious"


def test_classify_defensive_when_defensive_name_and_only_data_files():
    hit = RepoHit("ossf/malicious-packages", "ossf", "", paths=["list.txt", "README.md"])
    assert classify_hit(hit) == "defensive"


def test_build_search_terms_selects_attacker_domains_and_webhook_ids():
    iocs = IocSet(
        webhooks=Counter(["https://discord.com/api/webhooks/123456/tok"]),
        domains=Counter({"foo.workers.dev": 2, "docs.example.com": 1}),
    )
    terms = build_search_terms(iocs, 10)
    assert "foo.workers.dev" in terms       # attacker-host kept
    assert "123456" in terms                # webhook id extracted
    assert "docs.example.com" not in terms  # benign domain dropped


def test_build_search_terms_caps_at_max():
    iocs = IocSet(domains=Counter({f"h{i}.workers.dev": 10 - i for i in range(10)}))
    assert len(build_search_terms(iocs, 3)) == 3


def test_classify_nondefensive_name_data_only_is_suspicious():
    # eval verify: non-defensive name + IOC only in data files -> investigate.
    hit = RepoHit("attacker/totally-evil", "attacker", "", paths=["notes.txt", "data.md"])
    assert classify_hit(hit) == "suspicious"


def test_is_security_tool_breadcrumbs_pentest_readmes():
    # 2026-07-07: karmaz95/crimson (a pentest tool) confirmed on its exploit
    # payloads. A README with 2+ offensive-tool markers is a research breadcrumb.
    from git_warden.scanning.discovery import is_security_tool
    assert is_security_tool("A penetration testing toolkit for vulnerability assessment.")
    assert is_security_tool("Exploit collection and CTF challenge writeups for security research.")
    assert is_security_tool("Web Application Security Testing Tools: vulnerability scanning suite.")
    # a real malicious lure never describes itself this way (0-1 stray markers)
    assert not is_security_tool("A cool web3 project that can exploit market inefficiencies.")
    assert not is_security_tool("My portfolio site built with vite and tailwind.")
    assert not is_security_tool(None)


def test_is_security_tool_screens_defensive_scanners():
    # 2026-07-07: dnszlsk/muad-dib (a supply-chain MALWARE SCANNER) confirmed on its
    # own detection data (C2 lists, honeypot creds, rule strings). A defensive
    # scanner ships attack signatures as DATA and must be screened too.
    from git_warden.scanning.discovery import is_security_tool
    assert is_security_tool(
        "muad'dib detects malicious npm & pypi packages and typosquats, with a "
        "sandbox and SARIF output.")
    assert is_security_tool(
        "A supply-chain security scanner: detection rules, IOC match, threat detection.")
    # a DPRK coding-task lure and a plain project must NOT be screened
    assert not is_security_tool(
        "# Frontend Assessment\nA React app. Run npm install then npm start.")
    assert not is_security_tool(
        "TypeScript client generated from the Twitter API OpenAPI spec.")
