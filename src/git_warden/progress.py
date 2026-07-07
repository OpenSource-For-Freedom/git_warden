"""Human-facing progress for the hunt (the SEPARATE human channel).

The hunt's audit trail is the JSON log stream (``logging_setup.JsonFormatter``)
and the per-run artifacts; that stream is machine-parseable and must never
change shape for a human's benefit. This module is the human channel: a
TTY-aware progress renderer that tells a newcomer what the pipeline is doing
*right now* -- the slow paced code searches, the Tier-1 triage, the Tier-2
clones -- so silent execution never reads as "nothing is happening."

Two rules keep the two channels from fighting each other:
  * progress writes to **stderr**; the JSON summary and audit log own stdout,
    so a consumer piping stdout still gets clean machine output.
  * progress reports only counts and repo names, never tokens or clone paths.

``NullProgress`` is the default no-op so pipeline code can call ``progress.*``
freely without ``None`` guards; the CLI swaps in ``ConsoleProgress`` when a
human is watching. Neither one moves the evidentiary bar: this is display only.
"""

from __future__ import annotations

from typing import TextIO

# The four newcomer-legible buckets the run collapses to, mapped onto the
# pipeline's internal counters. Kept here so the footer and any future dashboard
# read from one definition.
_BUCKETS = (
    ("candidates", "repos scanned"),
    ("signature_match", "signatures matched"),
    ("confirmed", "code analysis passed"),
    ("queued", "queued for review"),
)


class NullProgress:
    """No-op reporter. Held by pipeline code unless a human is watching."""

    def run_header(self, run_number: int, snap: dict[str, int]) -> None: ...
    def phase(self, title: str, detail: str = "") -> None: ...
    def note(self, message: str) -> None: ...
    def source(self, name: str, added: int, total: int) -> None: ...
    def discovery(self, by_method: dict[str, int], total: int) -> None: ...
    def screen_start(self, total: int) -> None: ...
    def screen_item(self, idx: int, total: int, name: str, to_tier2: bool) -> None: ...
    def screen_end(self, screened: int) -> None: ...
    def tier2_start(self, total: int) -> None: ...
    def tier2_item(self, idx: int, total: int, name: str) -> None: ...
    def confirmed(self, name: str, score: int) -> None: ...
    def tier2_end(self, confirmed: int) -> None: ...
    def run_footer(self, before: dict[str, int], after: dict[str, int],
                   counts: dict[str, int]) -> None: ...


class ConsoleProgress(NullProgress):
    """Render hunt progress to a stream, live-updating on a TTY.

    On a TTY the per-item counters overwrite one status line with ``\\r``; on a
    pipe (CI) that would flood the log, so there we emit a milestone line every
    ``_MILESTONE`` items and at the end of each stage instead.
    """

    _MILESTONE = 25

    def __init__(self, stream: TextIO | None = None) -> None:
        import sys

        self.out: TextIO = stream if stream is not None else sys.stderr
        self.tty = bool(getattr(self.out, "isatty", lambda: False)())
        self._live = False   # a \r status line is pending its closing newline
        self._lastlen = 0    # width of the last status line, to clear leftovers
        # running per-stage tallies, surfaced live and reused by the footer copy
        self._scr_tier2 = 0

    # -- low-level stream helpers -------------------------------------------
    def _write(self, text: str) -> None:
        self.out.write(text)
        self.out.flush()

    def _close_live(self) -> None:
        if self._live:
            self._write("\n")
            self._live = False
            self._lastlen = 0

    def _emit(self, text: str = "") -> None:
        """A permanent line: never overwritten by later status updates."""
        self._close_live()
        self._write(text + "\n")

    def _status(self, text: str) -> None:
        """A live, overwriting line (TTY only)."""
        if not self.tty:
            return
        pad = max(0, self._lastlen - len(text))
        self._write("\r" + text + " " * pad)
        self._lastlen = len(text)
        self._live = True

    # -- run framing --------------------------------------------------------
    def run_header(self, run_number: int, snap: dict[str, int]) -> None:
        self._emit()
        self._emit(f"Git Warden hunt  ::  run #{run_number}")
        if run_number <= 3:
            # Expectation-setting: the yield compounds; a newcomer who quits after
            # run 1 never sees it. This is honest -- the corpus below is the fuel.
            self._emit("  Run 1 establishes a baseline. Runs 2-3 refine the patterns.")
            self._emit("  Most batches reach high yield by run 3, so give it three passes.")
        self._emit(
            "  Learned corpus (fuel for this run): "
            f"{snap.get('learned_iocs', 0)} IOCs, "
            f"{snap.get('code_signatures', 0)} code signatures, "
            f"{snap.get('search_terms', 0)} search terms "
            f"from {snap.get('confirmations', 0)} prior confirmation(s)."
        )

    def phase(self, title: str, detail: str = "") -> None:
        self._emit()
        self._emit(f"> {title}" + (f"   {detail}" if detail else ""))

    def note(self, message: str) -> None:
        self._emit(f"  {message}")

    # -- discovery ----------------------------------------------------------
    def source(self, name: str, added: int, total: int) -> None:
        # Emitted after each discovery sub-source so the paced (~7s/search) code
        # search phase visibly advances instead of hanging silent.
        self._emit(f"  {name}: +{added} candidate(s)  (running total {total})")

    def discovery(self, by_method: dict[str, int], total: int) -> None:
        self._emit(f"  {total} candidate repo(s) after ranking:")
        for method, n in sorted(by_method.items(), key=lambda kv: -kv[1]):
            self._emit(f"      {n:>4}  {method}")

    # -- Tier-1 screen ------------------------------------------------------
    def screen_start(self, total: int) -> None:
        self._scr_tier2 = 0
        self._emit(f"  triaging {total} candidate(s) by name + README")

    def screen_item(self, idx: int, total: int, name: str, to_tier2: bool) -> None:
        if to_tier2:
            self._scr_tier2 += 1
        line = f"  scanned {idx}/{total}  ::  queued for analysis {self._scr_tier2}"
        self._status(line)
        if not self.tty and (idx == total or idx % self._MILESTONE == 0):
            self._emit(line)

    def screen_end(self, screened: int) -> None:
        self._close_live()
        self._emit(f"  Tier-1 done: {screened} repo(s) advanced to code analysis")

    # -- Tier-2 analyze -----------------------------------------------------
    def tier2_start(self, total: int) -> None:
        self._emit(f"  cloning + statically analysing {total} repo(s) (never executed)")

    def tier2_item(self, idx: int, total: int, name: str) -> None:
        line = f"  analysed {idx}/{total}  ::  {name}"
        self._status(line)
        if not self.tty and (idx == total or idx % self._MILESTONE == 0):
            self._emit(f"  analysed {idx}/{total}")

    def confirmed(self, name: str, score: int) -> None:
        # Confirmations are rare and important: always a permanent line.
        self._emit(f"  [CONFIRMED] {name}  (score {score})")

    def tier2_end(self, confirmed: int) -> None:
        self._close_live()
        self._emit(f"  Tier-2 done: {confirmed} repo(s) confirmed malicious by static evidence")

    # -- run footer ---------------------------------------------------------
    def run_footer(self, before: dict[str, int], after: dict[str, int],
                   counts: dict[str, int]) -> None:
        by_method = counts.get("candidates_by_method") or {}
        queued = counts.get("confirmed", 0)  # confirmed == queued for analyst review
        tally = {
            "candidates": counts.get("candidates", 0),
            "signature_match": by_method.get("signature_match", 0),
            "confirmed": counts.get("confirmed", 0),
            "queued": queued,
        }
        self._emit()
        self._emit("This run:")
        for key, label in _BUCKETS:
            self._emit(f"      {tally.get(key, 0):>4}  {label}")
        self._emit(f"      {counts.get('gold_delivered', 0):>4}  delivered to review feed")

        # The learning delta: proof the corpus grew, so the next run searches
        # wider. This is what "the tool is learning" looks like in numbers.
        d_iocs = after.get("learned_iocs", 0) - before.get("learned_iocs", 0)
        d_sigs = after.get("code_signatures", 0) - before.get("code_signatures", 0)
        d_terms = after.get("search_terms", 0) - before.get("search_terms", 0)
        self._emit()
        if d_iocs or d_sigs or d_terms:
            self._emit(
                f"Corpus grew: +{d_iocs} IOCs, +{d_sigs} code signatures, "
                f"+{d_terms} search terms. Run again; the next pass searches wider."
            )
        else:
            self._emit(
                "Corpus unchanged this run. Nothing new confirmed, so the next pass "
                "searches the same terms; widen with a larger --limit or fresh intel."
            )
