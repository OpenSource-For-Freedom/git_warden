"""Base class for feed adapters.

A feed adapter turns one threat-intelligence source into normalized
:class:`~git_warden.models.SourceObservation` records. The two patterns we
support:

* **query-per-actor** (e.g. Google News): search each seed's terms and attribute
  every hit to that seed.
* **bulk-pull-and-match** (e.g. CISA advisories): fetch the feed once, then match
  seed names against the content.

Both produce the same output type, so the pipeline treats every feed uniformly.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar

from ..enums import FeedSource
from ..models import MaliciousArtifact, SeedActor, SourceObservation
from .http import HttpClient, RequestsHttpClient


class Feed(ABC):
    """Actor feed adapter. Subclasses set :attr:`source` and implement collect.

    Actor feeds (news, MITRE, CISA) produce :class:`SourceObservation`s that roll
    up into threat actors and drive the corroboration validator.
    """

    source: ClassVar[FeedSource]

    def __init__(self, http: HttpClient | None = None) -> None:
        self.http = http or RequestsHttpClient()

    @abstractmethod
    def collect(self, run_id: str, seeds: list[SeedActor]) -> list[SourceObservation]:
        """Fetch and normalize observations for the given seeds."""
        raise NotImplementedError


class ArtifactFeed(ABC):
    """Indicator feed adapter producing labeled malicious artifacts.

    Unlike :class:`Feed`, an artifact feed (e.g. OSM) is not actor-driven: it
    yields known-bad packages/repos directly into the ``malicious_artifacts``
    store, which seeds the Week-2 GitHub scanning layer.
    """

    source: ClassVar[FeedSource]

    def __init__(self, http: HttpClient | None = None) -> None:
        self.http = http or RequestsHttpClient()

    @abstractmethod
    def collect_artifacts(self, run_id: str) -> list[MaliciousArtifact]:
        """Fetch and normalize labeled malicious artifacts."""
        raise NotImplementedError
