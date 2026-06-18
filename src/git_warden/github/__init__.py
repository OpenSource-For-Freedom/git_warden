"""GitHub access layer for the Week-2 scanning pipeline."""

from .client import GitHubClient, RateLimit

__all__ = ["GitHubClient", "RateLimit"]
