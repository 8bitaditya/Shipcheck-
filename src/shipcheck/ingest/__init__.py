"""Ingest package exposing GitHubIngest and diff utilities."""

from shipcheck.ingest.github_ingest import GitHubIngest
from shipcheck.ingest.diff import parse_unified_diff, extract_changed_filenames

__all__ = [
    "GitHubIngest",
    "parse_unified_diff",
    "extract_changed_filenames",
]
