"""Abstract base for source providers."""

from __future__ import annotations

from abc import ABC, abstractmethod

from lfw.core.types import IpFamily, PrefixRecord, SourceSnapshot


class SourceProvider(ABC):
    """Contract for all source ingestion implementations."""

    @abstractmethod
    def fetch(self) -> tuple[SourceSnapshot, list[PrefixRecord]]:
        """Fetch raw data, return snapshot metadata and parsed prefix records."""

    @staticmethod
    def detect_family(cidr: str) -> IpFamily:
        return IpFamily.IPV6 if ":" in cidr else IpFamily.IPV4
