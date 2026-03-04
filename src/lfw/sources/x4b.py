"""X4BNet VPN/datacenter list source provider."""

from __future__ import annotations

import hashlib
import ipaddress
import logging
from datetime import datetime, timezone

import httpx

from lfw.core.exceptions import SourceFetchError
from lfw.core.types import IpFamily, PrefixRecord, SourceSnapshot
from lfw.schema.policy import X4bListSource
from lfw.sources.base import SourceProvider

logger = logging.getLogger(__name__)


class X4bListProvider(SourceProvider):
    """Fetches IP lists from X4BNet/lists_vpn GitHub repository."""

    def __init__(self, config: X4bListSource) -> None:
        self._config = config

    def fetch(self) -> tuple[SourceSnapshot, list[PrefixRecord]]:
        all_lines: list[str] = []
        combined_raw = b""

        for list_path in self._config.list_paths:
            url = f"{self._config.base_url}/{list_path}"
            logger.info("Fetching X4B list: %s", url)
            try:
                resp = httpx.get(url, timeout=30, follow_redirects=True)
                resp.raise_for_status()
            except httpx.HTTPError as exc:
                raise SourceFetchError(
                    f"Failed to fetch X4B list from {url}: {exc}"
                ) from exc

            combined_raw += resp.content
            lines = resp.text.strip().splitlines()
            all_lines.extend(lines)

        sha256 = hashlib.sha256(combined_raw).hexdigest()
        raw_count = len(all_lines)

        records: list[PrefixRecord] = []
        for line in all_lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                net = ipaddress.ip_network(line, strict=False)
                cidr = str(net)
                family = self.detect_family(cidr)
                records.append(
                    PrefixRecord(
                        cidr=cidr,
                        family=family,
                        source_id=self._config.id,
                        provenance=f"x4b/{self._config.list_paths[0]}",
                    )
                )
            except ValueError:
                logger.warning("Skipping invalid CIDR in X4B list: %s", line)

        snapshot = SourceSnapshot(
            source_id=self._config.id,
            source_type=self._config.type,
            url_or_command=", ".join(
                f"{self._config.base_url}/{p}" for p in self._config.list_paths
            ),
            sha256=sha256,
            fetched_at=datetime.now(timezone.utc),
            raw_count=raw_count,
            normalized_count=len(records),
        )

        logger.info(
            "X4B source '%s': %d raw lines → %d valid CIDRs",
            self._config.id,
            raw_count,
            len(records),
        )
        return snapshot, records
