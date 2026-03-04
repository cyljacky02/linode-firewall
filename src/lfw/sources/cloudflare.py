"""Cloudflare IP ranges source providers.

Two provider classes for two source types:

- ``CloudflareIpsProvider``   — aggregated IP ranges from ``ips-v4`` / ``ips-v6``
- ``CloudflareLocalProvider`` — per-PoP CSV with country/city filtering
"""

from __future__ import annotations

import hashlib
import ipaddress
import logging
from datetime import datetime, timezone

import httpx

from lfw.core.exceptions import SourceFetchError
from lfw.core.types import IpFamily, PrefixRecord, SourceSnapshot
from lfw.schema.policy import CloudflareIpsSource, CloudflareLocalSource
from lfw.sources.base import SourceProvider

logger = logging.getLogger(__name__)


def _fetch_lines(url: str) -> tuple[list[str], bytes]:
    """Fetch a URL and return (lines, raw_bytes)."""
    logger.info("Fetching Cloudflare IPs: %s", url)
    try:
        resp = httpx.get(url, timeout=30, follow_redirects=True)
        resp.raise_for_status()
    except httpx.HTTPError as exc:
        raise SourceFetchError(
            f"Failed to fetch Cloudflare IPs from {url}: {exc}"
        ) from exc
    return resp.text.strip().splitlines(), resp.content


# ---------------------------------------------------------------------------
# cloudflare_ips — aggregated IP ranges (plain CIDR, one per line)
# ---------------------------------------------------------------------------
class CloudflareIpsProvider(SourceProvider):
    """Fetches aggregated Cloudflare IP ranges from ips-v4 / ips-v6."""

    def __init__(self, config: CloudflareIpsSource) -> None:
        self._config = config

    def fetch(self) -> tuple[SourceSnapshot, list[PrefixRecord]]:
        all_lines: list[str] = []
        combined_raw = b""

        for url in self._config.urls:
            lines, raw = _fetch_lines(url)
            all_lines.extend(lines)
            combined_raw += raw

        records: list[PrefixRecord] = []
        for line in all_lines:
            line = line.strip()
            if not line or line.startswith("#") or "/" not in line:
                continue
            try:
                net = ipaddress.ip_network(line, strict=False)
                cidr = str(net)
                records.append(PrefixRecord(
                    cidr=cidr,
                    family=self.detect_family(cidr),
                    source_id=self._config.id,
                    provenance="cloudflare/ips",
                ))
            except ValueError:
                continue

        snapshot = SourceSnapshot(
            source_id=self._config.id,
            source_type=self._config.type,
            url_or_command=", ".join(self._config.urls),
            sha256=hashlib.sha256(combined_raw).hexdigest(),
            fetched_at=datetime.now(timezone.utc),
            raw_count=len(all_lines),
            normalized_count=len(records),
        )
        logger.info(
            "Cloudflare source '%s': %d raw → %d CIDRs",
            self._config.id, len(all_lines), len(records),
        )
        return snapshot, records


# ---------------------------------------------------------------------------
# cloudflare_local — per-PoP CSV with country/city filtering
# ---------------------------------------------------------------------------
class CloudflareLocalProvider(SourceProvider):
    """Fetches Cloudflare per-PoP IP allocations with country/city filtering.

    CSV format: ``CIDR,country_code,region,city,``
    """

    def __init__(self, config: CloudflareLocalSource) -> None:
        self._config = config
        self._country_filter = set(config.countries)  # already uppercased
        self._city_filter = set(config.cities)         # already lowercased
        self._max_prefix = config.max_prefix_length
        self._prefix_uplift = config.prefix_uplift

    def fetch(self) -> tuple[SourceSnapshot, list[PrefixRecord]]:
        lines, raw = _fetch_lines(self._config.url)
        has_filters = bool(self._country_filter or self._city_filter)

        records: list[PrefixRecord] = []
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            fields = [f.strip() for f in line.split(",")]
            if not fields or "/" not in fields[0]:
                continue

            cidr_raw = fields[0]
            row_country = fields[1].upper() if len(fields) > 1 else ""
            row_city = fields[3].lower() if len(fields) > 3 else ""

            if has_filters:
                country_ok = (not self._country_filter) or (row_country in self._country_filter)
                city_ok = (not self._city_filter) or (row_city in self._city_filter)
                if not (country_ok and city_ok):
                    continue

            try:
                net = ipaddress.ip_network(cidr_raw, strict=False)
                if self._max_prefix is not None and net.prefixlen > self._max_prefix:
                    continue
                cidr = str(net)
                provenance = f"cloudflare/{row_country or 'local'}"
                if row_city:
                    provenance += f"/{row_city}"
                records.append(PrefixRecord(
                    cidr=cidr,
                    family=self.detect_family(cidr),
                    source_id=self._config.id,
                    provenance=provenance,
                ))
            except ValueError:
                continue

        # Apply prefix uplift: widen narrow CIDRs to boundary then dedup
        if self._prefix_uplift is not None:
            pre_uplift = len(records)
            seen: set[str] = set()
            uplifted: list[PrefixRecord] = []
            for rec in records:
                net = ipaddress.ip_network(rec.cidr, strict=False)
                if net.prefixlen > self._prefix_uplift:
                    net = ipaddress.ip_network(
                        f"{net.network_address}/{self._prefix_uplift}", strict=False
                    )
                cidr = str(net)
                if cidr not in seen:
                    seen.add(cidr)
                    uplifted.append(PrefixRecord(
                        cidr=cidr,
                        family=rec.family,
                        source_id=rec.source_id,
                        provenance=rec.provenance,
                    ))
            records = uplifted
            logger.info(
                "Cloudflare local '%s': prefix uplift /%d: %d → %d CIDRs",
                self._config.id, self._prefix_uplift, pre_uplift, len(records),
            )

        metadata: dict = {}
        if self._config.countries:
            metadata["countries"] = sorted(self._config.countries)
        if self._config.cities:
            metadata["cities"] = sorted(self._config.cities)

        snapshot = SourceSnapshot(
            source_id=self._config.id,
            source_type=self._config.type,
            url_or_command=self._config.url,
            sha256=hashlib.sha256(raw).hexdigest(),
            fetched_at=datetime.now(timezone.utc),
            raw_count=len(lines),
            normalized_count=len(records),
            metadata=metadata,
        )

        filter_desc = ""
        if self._config.countries:
            filter_desc += f" countries={sorted(self._config.countries)}"
        if self._config.cities:
            filter_desc += f" cities={sorted(self._config.cities)}"

        logger.info(
            "Cloudflare local '%s': %d raw → %d CIDRs%s",
            self._config.id, len(lines), len(records), filter_desc,
        )
        return snapshot, records
