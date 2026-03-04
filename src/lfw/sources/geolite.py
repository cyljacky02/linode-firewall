"""GeoLite2 MMDB country prefix extraction via deterministic network iteration."""

from __future__ import annotations

import hashlib
import ipaddress
import logging
from datetime import datetime, timezone
from pathlib import Path

import maxminddb

from lfw.core.exceptions import GeoLiteDbNotFoundError, SourceFetchError
from lfw.core.types import IpFamily, PrefixRecord, SourceSnapshot
from lfw.schema.policy import CountryGeoliteSource
from lfw.sources.base import SourceProvider

logger = logging.getLogger(__name__)


class GeoLiteProvider(SourceProvider):
    """Extracts country-level prefix sets from a GeoLite2-Country MMDB file.

    Uses deterministic network iteration (reader.__iter__) rather than
    brute-force address lookups for correctness and performance.
    """

    def __init__(self, config: CountryGeoliteSource) -> None:
        self._config = config
        self._countries = set(config.countries)

    def fetch(self) -> tuple[SourceSnapshot, list[PrefixRecord]]:
        mmdb_path = Path(self._config.mmdb_path)
        if not mmdb_path.exists():
            raise GeoLiteDbNotFoundError(str(mmdb_path))

        file_hash = hashlib.sha256(mmdb_path.read_bytes()).hexdigest()

        records: list[PrefixRecord] = []
        total_networks = 0

        try:
            reader = maxminddb.open_database(str(mmdb_path))
        except Exception as exc:
            raise SourceFetchError(
                f"Failed to open GeoLite2 MMDB: {mmdb_path}: {exc}"
            ) from exc

        try:
            for network, record in reader:
                total_networks += 1
                if not isinstance(record, dict):
                    continue

                country_info = record.get("country") or record.get("registered_country")
                if not country_info:
                    continue

                iso_code = country_info.get("iso_code", "").upper()
                if iso_code not in self._countries:
                    continue

                net = ipaddress.ip_network(network)
                cidr = str(net)
                family = self.detect_family(cidr)
                records.append(
                    PrefixRecord(
                        cidr=cidr,
                        family=family,
                        source_id=self._config.id,
                        provenance=iso_code,
                    )
                )
        finally:
            reader.close()

        snapshot = SourceSnapshot(
            source_id=self._config.id,
            source_type=self._config.type,
            url_or_command=str(mmdb_path),
            sha256=file_hash,
            fetched_at=datetime.now(timezone.utc),
            raw_count=total_networks,
            normalized_count=len(records),
            metadata={"countries": sorted(self._countries)},
        )

        logger.info(
            "GeoLite source '%s': %d total networks scanned, "
            "%d CIDRs matched for countries %s",
            self._config.id,
            total_networks,
            len(records),
            sorted(self._countries),
        )
        return snapshot, records
