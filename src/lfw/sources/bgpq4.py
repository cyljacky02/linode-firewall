"""ASN prefix resolution via bgpq4 (local binary → Docker fallback)."""

from __future__ import annotations

import hashlib
import json
import logging
import shutil
import subprocess
from datetime import datetime, timezone

from lfw.core.exceptions import Bgpq4NotFoundError, SourceFetchError
from lfw.core.types import IpFamily, PrefixRecord, SourceSnapshot
from lfw.schema.policy import AsnBgpq4Source
from lfw.sources.base import SourceProvider

logger = logging.getLogger(__name__)


class Bgpq4Provider(SourceProvider):
    """Resolves ASN prefixes using bgpq4 CLI tool."""

    def __init__(self, config: AsnBgpq4Source) -> None:
        self._config = config
        self._binary = self._resolve_binary()

    def _resolve_binary(self) -> list[str]:
        """Detect bgpq4 execution path: local binary first, then Docker."""
        if self._config.bgpq4_path:
            if shutil.which(self._config.bgpq4_path):
                return [self._config.bgpq4_path]
            raise Bgpq4NotFoundError()

        local = shutil.which("bgpq4")
        if local:
            logger.debug("Using local bgpq4: %s", local)
            return [local]

        docker = shutil.which("docker")
        if docker:
            logger.info("Local bgpq4 not found, falling back to Docker image")
            return [
                docker,
                "run",
                "--rm",
                self._config.docker_image,
            ]

        raise Bgpq4NotFoundError()

    def _run_bgpq4(self, family_flag: str) -> list[dict]:
        """Execute bgpq4 for one address family and return prefix list."""
        cmd = [*self._binary, family_flag, "-j", "-l", "pfx", self._config.asn]
        logger.debug("Running: %s", " ".join(cmd))
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
                check=True,
            )
        except FileNotFoundError as exc:
            raise Bgpq4NotFoundError() from exc
        except subprocess.CalledProcessError as exc:
            raise SourceFetchError(
                f"bgpq4 failed for {self._config.asn} ({family_flag}): "
                f"{exc.stderr.strip()}"
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise SourceFetchError(
                f"bgpq4 timed out for {self._config.asn} ({family_flag})"
            ) from exc

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise SourceFetchError(
                f"bgpq4 returned invalid JSON for {self._config.asn}: {exc}"
            ) from exc

        return data.get("pfx", [])

    def fetch(self) -> tuple[SourceSnapshot, list[PrefixRecord]]:
        records: list[PrefixRecord] = []
        raw_items: list[dict] = []

        for family_flag, family in [("-4", IpFamily.IPV4), ("-6", IpFamily.IPV6)]:
            prefixes = self._run_bgpq4(family_flag)
            raw_items.extend(prefixes)
            for entry in prefixes:
                prefix = entry.get("prefix")
                if not prefix:
                    continue
                exact = entry.get("exact", False)
                cidr = prefix if exact or "/" in prefix else prefix
                records.append(
                    PrefixRecord(
                        cidr=cidr,
                        family=family,
                        source_id=self._config.id,
                        provenance=self._config.asn,
                    )
                )

        raw_json = json.dumps(raw_items, sort_keys=True)
        sha256 = hashlib.sha256(raw_json.encode()).hexdigest()

        snapshot = SourceSnapshot(
            source_id=self._config.id,
            source_type=self._config.type,
            url_or_command=f"bgpq4 {self._config.asn}",
            sha256=sha256,
            fetched_at=datetime.now(timezone.utc),
            raw_count=len(raw_items),
            normalized_count=len(records),
        )

        logger.info(
            "bgpq4 source '%s' (%s): %d prefixes resolved",
            self._config.id,
            self._config.asn,
            len(records),
        )
        return snapshot, records
