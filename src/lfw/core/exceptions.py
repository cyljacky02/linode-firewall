"""Structured exceptions for the LFW engine."""

from __future__ import annotations


class LfwError(Exception):
    """Base exception for all LFW errors."""


# ---------------------------------------------------------------------------
# Source errors
# ---------------------------------------------------------------------------
class SourceFetchError(LfwError):
    """Failed to fetch or parse an external source."""


class Bgpq4NotFoundError(LfwError):
    """Neither local bgpq4 binary nor Docker fallback is available."""

    def __init__(self) -> None:
        super().__init__(
            "bgpq4 not found. Install via package manager "
            "(e.g. `scoop install bgpq4`) or ensure Docker is available "
            "for the fallback image `ghcr.io/bgp/bgpq4`."
        )


class GeoLiteDbNotFoundError(LfwError):
    """GeoLite MMDB file not found at the configured path."""

    def __init__(self, path: str) -> None:
        super().__init__(f"GeoLite2 MMDB not found at: {path}")


# ---------------------------------------------------------------------------
# Validation / schema errors
# ---------------------------------------------------------------------------
class PolicyValidationError(LfwError):
    """Policy YAML failed schema or semantic validation."""


class FitCheckError(LfwError):
    """Resolved prefix set cannot fit within Linode firewall limits."""


# ---------------------------------------------------------------------------
# Summarization errors
# ---------------------------------------------------------------------------
class SummarizationBoundsExceededError(LfwError):
    """Prefix set cannot be summarized within configured guardrails."""

    def __init__(self, input_count: int, output_count: int, capacity: int, detail: str) -> None:
        self.input_count = input_count
        self.output_count = output_count
        self.capacity = capacity
        self.detail = detail
        super().__init__(
            f"Summarization failed: {output_count} CIDRs still exceed "
            f"capacity {capacity} (from {input_count} inputs). {detail}"
        )


# ---------------------------------------------------------------------------
# Linode adapter errors
# ---------------------------------------------------------------------------
class LinodeApiError(LfwError):
    """Linode API returned an unexpected error."""

    def __init__(self, status: int, message: str, endpoint: str = "") -> None:
        self.status = status
        self.endpoint = endpoint
        super().__init__(f"Linode API {status} on {endpoint}: {message}")


class LinodeRateLimitError(LinodeApiError):
    """HTTP 429 — rate-limited by Linode API."""

    def __init__(self, retry_after: int, endpoint: str = "") -> None:
        self.retry_after = retry_after
        super().__init__(429, f"Rate limited, retry after {retry_after}s", endpoint)


class BetaUnavailableError(LfwError):
    """A beta endpoint returned 403/404, indicating feature not enabled."""


# ---------------------------------------------------------------------------
# State / audit errors
# ---------------------------------------------------------------------------
class StateDbError(LfwError):
    """SQLite state database error."""
