"""Source provider factory — maps config types to provider instances."""

from __future__ import annotations

from lfw.schema.policy import (
    AsnBgpq4Source,
    CloudflareIpsSource,
    CloudflareLocalSource,
    CountryGeoliteSource,
    SourceConfig,
    X4bListSource,
)
from lfw.sources.base import SourceProvider
from lfw.sources.bgpq4 import Bgpq4Provider
from lfw.sources.cloudflare import CloudflareIpsProvider, CloudflareLocalProvider
from lfw.sources.geolite import GeoLiteProvider
from lfw.sources.x4b import X4bListProvider


def create_provider(source: SourceConfig) -> SourceProvider:
    """Factory: source config → provider instance."""
    if isinstance(source, X4bListSource):
        return X4bListProvider(source)
    if isinstance(source, AsnBgpq4Source):
        return Bgpq4Provider(source)
    if isinstance(source, CountryGeoliteSource):
        return GeoLiteProvider(source)
    if isinstance(source, CloudflareIpsSource):
        return CloudflareIpsProvider(source)
    if isinstance(source, CloudflareLocalSource):
        return CloudflareLocalProvider(source)
    raise ValueError(f"Unknown source type: {type(source).__name__}")
