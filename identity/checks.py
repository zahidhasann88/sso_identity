"""
Checks for configuration that is valid but unsafe in production.

The algorithm check runs on every ``manage.py check``; the rest need
``--deploy``. Each warning's own message and hint carry the reasoning.
"""

from __future__ import annotations

from django.conf import settings
from django.core.checks import Error, Tags, Warning, register

from identity.crypto import ALLOWED_ALGORITHMS

LOCMEM_BACKEND = "django.core.cache.backends.locmem.LocMemCache"


@register(Tags.security)
def check_signing_algorithm(app_configs, **kwargs):
    """The signing algorithm must be one of the asymmetric algorithms."""
    algorithm = getattr(settings, "JWT_ALGORITHM", "RS256")
    if algorithm in ALLOWED_ALGORITHMS:
        return []
    return [
        Error(
            f"JWT_ALGORITHM={algorithm!r} is not an allowed asymmetric algorithm.",
            hint=(
                f"Choose one of {', '.join(ALLOWED_ALGORITHMS)}. A symmetric "
                f"algorithm such as HS256 would make every relying party that "
                f"holds the verification key able to mint tokens."
            ),
            id="identity.E001",
        )
    ]


@register(Tags.caches, deploy=True)
def check_cache_is_shared(app_configs, **kwargs):
    """Throttling and login lockout are only as shared as the cache behind them."""
    backend = settings.CACHES.get("default", {}).get("BACKEND")
    if settings.DEBUG or backend != LOCMEM_BACKEND:
        return []
    return [
        Warning(
            "The default cache is local-memory, which is per-process. Request "
            "throttling and login lockout will be multiplied by the number of "
            "worker processes.",
            hint=(
                "Set CACHE_URL to a redis:// URL (any store shared by every "
                "worker), or run a single worker process."
            ),
            id="identity.W001",
        )
    ]


@register(Tags.security, deploy=True)
def check_revocation_store_is_durable(app_configs, **kwargs):
    """A Redis-only revocation ledger loses every revocation on eviction."""
    backend = str(getattr(settings, "JWT_BLACKLIST_BACKEND", "db")).lower()
    if backend != "redis":
        return []
    return [
        Warning(
            "JWT_BLACKLIST_BACKEND='redis' keeps revocations only in Redis, so "
            "a flush, failover or eviction silently un-revokes every token "
            "that has not expired yet.",
            hint=(
                "Use 'chained' for the same read latency with the database as "
                "the durable record, or 'db' for durability alone."
            ),
            id="identity.W002",
        )
    ]


@register(Tags.security, deploy=True)
def check_ssl_redirect_has_a_way_to_see_tls(app_configs, **kwargs):
    """``SECURE_SSL_REDIRECT`` needs a way to know a request already used TLS."""
    if not getattr(settings, "SECURE_SSL_REDIRECT", False):
        return []
    if getattr(settings, "SECURE_PROXY_SSL_HEADER", None):
        return []
    return [
        Warning(
            "SECURE_SSL_REDIRECT is on while no forwarded-protocol header is "
            "trusted. That is correct when the service terminates TLS itself, "
            "and an infinite redirect loop when a proxy terminates it.",
            hint=(
                "Behind a TLS-terminating proxy, set TRUST_PROXY_HEADERS=1. If "
                "the service handles TLS directly, this warning is expected."
            ),
            id="identity.W003",
        )
    ]


@register(Tags.security, deploy=True)
def check_rotation_consumes_the_old_token(app_configs, **kwargs):
    """Rotating without consuming the old token is rotation in name only."""
    if not getattr(settings, "JWT_ROTATE_REFRESH_TOKENS", True):
        return []
    if getattr(settings, "JWT_BLACKLIST_AFTER_ROTATION", True):
        return []
    return [
        Warning(
            "JWT_ROTATE_REFRESH_TOKENS is on but JWT_BLACKLIST_AFTER_ROTATION is "
            "off: rotated refresh tokens are never consumed, which disables "
            "replay detection and lets one stolen token mint sessions until it "
            "expires.",
            hint=(
                "Set JWT_BLACKLIST_AFTER_ROTATION=1, or turn rotation off too if "
                "the revocation ledger writes are genuinely unaffordable."
            ),
            id="identity.W004",
        )
    ]
