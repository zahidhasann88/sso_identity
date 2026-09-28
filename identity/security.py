from __future__ import annotations

import hashlib
import logging

from django.conf import settings
from django.core.cache import cache

logger = logging.getLogger("identity.security")


def client_ip(request) -> str:
    """
    Best-effort client IP, used as part of the login-lockout key.

    ``X-Forwarded-For`` is honoured only when ``TRUST_PROXY_HEADERS`` is set,
    since otherwise anyone could reset their own failure counter. Even then,
    the leading entries are client-supplied — each proxy appends the address it
    saw — so with N trusted proxies the client is the Nth entry from the right,
    matching how DRF's ``NUM_PROXIES`` reads the same header.
    """
    if getattr(settings, "TRUST_PROXY_HEADERS", False):
        forwarded = request.META.get("HTTP_X_FORWARDED_FOR", "")
        if forwarded:
            hops = [hop.strip() for hop in forwarded.split(",") if hop.strip()]
            count = max(1, int(getattr(settings, "TRUST_PROXY_COUNT", 1)))
            if len(hops) >= count:
                return hops[-count][:45]
            if hops:
                return hops[0][:45]
    return (request.META.get("REMOTE_ADDR") or "0.0.0.0")[:45]  # noqa: S104


def audit(event: str, request=None, **fields) -> None:
    """Emit a structured, secret-free security event."""
    parts = [event]
    if request is not None:
        parts.append(f"ip={client_ip(request)}")
        rid = getattr(request, "request_id", None)
        if rid:
            parts.append(f"rid={rid}")
    parts.extend(f"{key}={value}" for key, value in fields.items())
    logger.info(" ".join(parts))


class LoginGuard:
    """Sliding-window lockout for failed authentication attempts."""

    PREFIX = "identity:login-fail:"

    @classmethod
    def _key(cls, identifier: str, ip: str) -> str:
        digest = hashlib.sha256(
            f"{(identifier or '').strip().lower()}|{ip}".encode()
        ).hexdigest()
        return f"{cls.PREFIX}{digest}"

    @classmethod
    def limit(cls) -> int:
        return getattr(settings, "LOGIN_FAILURE_LIMIT", 8)

    @classmethod
    def window(cls) -> int:
        return getattr(settings, "LOGIN_FAILURE_WINDOW_SECONDS", 900)

    @classmethod
    def is_locked(cls, identifier: str, ip: str) -> bool:
        return int(cache.get(cls._key(identifier, ip), 0)) >= cls.limit()

    @classmethod
    def register_failure(cls, identifier: str, ip: str) -> int:
        """
        Count one failure and return the running total for the window.

        ``add`` is the atomic "am I the first failure" test: two concurrent
        misses cannot both believe they are, and reset each other back to 1.
        It also fixes the expiry at creation, so later attempts cannot push
        the window out.
        """
        key = cls._key(identifier, ip)
        if cache.add(key, 1, cls.window()):
            return 1
        try:
            return int(cache.incr(key))
        except ValueError:
            # The entry expired between add() and incr(): start a new window.
            cache.set(key, 1, cls.window())
            return 1

    @classmethod
    def reset(cls, identifier: str, ip: str) -> None:
        cache.delete(cls._key(identifier, ip))

    @classmethod
    def retry_after(cls) -> int:
        return cls.window()
