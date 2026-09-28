from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from collections.abc import Iterable
from datetime import UTC, datetime
from functools import lru_cache

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.utils import timezone

logger = logging.getLogger("identity.security")


class BaseBlacklist(ABC):
    """Interface every revocation store must satisfy."""

    @abstractmethod
    def revoke(
        self,
        jti: str,
        expires_at: datetime,
        *,
        user=None,
        token_type: str = "refresh",
        reason: str = "LOGOUT",
    ) -> bool:
        """Revoke ``jti``. Returns True if newly revoked, False if already so."""

    @abstractmethod
    def is_revoked(self, jti: str) -> bool:
        """Membership test on the hot path: every authenticated request runs it."""

    @abstractmethod
    def purge_expired(self) -> int:
        """Drop entries whose underlying token already expired naturally."""

    def revoke_many(self, entries: Iterable[tuple[str, datetime]], **kwargs) -> int:
        return sum(int(self.revoke(jti, exp, **kwargs)) for jti, exp in entries)


class DatabaseBlacklist(BaseBlacklist):
    """Durable revocation ledger backed by a single indexed table."""

    def revoke(
        self,
        jti: str,
        expires_at: datetime,
        *,
        user=None,
        token_type: str = "refresh",
        reason: str = "LOGOUT",
    ) -> bool:
        from identity.models import BlacklistedToken

        _, created = BlacklistedToken.objects.get_or_create(
            token_jti=jti,
            defaults={
                "expires_at": expires_at,
                "user": user,
                "token_type": token_type,
                "reason": reason,
            },
        )
        logger.info(
            "token.revoked jti=%s type=%s reason=%s new=%s",
            jti, token_type, reason, created,
        )
        return created

    def is_revoked(self, jti: str) -> bool:
        from identity.models import BlacklistedToken

        return BlacklistedToken.objects.filter(pk=jti).exists()

    def purge_expired(self) -> int:
        from identity.models import BlacklistedToken

        deleted, _ = BlacklistedToken.objects.expired().delete()
        return deleted


class RedisBlacklist(BaseBlacklist):
    """
    O(1) in-memory revocation set with automatic TTL eviction.

    Key layout: ``{prefix}{jti}`` -> ``"<reason>"``, with the TTL set to the
    token's remaining lifetime so Redis performs the garbage collection.
    """

    def __init__(self, url: str | None = None, prefix: str | None = None) -> None:
        try:
            import redis  # noqa: PLC0415 - optional dependency
        except ImportError as exc:  # pragma: no cover - env dependent
            raise ImproperlyConfigured(
                "JWT_BLACKLIST_BACKEND='redis' requires the `redis` package "
                "(pip install redis)."
            ) from exc

        self.prefix = prefix or getattr(
            settings, "JWT_BLACKLIST_REDIS_PREFIX", "sso:jti:revoked:"
        )
        self.client = redis.Redis.from_url(
            url or getattr(settings, "REDIS_URL", "redis://127.0.0.1:6379/0"),
            decode_responses=True,
            socket_connect_timeout=2,
            socket_timeout=2,
            health_check_interval=30,
        )

    def _key(self, jti: str) -> str:
        return f"{self.prefix}{jti}"

    def revoke(
        self,
        jti: str,
        expires_at: datetime,
        *,
        user=None,
        token_type: str = "refresh",
        reason: str = "LOGOUT",
    ) -> bool:
        ttl = int((expires_at - timezone.now()).total_seconds())
        if ttl <= 0:
            # Already expired: the signature/exp check rejects it anyway.
            return False
        created = bool(self.client.set(self._key(jti), reason, ex=ttl, nx=True))
        logger.info(
            "token.revoked backend=redis jti=%s type=%s reason=%s new=%s ttl=%ss",
            jti, token_type, reason, created, ttl,
        )
        return created

    def is_revoked(self, jti: str) -> bool:
        return bool(self.client.exists(self._key(jti)))

    def purge_expired(self) -> int:
        # Redis evicts on TTL; nothing to do.
        return 0


class ChainedBlacklist(BaseBlacklist):
    """
    Redis in front of the database.

    Reads hit Redis first (fast path) and fall back to the durable table if
    Redis is unavailable — a cache outage degrades latency, never security.
    Writes go to both stores.
    """

    def __init__(self) -> None:
        self.cache = RedisBlacklist()
        self.durable = DatabaseBlacklist()

    def revoke(self, jti: str, expires_at: datetime, **kwargs) -> bool:
        created = self.durable.revoke(jti, expires_at, **kwargs)
        try:
            self.cache.revoke(jti, expires_at, **kwargs)
        except Exception:
            logger.exception("redis.revoke_failed jti=%s", jti)
        return created

    def is_revoked(self, jti: str) -> bool:
        try:
            if self.cache.is_revoked(jti):
                return True
        except Exception:
            logger.exception("redis.lookup_failed jti=%s — falling back to DB", jti)
            return self.durable.is_revoked(jti)
        return self.durable.is_revoked(jti)

    def purge_expired(self) -> int:
        return self.durable.purge_expired()


@lru_cache(maxsize=1)
def get_blacklist() -> BaseBlacklist:
    backend = getattr(settings, "JWT_BLACKLIST_BACKEND", "db").lower()
    if backend == "db":
        return DatabaseBlacklist()
    if backend == "redis":
        return RedisBlacklist()
    if backend in {"chained", "redis+db"}:
        return ChainedBlacklist()
    raise ImproperlyConfigured(
        f"Unknown JWT_BLACKLIST_BACKEND={backend!r}; expected 'db', 'redis' or 'chained'."
    )


def reset_blacklist_cache() -> None:
    """Used by tests that flip ``JWT_BLACKLIST_BACKEND`` at runtime."""
    get_blacklist.cache_clear()


def to_aware(epoch: int | float) -> datetime:
    """Convert a NumericDate claim into an aware UTC datetime."""
    return datetime.fromtimestamp(int(epoch), tz=UTC)
