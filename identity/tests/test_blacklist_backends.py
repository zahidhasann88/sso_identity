"""
The three revocation backends and, more importantly, how they fail.

``chained`` claims a Redis outage costs latency rather than security. That is
worth a test: if a failed cache lookup were read as "not revoked", every
revoked token would silently work again.

The Redis stores run against an in-process stub so CI needs no extra service.
It implements only the two commands the backend uses, with the semantics the
implementation depends on: ``SET NX`` falsy on an existing key, ``EXISTS``
honouring the TTL.
"""

from __future__ import annotations

import time
from datetime import timedelta

from django.core.exceptions import ImproperlyConfigured
from django.test import override_settings
from django.utils import timezone

from identity.blacklist import (
    ChainedBlacklist,
    DatabaseBlacklist,
    RedisBlacklist,
    get_blacklist,
    reset_blacklist_cache,
    to_aware,
)
from identity.models import BlacklistedToken
from identity.tests.base import IdentityAPITestCase


class FakeRedis:
    """The two-command subset of Redis that RedisBlacklist relies on."""

    def __init__(self) -> None:
        self.store: dict[str, tuple[str, float | None]] = {}
        self.fail_on: set[str] = set()
        self.calls: list[str] = []

    def _expired(self, key: str) -> bool:
        _, expires_at = self.store[key]
        return expires_at is not None and expires_at <= time.monotonic()

    def set(self, key, value, ex=None, nx=False):
        self.calls.append("set")
        if "set" in self.fail_on:
            raise ConnectionError("redis is down")
        if nx and key in self.store and not self._expired(key):
            return None  # what redis-py returns for a failed SET NX
        self.store[key] = (value, time.monotonic() + ex if ex else None)
        return True

    def exists(self, key):
        self.calls.append("exists")
        if "exists" in self.fail_on:
            raise ConnectionError("redis is down")
        if key in self.store and self._expired(key):
            del self.store[key]
        return 1 if key in self.store else 0


class StubbedRedisBlacklist(RedisBlacklist):
    """RedisBlacklist wired to a FakeRedis, skipping the real connection setup."""

    def __init__(self, client: FakeRedis, prefix: str = "test:jti:") -> None:
        self.client = client
        self.prefix = prefix


def future(**kwargs):
    return timezone.now() + timedelta(**kwargs)


class BackendSelectionTests(IdentityAPITestCase):
    def test_db_is_the_default(self):
        self.assertIsInstance(get_blacklist(), DatabaseBlacklist)

    @override_settings(JWT_BLACKLIST_BACKEND="nonsense")
    def test_an_unknown_backend_name_is_a_configuration_error(self):
        reset_blacklist_cache()
        try:
            with self.assertRaises(ImproperlyConfigured):
                get_blacklist()
        finally:
            reset_blacklist_cache()

    @override_settings(JWT_BLACKLIST_BACKEND="REDIS+DB")
    def test_the_backend_name_is_case_insensitive_and_aliased(self):
        """``redis+db`` is an accepted spelling of ``chained``."""
        reset_blacklist_cache()
        try:
            # redis is an optional extra; without it this must fail loudly
            # rather than fall back to a store nobody asked for.
            with self.assertRaises(ImproperlyConfigured) as caught:
                get_blacklist()
            self.assertIn("redis", str(caught.exception).lower())
        finally:
            reset_blacklist_cache()


class RedisBlacklistTests(IdentityAPITestCase):
    def setUp(self) -> None:
        super().setUp()
        self.client_stub = FakeRedis()
        self.store = StubbedRedisBlacklist(self.client_stub)

    def test_revoke_then_lookup(self):
        self.assertFalse(self.store.is_revoked("jti-1"))
        self.assertTrue(self.store.revoke("jti-1", future(minutes=5)))
        self.assertTrue(self.store.is_revoked("jti-1"))

    def test_revocation_is_idempotent_via_set_nx(self):
        self.assertTrue(self.store.revoke("jti-1", future(minutes=5)))
        self.assertFalse(self.store.revoke("jti-1", future(minutes=5)))

    def test_an_already_expired_token_is_not_stored(self):
        """Redis rejects a non-positive TTL, and `exp` already refuses the token."""
        self.assertFalse(self.store.revoke("stale", timezone.now() - timedelta(minutes=1)))
        self.assertEqual(self.client_stub.store, {})

    def test_the_entry_expires_when_the_token_would_have(self):
        # A whole number of seconds: the TTL is int-truncated, so a token with
        # under a second left is skipped entirely.
        self.store.revoke("short", timezone.now() + timedelta(seconds=60))
        key = self.store._key("short")
        _, expires_at = self.client_stub.store[key]
        self.assertIsNotNone(expires_at)

        # Fast-forward by rewriting the stub's deadline rather than sleeping.
        self.client_stub.store[key] = ("LOGOUT", time.monotonic() - 1)
        self.assertFalse(self.store.is_revoked("short"))

    def test_keys_are_namespaced(self):
        self.store.revoke("jti-1", future(minutes=5))
        self.assertEqual(list(self.client_stub.store), ["test:jti:jti-1"])

    def test_purge_is_a_no_op_because_redis_evicts(self):
        self.assertEqual(self.store.purge_expired(), 0)

    def test_revoke_many_counts_new_revocations_only(self):
        entries = [("a", future(minutes=5)), ("b", future(minutes=5)), ("a", future(minutes=5))]
        self.assertEqual(self.store.revoke_many(entries), 2)


class ChainedBlacklistFailureTests(IdentityAPITestCase):
    """A cache outage must cost latency, never a revocation."""

    def setUp(self) -> None:
        super().setUp()
        self.client_stub = FakeRedis()
        self.store = ChainedBlacklist.__new__(ChainedBlacklist)
        self.store.cache = StubbedRedisBlacklist(self.client_stub)
        self.store.durable = DatabaseBlacklist()

    def test_a_write_lands_in_both_stores(self):
        self.assertTrue(self.store.revoke("jti-1", future(minutes=5)))
        self.assertTrue(BlacklistedToken.objects.filter(pk="jti-1").exists())
        self.assertTrue(self.store.cache.is_revoked("jti-1"))

    def test_the_durable_store_decides_idempotency(self):
        """The database row is the record of truth for 'was this new?'."""
        self.assertTrue(self.store.revoke("jti-1", future(minutes=5)))
        self.assertFalse(self.store.revoke("jti-1", future(minutes=5)))

    def test_a_cache_hit_short_circuits_the_database(self):
        self.store.cache.revoke("cached-only", future(minutes=5))
        self.assertFalse(BlacklistedToken.objects.filter(pk="cached-only").exists())
        self.assertTrue(self.store.is_revoked("cached-only"))

    def test_a_cache_read_failure_falls_back_to_the_database(self):
        """
        The security-critical path: if the failed lookup were treated as
        "not revoked", every revoked token would start working again the moment
        Redis went down.
        """
        BlacklistedToken.objects.create(token_jti="jti-1", expires_at=future(minutes=5))
        self.client_stub.fail_on.add("exists")

        self.assertTrue(self.store.is_revoked("jti-1"))
        self.assertFalse(self.store.is_revoked("never-revoked"))

    def test_a_cache_write_failure_still_records_the_revocation(self):
        self.client_stub.fail_on.add("set")
        self.assertTrue(self.store.revoke("jti-1", future(minutes=5)))
        self.assertTrue(BlacklistedToken.objects.filter(pk="jti-1").exists())

        self.client_stub.fail_on.add("exists")
        self.assertTrue(self.store.is_revoked("jti-1"))

    def test_purging_only_touches_the_durable_store(self):
        BlacklistedToken.objects.create(
            token_jti="expired", expires_at=timezone.now() - timedelta(hours=1)
        )
        BlacklistedToken.objects.create(token_jti="live", expires_at=future(hours=1))
        self.assertEqual(self.store.purge_expired(), 1)
        self.assertTrue(self.store.is_revoked("live"))


class EpochConversionTests(IdentityAPITestCase):
    def test_a_numericdate_claim_becomes_an_aware_utc_datetime(self):
        moment = to_aware(1_700_000_000)
        self.assertIsNotNone(moment.tzinfo)
        self.assertEqual(moment.utcoffset(), timedelta(0))

    def test_a_float_claim_is_accepted(self):
        self.assertEqual(to_aware(1_700_000_000.9), to_aware(1_700_000_000))
