"""
Configuration safety: proxy trust, abuse-counter identity, and the deployment
checks for setups that are valid but unsafe.

Every abuse control here is keyed on the client address, so a client that can
choose that address can choose to have no limits.
"""

from __future__ import annotations

from django.core.checks import Error, Warning
from django.core.exceptions import ImproperlyConfigured
from django.test import RequestFactory, SimpleTestCase, override_settings

from identity.checks import (
    check_cache_is_shared,
    check_revocation_store_is_durable,
    check_rotation_consumes_the_old_token,
    check_signing_algorithm,
    check_ssl_redirect_has_a_way_to_see_tls,
)
from identity.security import LoginGuard, client_ip
from identity.tests.base import STRONG_PASSWORD, IdentityAPITestCase

LOCMEM = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": "identity-default",
    }
}
SHARED = {
    "default": {
        "BACKEND": "django.core.cache.backends.redis.RedisCache",
        "LOCATION": "redis://127.0.0.1:6379/1",
    }
}


class ClientAddressTests(SimpleTestCase):
    """``client_ip`` decides who a failed login is counted against."""

    def setUp(self) -> None:
        self.factory = RequestFactory()

    def request(self, forwarded: str | None = None, remote: str = "203.0.113.9"):
        extra = {"REMOTE_ADDR": remote}
        if forwarded is not None:
            extra["HTTP_X_FORWARDED_FOR"] = forwarded
        return self.factory.post("/api/auth/login/", **extra)

    @override_settings(TRUST_PROXY_HEADERS=False)
    def test_forwarded_for_is_ignored_when_no_proxy_is_trusted(self):
        request = self.request(forwarded="1.2.3.4")
        self.assertEqual(client_ip(request), "203.0.113.9")

    @override_settings(TRUST_PROXY_HEADERS=True, TRUST_PROXY_COUNT=1)
    def test_the_hop_added_by_the_trusted_proxy_is_used_not_the_clients_own(self):
        """
        With one proxy in front, the rightmost entry is the address the proxy
        actually saw. Everything to its left is whatever the client sent, so
        reading the leading entry would let a client pick its own identity.
        """
        request = self.request(forwarded="10.0.0.1, 198.51.100.7")
        self.assertEqual(client_ip(request), "198.51.100.7")

    @override_settings(TRUST_PROXY_HEADERS=True, TRUST_PROXY_COUNT=2)
    def test_two_trusted_proxies_read_two_hops_from_the_right(self):
        request = self.request(forwarded="10.0.0.1, 198.51.100.7, 172.16.0.1")
        self.assertEqual(client_ip(request), "198.51.100.7")

    @override_settings(TRUST_PROXY_HEADERS=True, TRUST_PROXY_COUNT=2)
    def test_a_short_forwarded_chain_does_not_index_out_of_range(self):
        request = self.request(forwarded="198.51.100.7")
        self.assertEqual(client_ip(request), "198.51.100.7")

    @override_settings(TRUST_PROXY_HEADERS=True, TRUST_PROXY_COUNT=1)
    def test_an_empty_forwarded_header_falls_back_to_the_socket(self):
        self.assertEqual(client_ip(self.request(forwarded="")), "203.0.113.9")
        self.assertEqual(client_ip(self.request(forwarded=" , ")), "203.0.113.9")

    def test_a_missing_remote_addr_never_crashes(self):
        request = self.factory.post("/api/auth/login/")
        request.META.pop("REMOTE_ADDR", None)
        self.assertTrue(client_ip(request))


class LockoutCannotBeBypassedTests(IdentityAPITestCase):
    """The lockout counter must not be resettable by the caller."""

    URL = "/api/auth/login/"

    def setUp(self) -> None:
        super().setUp()
        self.user = self.make_user("target")

    @override_settings(LOGIN_FAILURE_LIMIT=3, TRUST_PROXY_HEADERS=False)
    def test_rotating_x_forwarded_for_does_not_earn_fresh_attempts(self):
        for index in range(3):
            self.client.post(
                self.URL,
                {"identifier": "target", "password": "wrong-password-11"},
                format="json",
                HTTP_X_FORWARDED_FOR=f"10.0.0.{index}",
            )

        blocked = self.client.post(
            self.URL,
            {"identifier": "target", "password": STRONG_PASSWORD},
            format="json",
            HTTP_X_FORWARDED_FOR="10.0.0.99",
        )
        self.assertEqual(blocked.status_code, 429)
        self.assertEqual(
            blocked.data["error"]["code"], "too_many_failed_attempts"
        )

    @override_settings(
        LOGIN_FAILURE_LIMIT=3,
        REST_FRAMEWORK={
            "DEFAULT_THROTTLE_RATES": {"auth_login": "2/min"},
            "DEFAULT_THROTTLE_CLASSES": [],
            "EXCEPTION_HANDLER": "identity.exceptions.rfc7807_exception_handler",
            "NUM_PROXIES": 0,
        },
    )
    def test_rotating_x_forwarded_for_does_not_reset_the_request_throttle(self):
        """
        Regression: DRF's default NUM_PROXIES of None reads the *leading*
        X-Forwarded-For entry, so a client could mint a new throttle bucket per
        request simply by varying the header.
        """
        codes = [
            self.client.post(
                self.URL,
                {"identifier": "target", "password": STRONG_PASSWORD},
                format="json",
                HTTP_X_FORWARDED_FOR=f"10.0.0.{index}",
            ).status_code
            for index in range(4)
        ]
        self.assertIn(429, codes, codes)

    @override_settings(LOGIN_FAILURE_LIMIT=5)
    def test_the_failure_counter_accumulates_rather_than_resetting(self):
        for expected in (1, 2, 3):
            self.assertEqual(
                LoginGuard.register_failure("target", "203.0.113.9"), expected
            )
        self.assertFalse(LoginGuard.is_locked("target", "203.0.113.9"))

        LoginGuard.register_failure("target", "203.0.113.9")
        LoginGuard.register_failure("target", "203.0.113.9")
        self.assertTrue(LoginGuard.is_locked("target", "203.0.113.9"))

        LoginGuard.reset("target", "203.0.113.9")
        self.assertFalse(LoginGuard.is_locked("target", "203.0.113.9"))

    @override_settings(LOGIN_FAILURE_LIMIT=2)
    def test_the_counter_is_scoped_to_one_identifier_and_address(self):
        LoginGuard.register_failure("target", "203.0.113.9")
        LoginGuard.register_failure("target", "203.0.113.9")

        self.assertTrue(LoginGuard.is_locked("target", "203.0.113.9"))
        self.assertFalse(LoginGuard.is_locked("target", "198.51.100.1"))
        self.assertFalse(LoginGuard.is_locked("someone-else", "203.0.113.9"))

    def test_the_identifier_is_not_stored_in_the_clear(self):
        """A cache dump must not become a list of attempted usernames."""
        key = LoginGuard._key("victim@example.com", "203.0.113.9")
        self.assertNotIn("victim", key)
        self.assertNotIn("example.com", key)


class PasswordChangeThrottleTests(IdentityAPITestCase):
    URL = "/api/auth/password/change/"

    @override_settings(
        REST_FRAMEWORK={
            "DEFAULT_THROTTLE_RATES": {"auth_password_change": "2/min"},
            "DEFAULT_THROTTLE_CLASSES": [],
            "EXCEPTION_HANDLER": "identity.exceptions.rfc7807_exception_handler",
            "NUM_PROXIES": 0,
        }
    )
    def test_password_change_is_rate_limited(self):
        """
        The most expensive authenticated endpoint in the service: it verifies
        one password hash and computes another, so it needs a limit of its own.
        """
        self.make_user("spender")
        tokens = self.login("spender")

        codes = [
            self.client.post(
                self.URL,
                {"current_password": "wrong-password-11", "new_password": "N0pe!Nope99xy"},
                format="json",
                **self.bearer(tokens["access_token"]),
            ).status_code
            for _ in range(4)
        ]
        self.assertIn(429, codes, codes)


class EnvironmentParsingTests(SimpleTestCase):
    """Malformed configuration must name the variable, not dump a traceback."""

    def test_a_non_numeric_integer_setting_is_reported_clearly(self):
        import os

        from config.settings import env_int

        os.environ["IDENTITY_TEST_INT"] = "not-a-number"
        try:
            with self.assertRaises(ImproperlyConfigured) as caught:
                env_int("IDENTITY_TEST_INT", 5)
            self.assertIn("IDENTITY_TEST_INT", str(caught.exception))
        finally:
            del os.environ["IDENTITY_TEST_INT"]

    def test_an_absent_or_blank_value_uses_the_default(self):
        import os

        from config.settings import env_int

        self.assertEqual(env_int("IDENTITY_TEST_ABSENT", 7), 7)
        os.environ["IDENTITY_TEST_BLANK"] = "   "
        try:
            self.assertEqual(env_int("IDENTITY_TEST_BLANK", 7), 7)
        finally:
            del os.environ["IDENTITY_TEST_BLANK"]


class DeploymentCheckTests(SimpleTestCase):
    """``manage.py check --deploy`` has to catch the unsafe-but-valid setups."""

    @override_settings(DEBUG=False, CACHES=LOCMEM)
    def test_per_process_cache_is_flagged_in_production(self):
        findings = check_cache_is_shared(None)
        self.assertEqual([f.id for f in findings], ["identity.W001"])
        self.assertIsInstance(findings[0], Warning)

    @override_settings(DEBUG=True, CACHES=LOCMEM)
    def test_per_process_cache_is_fine_in_development(self):
        self.assertEqual(check_cache_is_shared(None), [])

    @override_settings(DEBUG=False, CACHES=SHARED)
    def test_a_shared_cache_passes(self):
        self.assertEqual(check_cache_is_shared(None), [])

    @override_settings(JWT_BLACKLIST_BACKEND="redis")
    def test_a_redis_only_revocation_ledger_is_flagged(self):
        findings = check_revocation_store_is_durable(None)
        self.assertEqual([f.id for f in findings], ["identity.W002"])

    @override_settings(JWT_BLACKLIST_BACKEND="chained")
    def test_the_chained_backend_is_not_flagged(self):
        self.assertEqual(check_revocation_store_is_durable(None), [])

    @override_settings(JWT_BLACKLIST_BACKEND="db")
    def test_the_database_backend_is_not_flagged(self):
        self.assertEqual(check_revocation_store_is_durable(None), [])

    @override_settings(JWT_ALGORITHM="HS256")
    def test_a_symmetric_signing_algorithm_is_an_error_not_a_warning(self):
        findings = check_signing_algorithm(None)
        self.assertEqual([f.id for f in findings], ["identity.E001"])
        self.assertIsInstance(findings[0], Error)

    @override_settings(JWT_ALGORITHM="RS256")
    def test_the_default_algorithm_passes(self):
        self.assertEqual(check_signing_algorithm(None), [])

    @override_settings(SECURE_SSL_REDIRECT=True, SECURE_PROXY_SSL_HEADER=None)
    def test_ssl_redirect_with_no_trusted_proto_header_is_flagged(self):
        """The redirect-loop footgun of terminating TLS at a proxy."""
        findings = check_ssl_redirect_has_a_way_to_see_tls(None)
        self.assertEqual([f.id for f in findings], ["identity.W003"])

    @override_settings(
        SECURE_SSL_REDIRECT=True,
        SECURE_PROXY_SSL_HEADER=("HTTP_X_FORWARDED_PROTO", "https"),
    )
    def test_ssl_redirect_behind_a_trusted_proxy_passes(self):
        self.assertEqual(check_ssl_redirect_has_a_way_to_see_tls(None), [])

    @override_settings(SECURE_SSL_REDIRECT=False, SECURE_PROXY_SSL_HEADER=None)
    def test_no_ssl_redirect_means_nothing_to_warn_about(self):
        self.assertEqual(check_ssl_redirect_has_a_way_to_see_tls(None), [])


class RotationConsistencyCheckTests(SimpleTestCase):
    """Rotation that consumes nothing has no replay to detect."""

    @override_settings(
        JWT_ROTATE_REFRESH_TOKENS=True, JWT_BLACKLIST_AFTER_ROTATION=False
    )
    def test_rotating_without_consuming_is_flagged(self):
        findings = check_rotation_consumes_the_old_token(None)
        self.assertEqual([f.id for f in findings], ["identity.W004"])

    @override_settings(
        JWT_ROTATE_REFRESH_TOKENS=True, JWT_BLACKLIST_AFTER_ROTATION=True
    )
    def test_the_default_combination_passes(self):
        self.assertEqual(check_rotation_consumes_the_old_token(None), [])

    @override_settings(
        JWT_ROTATE_REFRESH_TOKENS=False, JWT_BLACKLIST_AFTER_ROTATION=False
    )
    def test_rotation_disabled_entirely_is_a_coherent_choice(self):
        self.assertEqual(check_rotation_consumes_the_old_token(None), [])
