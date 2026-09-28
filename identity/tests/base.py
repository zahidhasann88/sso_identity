"""Shared fixtures/utilities for the security test-suite."""

from __future__ import annotations

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import override_settings
from rest_framework.test import APITestCase

from identity.blacklist import reset_blacklist_cache
from identity.models import SystemRole

User = get_user_model()

STRONG_PASSWORD = "Xq7!vartan-Spindle42"

# Pinned, because settings are environment-driven: a developer's .env may
# legitimately point JWT_ISSUER at localhost and the suite must not depend on it.
TEST_ISSUER = "https://sso.identity.local"
TEST_AUDIENCE = ["identity-clients"]


def make_user(
    username: str = "alice",
    email: str | None = None,
    password: str = STRONG_PASSWORD,
    role: str = SystemRole.USER,
    **extra,
):
    """
    Create a persisted user.

    A module-level function rather than only a helper on the base case, so the
    concurrency tests — which need ``TransactionTestCase`` and therefore cannot
    inherit from :class:`IdentityAPITestCase` — build users the same way.
    """
    user = User(
        username=username,
        email=email or f"{username}@example.com",
        system_role=role,
        metadata=extra.pop("metadata", {"token_version": 0}),
        **extra,
    )
    user.set_password(password)
    user.save()
    return user


@override_settings(JWT_ISSUER=TEST_ISSUER, JWT_AUDIENCE=TEST_AUDIENCE)
class IdentityAPITestCase(APITestCase):
    """
    Base case: a pinned token policy, with rate limits and login lockouts
    reset between tests.

    ``override_settings`` on the class is inherited by subclasses, so every
    test in the suite runs against ``TEST_ISSUER``/``TEST_AUDIENCE``.
    """

    def setUp(self) -> None:
        super().setUp()
        cache.clear()          # DRF throttles + LoginGuard share the cache
        reset_blacklist_cache()

    def tearDown(self) -> None:
        cache.clear()
        super().tearDown()

    make_user = staticmethod(make_user)

    def login(self, identifier: str, password: str = STRONG_PASSWORD):
        response = self.client.post(
            "/api/auth/login/",
            {"identifier": identifier, "password": password},
            format="json",
        )
        assert response.status_code == 200, response.data
        return response.data["tokens"]

    def bearer(self, access_token: str) -> dict:
        return {"HTTP_AUTHORIZATION": f"Bearer {access_token}"}
