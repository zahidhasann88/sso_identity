"""
Revocation tests — the blacklist is the security control that makes stateless
tokens revocable, so it gets its own suite.
"""

from __future__ import annotations

from datetime import timedelta

from django.test import override_settings
from django.utils import timezone

from identity.blacklist import DatabaseBlacklist, get_blacklist
from identity.models import BlacklistedToken
from identity.tests.base import IdentityAPITestCase
from identity.tokens import AccessToken, RefreshToken


class LogoutEndpointTests(IdentityAPITestCase):
    URL = "/api/auth/logout/"

    def setUp(self) -> None:
        super().setUp()
        self.user = self.make_user("erin")
        self.tokens = self.login("erin")

    def test_logout_writes_the_jti_into_the_blacklist_table(self):
        response = self.client.post(
            self.URL, {"refresh": self.tokens["refresh_token"]}, format="json"
        )
        self.assertEqual(response.status_code, 200, response.data)
        self.assertTrue(response.data["revoked"])

        jti = self.tokens["refresh_jti"]
        self.assertEqual(response.data["token_jti"], jti)

        row = BlacklistedToken.objects.get(pk=jti)
        self.assertEqual(row.user_id, self.user.pk)
        self.assertEqual(row.token_type, "refresh")
        self.assertEqual(row.reason, BlacklistedToken.Reason.LOGOUT)
        self.assertGreater(row.expires_at, timezone.now())
        self.assertIsNotNone(row.invalidated_at)

    def test_blacklisted_refresh_token_cannot_mint_new_access_tokens(self):
        self.client.post(
            self.URL, {"refresh": self.tokens["refresh_token"]}, format="json"
        )
        response = self.client.post(
            "/api/auth/refresh/", {"refresh": self.tokens["refresh_token"]},
            format="json",
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.data["error"]["code"], "token_revoked")

    def test_logout_also_kills_the_sessions_live_access_token(self):
        """
        The headline requirement: after logout, a still-unexpired access token
        from that session must be rejected on protected routes.
        """
        access = self.tokens["access_token"]
        self.assertEqual(
            self.client.get("/api/auth/me/", **self.bearer(access)).status_code, 200
        )

        self.client.post(
            self.URL, {"refresh": self.tokens["refresh_token"]}, format="json"
        )

        after = self.client.get("/api/auth/me/", **self.bearer(access))
        self.assertEqual(after.status_code, 401)
        self.assertIn(
            after.data["error"]["code"], {"token_revoked", "session_revoked"}
        )

    def test_logout_is_idempotent(self):
        first = self.client.post(
            self.URL, {"refresh": self.tokens["refresh_token"]}, format="json"
        )
        second = self.client.post(
            self.URL, {"refresh": self.tokens["refresh_token"]}, format="json"
        )
        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 200)
        self.assertFalse(first.data["already_revoked"])
        self.assertTrue(second.data["already_revoked"])
        self.assertEqual(
            BlacklistedToken.objects.filter(pk=self.tokens["refresh_jti"]).count(), 1
        )

    def test_logout_everywhere_revokes_every_session(self):
        session_a = self.tokens
        session_b = self.login("erin")
        session_c = self.login("erin")

        for session in (session_a, session_b, session_c):
            self.assertEqual(
                self.client.get(
                    "/api/auth/me/", **self.bearer(session["access_token"])
                ).status_code,
                200,
            )

        response = self.client.post(
            self.URL,
            {"refresh": session_a["refresh_token"], "all_sessions": True},
            format="json",
        )
        self.assertEqual(response.status_code, 200, response.data)
        self.assertTrue(response.data["all_sessions_revoked"])
        self.assertEqual(response.data["token_version"], 1)

        for session in (session_a, session_b, session_c):
            probe = self.client.get(
                "/api/auth/me/", **self.bearer(session["access_token"])
            )
            self.assertEqual(probe.status_code, 401)
            self.assertIn(
                probe.data["error"]["code"],
                {"token_version_stale", "token_revoked", "session_revoked"},
            )

            refreshed = self.client.post(
                "/api/auth/refresh/", {"refresh": session["refresh_token"]},
                format="json",
            )
            self.assertEqual(refreshed.status_code, 401)

    def test_logout_everywhere_does_not_touch_other_users(self):
        other = self.make_user("frank")
        other_tokens = self.login("frank")

        self.client.post(
            self.URL,
            {"refresh": self.tokens["refresh_token"], "all_sessions": True},
            format="json",
        )

        probe = self.client.get(
            "/api/auth/me/", **self.bearer(other_tokens["access_token"])
        )
        self.assertEqual(probe.status_code, 200)
        other.refresh_from_db()
        self.assertEqual(other.token_version, 0)

    def test_logout_accepts_an_expired_refresh_token(self):
        with override_settings(REFRESH_TOKEN_LIFETIME=timedelta(seconds=-5),
                               JWT_LEEWAY_SECONDS=0):
            stale = RefreshToken.for_user(self.user).encode()
        response = self.client.post(self.URL, {"refresh": stale}, format="json")
        self.assertEqual(response.status_code, 200, response.data)

    def test_logout_rejects_a_forged_token(self):
        forged = self.tokens["refresh_token"][:-4] + "AAAA"
        response = self.client.post(self.URL, {"refresh": forged}, format="json")
        self.assertEqual(response.status_code, 401)

    def test_logout_rejects_an_access_token(self):
        response = self.client.post(
            self.URL, {"refresh": self.tokens["access_token"]}, format="json"
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.data["error"]["code"], "token_type_mismatch")

    def test_other_sessions_survive_a_single_logout(self):
        session_b = self.login("erin")
        self.client.post(
            self.URL, {"refresh": self.tokens["refresh_token"]}, format="json"
        )
        probe = self.client.get(
            "/api/auth/me/", **self.bearer(session_b["access_token"])
        )
        self.assertEqual(probe.status_code, 200)


class BlacklistStoreTests(IdentityAPITestCase):
    """Direct unit tests on the revocation store contract."""

    def setUp(self) -> None:
        super().setUp()
        self.user = self.make_user("grace")
        self.store = DatabaseBlacklist()

    def test_revoke_and_lookup(self):
        token = RefreshToken.for_user(self.user)
        self.assertFalse(self.store.is_revoked(token.jti))

        created = self.store.revoke(token.jti, token.expires_at, user=self.user)
        self.assertTrue(created)
        self.assertTrue(self.store.is_revoked(token.jti))

        again = self.store.revoke(token.jti, token.expires_at, user=self.user)
        self.assertFalse(again)  # idempotent

    def test_purge_removes_only_expired_rows(self):
        live = RefreshToken.for_user(self.user)
        self.store.revoke(live.jti, live.expires_at, user=self.user)

        BlacklistedToken.objects.create(
            token_jti="expired-entry",
            expires_at=timezone.now() - timedelta(hours=1),
            user=self.user,
        )
        self.assertEqual(BlacklistedToken.objects.count(), 2)

        purged = self.store.purge_expired()
        self.assertEqual(purged, 1)
        self.assertTrue(self.store.is_revoked(live.jti))
        self.assertFalse(self.store.is_revoked("expired-entry"))

    def test_default_backend_is_the_database_store(self):
        self.assertIsInstance(get_blacklist(), DatabaseBlacklist)

    def test_queryset_helpers(self):
        BlacklistedToken.objects.create(
            token_jti="old", expires_at=timezone.now() - timedelta(minutes=1)
        )
        BlacklistedToken.objects.create(
            token_jti="new", expires_at=timezone.now() + timedelta(minutes=10)
        )
        self.assertEqual(BlacklistedToken.objects.expired().count(), 1)
        self.assertEqual(BlacklistedToken.objects.active().count(), 1)

    def test_purge_management_command(self):
        from io import StringIO

        from django.core.management import call_command

        BlacklistedToken.objects.create(
            token_jti="stale", expires_at=timezone.now() - timedelta(days=1)
        )
        out = StringIO()
        call_command("purge_blacklist", stdout=out)
        self.assertIn("Purged 1", out.getvalue())
        self.assertEqual(BlacklistedToken.objects.count(), 0)

    def test_revoke_user_tokens_management_command(self):
        from io import StringIO

        from django.core.management import call_command

        tokens = self.login("grace")
        out = StringIO()
        call_command("revoke_user_tokens", username="grace", stdout=out)

        self.user.refresh_from_db()
        self.assertEqual(self.user.token_version, 1)
        probe = self.client.get("/api/auth/me/", **self.bearer(tokens["access_token"]))
        self.assertEqual(probe.status_code, 401)


class IntrospectionTests(IdentityAPITestCase):
    URL = "/api/auth/introspect/"

    def setUp(self) -> None:
        super().setUp()
        self.user = self.make_user("heidi")
        self.tokens = self.login("heidi")
        self.auth = self.bearer(self.tokens["access_token"])

    def test_active_token_reports_active(self):
        response = self.client.post(
            self.URL, {"token": self.tokens["access_token"]}, format="json", **self.auth
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data["active"])
        self.assertEqual(response.data["sub"], str(self.user.pk))
        self.assertEqual(response.data["typ"], "access")

    def test_revoked_token_reports_inactive(self):
        self.client.post(
            "/api/auth/logout/", {"refresh": self.tokens["refresh_token"]},
            format="json",
        )
        fresh = self.login("heidi")
        response = self.client.post(
            self.URL,
            {"token": self.tokens["refresh_token"]},
            format="json",
            **self.bearer(fresh["access_token"]),
        )
        self.assertFalse(response.data["active"])
        self.assertEqual(response.data["reason"], "token_revoked")

    def test_forged_token_reports_inactive_rather_than_erroring(self):
        response = self.client.post(
            self.URL, {"token": "a.b.c"}, format="json", **self.auth
        )
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.data["active"])

    def test_introspection_requires_authentication(self):
        response = self.client.post(
            self.URL, {"token": self.tokens["access_token"]}, format="json"
        )
        self.assertEqual(response.status_code, 401)

    def test_expired_token_reports_inactive(self):
        with override_settings(ACCESS_TOKEN_LIFETIME=timedelta(seconds=-30),
                               JWT_LEEWAY_SECONDS=0):
            stale = AccessToken.for_user(self.user).encode()
            response = self.client.post(
                self.URL, {"token": stale}, format="json", **self.auth
            )
        self.assertFalse(response.data["active"])
        self.assertEqual(response.data["reason"], "token_expired")
