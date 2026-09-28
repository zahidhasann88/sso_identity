"""
Race conditions and authorization edges.

These cover what a sequential suite cannot see: two requests arriving with the
same credential at the same moment. Where threads cannot be made to interleave
reliably, the two halves of the check-then-act are interleaved by hand instead.
"""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

from django.contrib.auth import get_user_model
from django.db import connections
from django.test import TransactionTestCase, override_settings
from rest_framework.exceptions import ValidationError as DRFValidationError
from rest_framework.test import APIClient

from identity.blacklist import reset_blacklist_cache
from identity.models import BlacklistedToken, SystemRole
from identity.serializers import RegistrationSerializer
from identity.tests.base import STRONG_PASSWORD, IdentityAPITestCase, make_user

User = get_user_model()

TEST_POLICY = override_settings(
    JWT_ISSUER="https://sso.identity.local",
    JWT_AUDIENCE=["identity-clients"],
)


@TEST_POLICY
class ConcurrentRefreshTests(TransactionTestCase):
    """
    Rotation has to be single-use under concurrency, not just in sequence.

    ``TransactionTestCase`` because the threads need to see each other's
    committed rows — the shared transaction of ``TestCase`` would hide them.
    """

    URL = "/api/auth/refresh/"
    reset_sequences = False

    def setUp(self) -> None:
        super().setUp()
        reset_blacklist_cache()
        self.user = make_user("racer")
        response = APIClient().post(
            "/api/auth/login/",
            {"identifier": "racer", "password": STRONG_PASSWORD},
            format="json",
        )
        self.assertEqual(response.status_code, 200, response.data)
        self.tokens = response.data["tokens"]

    def tearDown(self) -> None:
        BlacklistedToken.objects.all().delete()
        super().tearDown()

    def _refresh_concurrently(self, refresh_token: str, workers: int):
        """Fire `workers` simultaneous refreshes of the same token."""
        barrier = threading.Barrier(workers)

        def attempt():
            try:
                barrier.wait(timeout=10)
                return APIClient().post(
                    self.URL, {"refresh": refresh_token}, format="json"
                )
            finally:
                # Each thread gets its own connection; the test database
                # cannot be dropped until they are closed.
                connections.close_all()

        with ThreadPoolExecutor(max_workers=workers) as pool:
            return [future.result() for future in
                    [pool.submit(attempt) for _ in range(workers)]]

    def test_only_one_of_several_simultaneous_rotations_succeeds(self):
        """
        Regression: the endpoint used to check ``is_revoked`` and then revoke
        in two steps, so two requests arriving together both passed the check
        and both were handed a fresh, valid refresh token — the exact split of
        one session into two that rotation exists to prevent.
        """
        responses = self._refresh_concurrently(self.tokens["refresh_token"], workers=6)

        statuses = sorted(response.status_code for response in responses)
        self.assertEqual(
            statuses.count(200), 1,
            f"exactly one rotation may succeed, got {statuses}",
        )
        self.assertEqual(statuses.count(401), 5, statuses)

        for response in responses:
            if response.status_code == 401:
                self.assertEqual(response.data["error"]["code"], "token_revoked")

        # Recorded once, by definition of the primary key that makes it atomic.
        self.assertEqual(
            BlacklistedToken.objects.filter(
                pk=self.tokens["refresh_jti"]
            ).count(),
            1,
        )

    def test_losing_the_rotation_race_terminates_the_session(self):
        """A replay is indistinguishable from theft, so the session dies."""
        responses = self._refresh_concurrently(self.tokens["refresh_token"], workers=4)
        winner = next(r for r in responses if r.status_code == 200)

        self.assertTrue(
            BlacklistedToken.objects.filter(
                pk=self.tokens["session_id"],
                reason=BlacklistedToken.Reason.REUSE_DETECTED,
            ).exists(),
            "the session id must be revoked once a consumed token is replayed",
        )

        # Even the winner's brand-new tokens are dead: they belong to the
        # session that was just terminated.
        probe = APIClient().get(
            "/api/auth/me/",
            HTTP_AUTHORIZATION=f"Bearer {winner.data['access_token']}",
        )
        self.assertEqual(probe.status_code, 401)
        self.assertEqual(probe.data["error"]["code"], "session_revoked")


class RegistrationRaceTests(IdentityAPITestCase):
    """
    The uniqueness pre-check is a read, so the constraint has the last word.

    Threads are the wrong tool here: registration hashes a password with
    Argon2, which makes one request finish long before the next one validates,
    so a thread pool never actually interleaves the read and the insert. These
    tests interleave them deliberately instead, which is both deterministic and
    a closer match to what two application servers do.

    These assert at the serializer boundary rather than over HTTP on purpose:
    ModelSerializer attaches a UniqueValidator to every unique model field, so
    an exact-case duplicate arriving over HTTP is rejected during validation
    and never reaches the insert. The constraint is what catches the *race*,
    and the race is what these tests are about.
    """

    URL = "/api/auth/register/"

    def payload(self, **overrides) -> dict:
        data = {
            "username": "twin",
            "email": "twin@example.com",
            "password": STRONG_PASSWORD,
            "password_confirm": STRONG_PASSWORD,
        }
        data.update(overrides)
        return data

    def test_losing_the_uniqueness_race_raises_a_validation_error(self):
        """
        Regression: the loser of this race raised a bare Django
        ``ValidationError`` out of ``save()`` — from the model's own
        ``full_clean`` — which DRF's handler does not recognise, so the client
        saw a 500 for what is an ordinary conflict. (The even narrower window
        between ``full_clean`` and the INSERT surfaces as IntegrityError, which
        is translated the same way.)
        """
        serializer = RegistrationSerializer(
            data=self.payload(), context={"request": None}
        )
        self.assertTrue(serializer.is_valid(), serializer.errors)

        # The competing request commits between validation and the insert.
        make_user("twin", email="twin@example.com")

        with self.assertRaises(DRFValidationError):
            serializer.save()

    def test_the_database_state_is_not_half_written(self):
        """The failed insert must leave nothing behind for the next attempt."""
        before = User.objects.count()
        serializer = RegistrationSerializer(
            data=self.payload(), context={"request": None}
        )
        self.assertTrue(serializer.is_valid(), serializer.errors)
        make_user("twin", email="twin@example.com")

        with self.assertRaises(DRFValidationError):
            serializer.save()

        self.assertEqual(User.objects.count(), before + 1)  # only the winner

        # Still usable: the savepoint rolled back without poisoning the
        # surrounding transaction.
        self.assertTrue(User.objects.filter(username="twin").exists())


class IntrospectionAuthorizationTests(IdentityAPITestCase):
    """Introspection must not become a directory of other people's sessions."""

    URL = "/api/auth/introspect/"

    def setUp(self) -> None:
        super().setUp()
        self.owner = self.make_user("owner")
        self.other = self.make_user("nosy")
        self.admin = self.make_user("auditor", role=SystemRole.ADMIN)

        self.owner_tokens = self.login("owner")
        self.other_tokens = self.login("nosy")

    def test_a_subject_may_introspect_its_own_token(self):
        response = self.client.post(
            self.URL,
            {"token": self.owner_tokens["access_token"]},
            format="json",
            **self.bearer(self.owner_tokens["access_token"]),
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data["active"])

    def test_another_user_cannot_introspect_someone_elses_token(self):
        response = self.client.post(
            self.URL,
            {"token": self.owner_tokens["access_token"]},
            format="json",
            **self.bearer(self.other_tokens["access_token"]),
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.data["error"]["code"], "not_token_owner")
        # Nothing about the token leaks alongside the refusal.
        body = str(response.data)
        self.assertNotIn(str(self.owner.pk), body)
        self.assertNotIn("identity:read", body)

    def test_a_refresh_token_of_another_user_is_equally_off_limits(self):
        response = self.client.post(
            self.URL,
            {"token": self.owner_tokens["refresh_token"]},
            format="json",
            **self.bearer(self.other_tokens["access_token"]),
        )
        self.assertEqual(response.status_code, 403)

    def test_an_admin_may_introspect_any_token(self):
        admin_tokens = self.login("auditor")
        response = self.client.post(
            self.URL,
            {"token": self.owner_tokens["access_token"]},
            format="json",
            **self.bearer(admin_tokens["access_token"]),
        )
        self.assertEqual(response.status_code, 200, response.data)
        self.assertTrue(response.data["active"])
        self.assertEqual(response.data["sub"], str(self.owner.pk))

    def test_an_unverifiable_token_is_inactive_before_any_ownership_check(self):
        """There is no subject to compare against, so the answer is 'inactive'."""
        response = self.client.post(
            self.URL,
            {"token": "a.b.c"},
            format="json",
            **self.bearer(self.other_tokens["access_token"]),
        )
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.data["active"])


class LogoutWithoutAccessTokenTests(IdentityAPITestCase):
    """Signing out must not depend on still holding a usable access token."""

    URL = "/api/auth/logout/"

    def setUp(self) -> None:
        super().setUp()
        self.user = self.make_user("leaver")
        self.tokens = self.login("leaver")

    def test_logout_works_with_an_expired_access_token_in_the_header(self):
        from datetime import timedelta

        from identity.tokens import AccessToken

        with override_settings(
            ACCESS_TOKEN_LIFETIME=timedelta(seconds=-60), JWT_LEEWAY_SECONDS=0
        ):
            stale_access = AccessToken.for_user(self.user).encode()

        response = self.client.post(
            self.URL,
            {"refresh": self.tokens["refresh_token"]},
            format="json",
            **self.bearer(stale_access),
        )
        self.assertEqual(response.status_code, 200, response.data)
        self.assertTrue(response.data["revoked"])

    def test_logout_works_with_a_garbage_authorization_header(self):
        response = self.client.post(
            self.URL,
            {"refresh": self.tokens["refresh_token"]},
            format="json",
            HTTP_AUTHORIZATION="Bearer not-a-token",
        )
        self.assertEqual(response.status_code, 200, response.data)

    def test_an_invalid_refresh_token_is_still_refused(self):
        """Optional authentication must not weaken the body's credential."""
        response = self.client.post(
            self.URL, {"refresh": "clearly.not.ajwt"}, format="json"
        )
        self.assertEqual(response.status_code, 401)
