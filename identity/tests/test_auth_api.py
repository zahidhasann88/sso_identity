"""End-to-end API tests: registration, login, refresh rotation, protected routes."""

from __future__ import annotations

from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import override_settings

from identity.models import SystemRole
from identity.tests.base import STRONG_PASSWORD, IdentityAPITestCase
from identity.tokens import AccessToken

User = get_user_model()


class RegistrationTests(IdentityAPITestCase):
    URL = "/api/auth/register/"

    def payload(self, **overrides) -> dict:
        data = {
            "username": "newcomer",
            "email": "newcomer@example.com",
            "password": STRONG_PASSWORD,
            "password_confirm": STRONG_PASSWORD,
            "first_name": "New",
            "last_name": "Comer",
            "metadata": {"tenant": "acme", "region": "eu-west-1"},
        }
        data.update(overrides)
        return data

    def test_registration_creates_user_and_returns_token_pair(self):
        response = self.client.post(self.URL, self.payload(), format="json")
        self.assertEqual(response.status_code, 201, response.data)

        self.assertEqual(response.data["user"]["username"], "newcomer")
        self.assertEqual(response.data["user"]["system_role"], SystemRole.USER)
        self.assertEqual(response.data["user"]["metadata"]["tenant"], "acme")
        self.assertIn("access_token", response.data["tokens"])
        self.assertIn("refresh_token", response.data["tokens"])

        user = User.objects.get(username="newcomer")
        self.assertTrue(user.check_password(STRONG_PASSWORD))

    def test_password_is_hashed_never_stored_or_echoed(self):
        response = self.client.post(self.URL, self.payload(), format="json")
        user = User.objects.get(username="newcomer")

        self.assertNotEqual(user.password, STRONG_PASSWORD)
        self.assertTrue(
            user.password.startswith(("pbkdf2_", "argon2", "scrypt")), user.password
        )
        self.assertNotIn(STRONG_PASSWORD, str(response.data))

    def test_argon2_is_optional_and_pbkdf2_is_always_the_fallback(self):
        """
        Regression: ``PASSWORD_HASHERS`` once listed Argon2id unconditionally,
        so a deployment without ``argon2-cffi`` crashed at import time (the
        preferred hasher is loaded eagerly for the enumeration dummy hash).
        """
        from config.settings import password_hashers

        without = password_hashers(with_argon2=False)
        self.assertNotIn("django.contrib.auth.hashers.Argon2PasswordHasher", without)
        self.assertEqual(
            without[0],
            "django.contrib.auth.hashers.PBKDF2PasswordHasher",
            "PBKDF2 must be the preferred hasher when Argon2 is unavailable.",
        )

        with_argon2 = password_hashers(with_argon2=True)
        self.assertEqual(
            with_argon2[0],
            "django.contrib.auth.hashers.Argon2PasswordHasher",
            "Argon2id must stay preferred wherever it is installed.",
        )
        self.assertIn("django.contrib.auth.hashers.PBKDF2PasswordHasher", with_argon2)

    def test_preferred_password_hasher_is_always_loadable(self):
        """The actual crash path: encoding with the live configuration."""
        from django.contrib.auth.hashers import make_password

        encoded = make_password(STRONG_PASSWORD)
        self.assertTrue(encoded.startswith(("argon2", "pbkdf2_")), encoded)

    def test_weak_password_is_rejected(self):
        for weak in ("short1!", "password1234", "123456789012"):
            response = self.client.post(
                self.URL,
                self.payload(password=weak, password_confirm=weak),
                format="json",
            )
            self.assertEqual(response.status_code, 400, weak)
            self.assertEqual(response.data["error"]["code"], "validation_error")

    def test_mismatched_confirmation_is_rejected(self):
        response = self.client.post(
            self.URL, self.payload(password_confirm="Different!Pass99xy"), format="json"
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("password_confirm", response.data["error"]["fields"])

    def test_duplicate_username_and_email_are_rejected_case_insensitively(self):
        self.make_user("taken", email="taken@example.com")

        dup_user = self.client.post(
            self.URL,
            self.payload(username="TAKEN", email="other@example.com"),
            format="json",
        )
        self.assertEqual(dup_user.status_code, 400)

        dup_mail = self.client.post(
            self.URL,
            self.payload(username="other", email="TAKEN@example.com"),
            format="json",
        )
        self.assertEqual(dup_mail.status_code, 400)

    def test_anonymous_cannot_self_assign_admin_role(self):
        """Privilege-escalation attempt at the registration boundary."""
        response = self.client.post(
            self.URL, self.payload(system_role="ADMIN"), format="json"
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("system_role", response.data["error"]["fields"])
        self.assertFalse(User.objects.filter(system_role=SystemRole.ADMIN).exists())

    def test_admin_may_provision_elevated_roles(self):
        admin = self.make_user("root", role=SystemRole.ADMIN)
        tokens = self.login("root")

        response = self.client.post(
            self.URL,
            self.payload(system_role="DEVELOPER"),
            format="json",
            **self.bearer(tokens["access_token"]),
        )
        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual(response.data["user"]["system_role"], "DEVELOPER")
        self.assertEqual(admin.system_role, SystemRole.ADMIN)

    def test_reserved_metadata_keys_are_rejected(self):
        response = self.client.post(
            self.URL, self.payload(metadata={"token_version": 999}), format="json"
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("metadata", response.data["error"]["fields"])

    def test_invalid_username_shapes_are_rejected(self):
        for bad in ("ab", "-leading", "has space", "emoji🙂", "x" * 200):
            response = self.client.post(
                self.URL, self.payload(username=bad), format="json"
            )
            self.assertEqual(response.status_code, 400, bad)


class LoginTests(IdentityAPITestCase):
    URL = "/api/auth/login/"

    def setUp(self) -> None:
        super().setUp()
        self.user = self.make_user("alice")

    def test_login_with_username_or_email(self):
        for identifier in ("alice", "ALICE", "alice@example.com"):
            response = self.client.post(
                self.URL,
                {"identifier": identifier, "password": STRONG_PASSWORD},
                format="json",
            )
            self.assertEqual(response.status_code, 200, identifier)
            self.assertEqual(response.data["tokens"]["token_type"], "Bearer")

    def test_login_updates_last_login(self):
        self.assertIsNone(self.user.last_login)
        self.login("alice")
        self.user.refresh_from_db()
        self.assertIsNotNone(self.user.last_login)

    def test_wrong_password_returns_401_without_enumeration(self):
        bad_pw = self.client.post(
            self.URL, {"identifier": "alice", "password": "WrongPassword123!"},
            format="json",
        )
        unknown = self.client.post(
            self.URL, {"identifier": "ghost", "password": "WrongPassword123!"},
            format="json",
        )
        self.assertEqual(bad_pw.status_code, 401)
        self.assertEqual(unknown.status_code, 401)
        # Identical envelopes: the response cannot be used to probe accounts.
        self.assertEqual(bad_pw.data["error"]["code"], unknown.data["error"]["code"])
        self.assertEqual(bad_pw.data["error"]["detail"], unknown.data["error"]["detail"])

    def test_inactive_account_cannot_sign_in(self):
        self.user.is_active = False
        self.user.save(update_fields=["is_active"])
        response = self.client.post(
            self.URL, {"identifier": "alice", "password": STRONG_PASSWORD},
            format="json",
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.data["error"]["code"], "user_inactive")

    @override_settings(LOGIN_FAILURE_LIMIT=3)
    def test_repeated_failures_trigger_lockout(self):
        for _ in range(3):
            self.client.post(
                self.URL, {"identifier": "alice", "password": "nope-nope-nope1!"},
                format="json",
            )
        blocked = self.client.post(
            self.URL, {"identifier": "alice", "password": STRONG_PASSWORD},
            format="json",
        )
        self.assertEqual(blocked.status_code, 429)
        self.assertEqual(blocked.data["error"]["code"], "too_many_failed_attempts")
        self.assertIn("Retry-After", blocked)

    @override_settings(LOGIN_FAILURE_LIMIT=3)
    def test_successful_login_clears_the_failure_counter(self):
        for _ in range(2):
            self.client.post(
                self.URL, {"identifier": "alice", "password": "nope-nope-nope1!"},
                format="json",
            )
        self.login("alice")
        for _ in range(2):
            self.client.post(
                self.URL, {"identifier": "alice", "password": "nope-nope-nope1!"},
                format="json",
            )
        ok = self.client.post(
            self.URL, {"identifier": "alice", "password": STRONG_PASSWORD},
            format="json",
        )
        self.assertEqual(ok.status_code, 200)

    def test_missing_identifier_is_a_validation_error(self):
        response = self.client.post(self.URL, {"password": "x"}, format="json")
        self.assertEqual(response.status_code, 400)


class ProtectedRouteTests(IdentityAPITestCase):
    URL = "/api/auth/me/"

    def setUp(self) -> None:
        super().setUp()
        self.user = self.make_user("bob", role=SystemRole.DEVELOPER)
        self.tokens = self.login("bob")

    def test_valid_access_token_is_accepted(self):
        response = self.client.get(self.URL, **self.bearer(self.tokens["access_token"]))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["user"]["username"], "bob")
        self.assertEqual(response.data["token"]["sid"], self.tokens["session_id"])

    def test_missing_header_is_401(self):
        response = self.client.get(self.URL)
        self.assertEqual(response.status_code, 401)

    def test_malformed_authorization_headers_are_401(self):
        for header in (
            "Bearer",
            "Bearer a b",
            f"Token {self.tokens['access_token']}",
            self.tokens["access_token"],
        ):
            response = self.client.get(self.URL, HTTP_AUTHORIZATION=header)
            self.assertEqual(response.status_code, 401, header)

    def test_refresh_token_is_not_accepted_as_a_bearer_credential(self):
        response = self.client.get(
            self.URL, **self.bearer(self.tokens["refresh_token"])
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.data["error"]["code"], "token_type_mismatch")

    @override_settings(ACCESS_TOKEN_LIFETIME=timedelta(seconds=-60),
                       JWT_LEEWAY_SECONDS=0)
    def test_expired_access_token_is_401(self):
        stale = AccessToken.for_user(self.user).encode()
        response = self.client.get(self.URL, **self.bearer(stale))
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.data["error"]["code"], "token_expired")

    def test_deactivated_user_loses_access_immediately(self):
        self.user.is_active = False
        self.user.save(update_fields=["is_active"])
        response = self.client.get(self.URL, **self.bearer(self.tokens["access_token"]))
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.data["error"]["code"], "user_inactive")

    def test_deleted_user_token_is_rejected(self):
        access = self.tokens["access_token"]
        self.user.delete()
        response = self.client.get(self.URL, **self.bearer(access))
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.data["error"]["code"], "user_not_found")

    def test_www_authenticate_challenge_is_present(self):
        response = self.client.get(self.URL)
        self.assertIn("WWW-Authenticate", response)
        self.assertIn("Bearer", response["WWW-Authenticate"])


class RefreshRotationTests(IdentityAPITestCase):
    URL = "/api/auth/refresh/"

    def setUp(self) -> None:
        super().setUp()
        self.user = self.make_user("carol")
        self.tokens = self.login("carol")

    def test_refresh_returns_a_working_access_token(self):
        response = self.client.post(
            self.URL, {"refresh": self.tokens["refresh_token"]}, format="json"
        )
        self.assertEqual(response.status_code, 200, response.data)
        new_access = response.data["access_token"]
        self.assertNotEqual(new_access, self.tokens["access_token"])

        probe = self.client.get("/api/auth/me/", **self.bearer(new_access))
        self.assertEqual(probe.status_code, 200)

    def test_rotation_preserves_the_session_id(self):
        response = self.client.post(
            self.URL, {"refresh": self.tokens["refresh_token"]}, format="json"
        )
        self.assertEqual(response.data["session_id"], self.tokens["session_id"])
        self.assertIn("refresh_token", response.data)
        self.assertNotEqual(
            response.data["refresh_token"], self.tokens["refresh_token"]
        )

    def test_consumed_refresh_token_cannot_be_replayed(self):
        first = self.client.post(
            self.URL, {"refresh": self.tokens["refresh_token"]}, format="json"
        )
        self.assertEqual(first.status_code, 200)

        replay = self.client.post(
            self.URL, {"refresh": self.tokens["refresh_token"]}, format="json"
        )
        self.assertEqual(replay.status_code, 401)
        self.assertEqual(replay.data["error"]["code"], "token_revoked")

    def test_replay_detection_kills_the_whole_session(self):
        """Reusing a consumed token revokes the descendant tokens too."""
        rotated = self.client.post(
            self.URL, {"refresh": self.tokens["refresh_token"]}, format="json"
        ).data

        self.client.post(
            self.URL, {"refresh": self.tokens["refresh_token"]}, format="json"
        )  # replay -> session terminated

        after = self.client.post(
            self.URL, {"refresh": rotated["refresh_token"]}, format="json"
        )
        self.assertEqual(after.status_code, 401)
        self.assertIn(
            after.data["error"]["code"], {"session_revoked", "token_revoked"}
        )

        probe = self.client.get(
            "/api/auth/me/", **self.bearer(rotated["access_token"])
        )
        self.assertEqual(probe.status_code, 401)

    @override_settings(JWT_ROTATE_REFRESH_TOKENS=False)
    def test_rotation_can_be_disabled(self):
        first = self.client.post(
            self.URL, {"refresh": self.tokens["refresh_token"]}, format="json"
        )
        self.assertNotIn("refresh_token", first.data)

        again = self.client.post(
            self.URL, {"refresh": self.tokens["refresh_token"]}, format="json"
        )
        self.assertEqual(again.status_code, 200)

    def test_access_token_is_not_accepted_at_the_refresh_endpoint(self):
        response = self.client.post(
            self.URL, {"refresh": self.tokens["access_token"]}, format="json"
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.data["error"]["code"], "token_type_mismatch")

    @override_settings(REFRESH_TOKEN_LIFETIME=timedelta(seconds=-10),
                       JWT_LEEWAY_SECONDS=0)
    def test_expired_refresh_token_is_rejected(self):
        from identity.tokens import RefreshToken

        stale = RefreshToken.for_user(self.user).encode()
        response = self.client.post(self.URL, {"refresh": stale}, format="json")
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.data["error"]["code"], "token_expired")

    def test_garbage_refresh_token_is_rejected(self):
        response = self.client.post(
            self.URL, {"refresh": "clearly.not.ajwt"}, format="json"
        )
        self.assertEqual(response.status_code, 401)


class PasswordChangeTests(IdentityAPITestCase):
    URL = "/api/auth/password/change/"

    def setUp(self) -> None:
        super().setUp()
        self.user = self.make_user("dave")
        self.tokens = self.login("dave")

    def test_password_change_invalidates_all_existing_tokens(self):
        new_password = "Brand!NewSecret77xz"
        response = self.client.post(
            self.URL,
            {"current_password": STRONG_PASSWORD, "new_password": new_password},
            format="json",
            **self.bearer(self.tokens["access_token"]),
        )
        self.assertEqual(response.status_code, 200, response.data)

        old = self.client.get("/api/auth/me/", **self.bearer(self.tokens["access_token"]))
        self.assertEqual(old.status_code, 401)
        self.assertEqual(old.data["error"]["code"], "token_version_stale")

        fresh = self.client.get(
            "/api/auth/me/", **self.bearer(response.data["tokens"]["access_token"])
        )
        self.assertEqual(fresh.status_code, 200)

        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password(new_password))

    def test_wrong_current_password_is_rejected(self):
        response = self.client.post(
            self.URL,
            {"current_password": "nope-nope-nope1!", "new_password": "Another!Pass99xy"},
            format="json",
            **self.bearer(self.tokens["access_token"]),
        )
        self.assertEqual(response.status_code, 400)

    def test_anonymous_cannot_change_a_password(self):
        response = self.client.post(
            self.URL,
            {"current_password": STRONG_PASSWORD, "new_password": "Another!Pass99xy"},
            format="json",
        )
        self.assertEqual(response.status_code, 401)
