"""Public key distribution, discovery documents, headers and model behaviour."""

from __future__ import annotations

import json

import jwt
from django.core.exceptions import ValidationError
from django.db.utils import IntegrityError
from django.test import override_settings

from identity.crypto import keyring
from identity.models import BlacklistedToken, CustomUser, SystemRole
from identity.tests.base import TEST_AUDIENCE, TEST_ISSUER, IdentityAPITestCase


class PublicKeyDistributionTests(IdentityAPITestCase):
    def test_jwks_endpoint_is_public_and_well_formed(self):
        response = self.client.get("/.well-known/jwks.json")
        self.assertEqual(response.status_code, 200)

        keys = response.json()["keys"]
        self.assertEqual(len(keys), 1)
        jwk = keys[0]
        self.assertEqual(jwk["kty"], "RSA")
        self.assertEqual(jwk["use"], "sig")
        self.assertEqual(jwk["alg"], "RS256")
        self.assertEqual(jwk["kid"], keyring().kid)
        self.assertIn("n", jwk)
        self.assertIn("e", jwk)

    def test_jwks_never_leaks_private_parameters(self):
        body = self.client.get("/.well-known/jwks.json").content.decode()
        for marker in ("d", "p", "q", "dp", "dq", "qi"):
            self.assertNotIn(f'"{marker}"', body)
        self.assertNotIn("PRIVATE", body)

    def test_structured_public_key_endpoint(self):
        response = self.client.get("/api/auth/keys/")
        self.assertEqual(response.status_code, 200)
        data = response.json()

        self.assertEqual(data["algorithm"], "RS256")
        self.assertIn("BEGIN PUBLIC KEY", data["public_key_pem"])
        self.assertNotIn("PRIVATE", data["public_key_pem"])
        self.assertEqual(data["token_lifetimes"]["access_seconds"], 900)
        self.assertEqual(data["token_lifetimes"]["refresh_seconds"], 604800)
        self.assertTrue(data["jwks_uri"].endswith("/.well-known/jwks.json"))

    def test_relying_party_can_verify_a_token_using_only_published_material(self):
        """Simulates a downstream microservice validating SSO tokens offline."""
        self.make_user("ivan")
        tokens = self.login("ivan")

        jwk = self.client.get("/.well-known/jwks.json").json()["keys"][0]
        verification_key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwk))

        claims = jwt.decode(
            tokens["access_token"],
            verification_key,
            algorithms=["RS256"],
            audience=TEST_AUDIENCE,
            issuer=TEST_ISSUER,
        )
        self.assertEqual(claims["username"], "ivan")
        self.assertEqual(claims["typ"], "access")

    def test_discovery_document_lists_every_endpoint(self):
        data = self.client.get("/.well-known/openid-configuration").json()
        self.assertEqual(data["issuer"], TEST_ISSUER)
        for key in (
            "jwks_uri", "token_endpoint", "token_refresh_endpoint",
            "revocation_endpoint", "introspection_endpoint",
            "registration_endpoint", "userinfo_endpoint",
        ):
            self.assertIn(key, data)
        self.assertEqual(data["id_token_signing_alg_values_supported"], ["RS256"])

    def test_service_root_and_health(self):
        root = self.client.get("/")
        self.assertEqual(root.status_code, 200)
        self.assertEqual(root.json()["service"], "sso-identity")

        health = self.client.get("/api/health/")
        self.assertEqual(health.status_code, 200)
        self.assertEqual(health.json()["status"], "ok")
        self.assertEqual(health.json()["checks"]["signing_key"], "ok")


class ResponseHardeningTests(IdentityAPITestCase):
    def test_auth_responses_are_never_cached(self):
        self.make_user("judy")
        response = self.client.post(
            "/api/auth/login/",
            {"identifier": "judy", "password": "Xq7!vartan-Spindle42"},
            format="json",
        )
        self.assertIn("no-store", response["Cache-Control"])

    def test_security_headers_are_applied(self):
        response = self.client.get("/api/health/")
        self.assertEqual(response["X-Content-Type-Options"], "nosniff")
        self.assertEqual(response["Referrer-Policy"], "no-referrer")
        self.assertIn("frame-ancestors 'none'", response["Content-Security-Policy"])

    def test_request_id_is_echoed_and_generated(self):
        generated = self.client.get("/api/health/")
        self.assertTrue(generated["X-Request-ID"])

        echoed = self.client.get("/api/health/", HTTP_X_REQUEST_ID="abc-123")
        self.assertEqual(echoed["X-Request-ID"], "abc-123")

    def test_oversized_request_id_is_replaced(self):
        response = self.client.get("/api/health/", HTTP_X_REQUEST_ID="x" * 500)
        self.assertNotEqual(response["X-Request-ID"], "x" * 500)
        self.assertEqual(len(response["X-Request-ID"]), 32)

    @override_settings(
        REST_FRAMEWORK={
            "DEFAULT_THROTTLE_RATES": {"auth_login": "2/min"},
            "DEFAULT_THROTTLE_CLASSES": [],
            "EXCEPTION_HANDLER": "identity.exceptions.rfc7807_exception_handler",
        }
    )
    def test_login_endpoint_is_rate_limited(self):
        self.make_user("kate")
        codes = [
            self.client.post(
                "/api/auth/login/",
                {"identifier": "kate", "password": "Xq7!vartan-Spindle42"},
                format="json",
            ).status_code
            for _ in range(4)
        ]
        self.assertIn(429, codes)

    def test_error_envelope_is_uniform(self):
        response = self.client.get("/api/auth/me/")
        self.assertEqual(response.status_code, 401)
        error = response.json()["error"]
        for key in ("code", "detail", "status"):
            self.assertIn(key, error)
        self.assertEqual(error["status"], 401)

    def test_request_id_is_present_on_view_built_errors(self):
        """
        Errors built by ``identity.views.error`` must carry ``request_id``
        just like those rendered by the DRF exception handler — these are
        precisely the auth failures an operator needs to correlate.
        """
        self.make_user("rhea")
        tokens = self.login("rhea")

        # Consume the refresh token, then replay it: a hand-rolled 401.
        self.client.post(
            "/api/auth/refresh/",
            {"refresh": tokens["refresh_token"]},
            format="json",
        )
        replay = self.client.post(
            "/api/auth/refresh/",
            {"refresh": tokens["refresh_token"]},
            format="json",
            HTTP_X_REQUEST_ID="trace-me-42",
        )

        self.assertEqual(replay.status_code, 401)
        error = replay.json()["error"]
        self.assertEqual(error["code"], "token_revoked")
        self.assertEqual(error["request_id"], "trace-me-42")
        self.assertEqual(replay["X-Request-ID"], "trace-me-42")

    def test_request_id_matches_the_header_on_every_error_path(self):
        """The body's request_id and the X-Request-ID header never diverge."""
        self.make_user("rory")

        cases = (
            # One hand-rolled 401, one raised through DRF's handler.
            self.client.post(
                "/api/auth/login/",
                {"identifier": "rory", "password": "definitely-not-it"},
                format="json",
            ),
            self.client.get("/api/auth/me/"),
        )

        for response in cases:
            with self.subTest(code=response.json()["error"]["code"]):
                self.assertEqual(response.status_code, 401)
                self.assertEqual(
                    response.json()["error"]["request_id"],
                    response["X-Request-ID"],
                )

    def test_unsupported_method_is_405(self):
        self.assertEqual(self.client.get("/api/auth/login/").status_code, 405)


class ModelTests(IdentityAPITestCase):
    def test_custom_user_fields_and_defaults(self):
        user = self.make_user("leo")
        self.assertEqual(user.system_role, SystemRole.USER)
        self.assertEqual(user.token_version, 0)
        self.assertIn("leo", str(user))

    def test_system_role_choices_are_enforced(self):
        user = CustomUser(username="mallory", email="m@example.com",
                          system_role="SUPERVILLAIN")
        with self.assertRaises(ValidationError):
            user.full_clean()

    def test_bump_token_version_is_monotonic_and_timestamped(self):
        user = self.make_user("nina")
        self.assertEqual(user.bump_token_version(), 1)
        self.assertEqual(user.bump_token_version(), 2)
        user.refresh_from_db()
        self.assertEqual(user.token_version, 2)
        self.assertIn("tokens_revoked_at", user.metadata)

    def test_public_claims_hide_internal_metadata_keys(self):
        user = self.make_user(
            "olivia", metadata={"token_version": 3, "tenant": "acme"}
        )
        claims = user.public_claims()
        self.assertEqual(claims["tv"], 3)
        self.assertEqual(claims["meta"], {"tenant": "acme"})
        self.assertNotIn("token_version", claims["meta"])

    def test_metadata_survives_a_roundtrip(self):
        user = self.make_user("peter", metadata={"a": [1, 2, {"b": True}]})
        user.refresh_from_db()
        self.assertEqual(user.metadata["a"], [1, 2, {"b": True}])

    def test_email_uniqueness_is_enforced_at_the_database_level(self):
        self.make_user("quinn", email="dup@example.com")
        with self.assertRaises((IntegrityError, ValidationError)):
            self.make_user("quinn2", email="dup@example.com")

    def test_blacklisted_token_primary_key_is_the_jti(self):
        row = BlacklistedToken.objects.create(
            token_jti="abc-jti",
            expires_at=self._future(),
        )
        self.assertEqual(row.pk, "abc-jti")
        self.assertFalse(row.is_expired)
        self.assertIn("abc-jti", str(row))

    def test_blacklisted_token_jti_cannot_be_duplicated(self):
        BlacklistedToken.objects.create(token_jti="dup-jti", expires_at=self._future())
        with self.assertRaises(IntegrityError):
            BlacklistedToken.objects.create(
                token_jti="dup-jti", expires_at=self._future()
            )

    @staticmethod
    def _future():
        from datetime import timedelta

        from django.utils import timezone

        return timezone.now() + timedelta(days=1)


class PermissionTests(IdentityAPITestCase):
    def test_scopes_are_derived_from_the_system_role(self):
        from identity.tokens import AccessToken

        expectations = {
            SystemRole.ADMIN: "identity:admin",
            SystemRole.DEVELOPER: "keys:read",
            SystemRole.USER: "identity:read",
        }
        for index, (role, expected_scope) in enumerate(expectations.items()):
            user = self.make_user(f"scoped{index}", role=role)
            payload = AccessToken.decode(AccessToken.for_user(user).encode())
            self.assertIn(expected_scope, payload["scope"])
            self.assertEqual(payload["role"], role)

    def test_role_permission_class_gates_access(self):
        from rest_framework.test import APIRequestFactory

        from identity.permissions import IsAdminRole

        factory = APIRequestFactory()
        request = factory.get("/")
        request.user = self.make_user("rachel", role=SystemRole.USER)
        self.assertFalse(IsAdminRole().has_permission(request, None))

        request.user = self.make_user("sam", role=SystemRole.ADMIN)
        self.assertTrue(IsAdminRole().has_permission(request, None))

    def test_scope_permission_class_checks_the_token_claim(self):
        from rest_framework.test import APIRequestFactory

        from identity.permissions import HasTokenScope

        class View:
            required_scopes = ("identity:write",)

        factory = APIRequestFactory()
        request = factory.get("/")
        request.auth_payload = {"scope": "identity:read"}
        self.assertFalse(HasTokenScope().has_permission(request, View))

        request.auth_payload = {"scope": "identity:read identity:write"}
        self.assertTrue(HasTokenScope().has_permission(request, View))
