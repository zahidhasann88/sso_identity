"""
Key rotation with an overlap window.

The retired public key stays in the JWKS until the last token it signed has
expired, so a rotation is not a mass logout. The part that matters most is the
last test: a retired key must not become a second way to forge a token.
"""

from __future__ import annotations

import json

import jwt
from django.core.exceptions import ImproperlyConfigured
from django.test import override_settings

from identity.crypto import generate_rsa_keypair, keyring, reset_keyring
from identity.models import SystemRole
from identity.tests.base import IdentityAPITestCase
from identity.tokens import AccessToken, TokenSignatureError


class KeyRotationOverlapTests(IdentityAPITestCase):
    def setUp(self) -> None:
        super().setUp()
        self.user = self.make_user("rotator", role=SystemRole.DEVELOPER)

        self.old_private, self.old_public = generate_rsa_keypair(2048)
        reset_keyring()
        with override_settings(JWT_PRIVATE_KEY=self.old_private):
            self.old_kid = keyring().kid
            self.token_from_old_key = AccessToken.for_user(self.user).encode()

        self.new_private, self.new_public = generate_rsa_keypair(2048)
        reset_keyring()

    def tearDown(self) -> None:
        reset_keyring()
        super().tearDown()

    def rotated(self, *, overlap: bool):
        """Settings for the post-rotation service, with or without a drain window."""
        return override_settings(
            JWT_PRIVATE_KEY=self.new_private,
            JWT_ADDITIONAL_PUBLIC_KEYS=self.old_public if overlap else "",
        )

    def test_token_from_the_retired_key_still_verifies_during_the_overlap(self):
        with self.rotated(overlap=True):
            payload = AccessToken.decode(self.token_from_old_key)
            self.assertEqual(payload["sub"], str(self.user.pk))

    def test_protected_route_accepts_a_token_from_the_retired_key(self):
        with self.rotated(overlap=True):
            response = self.client.get(
                "/api/auth/me/", **self.bearer(self.token_from_old_key)
            )
            self.assertEqual(response.status_code, 200, response.data)
            self.assertEqual(response.data["user"]["username"], "rotator")

    def test_token_from_the_retired_key_is_refused_once_the_window_closes(self):
        with self.rotated(overlap=False):
            with self.assertRaises(TokenSignatureError):
                AccessToken.decode(self.token_from_old_key)

    def test_jwks_publishes_both_keys_during_the_overlap(self):
        with self.rotated(overlap=True):
            keys = self.client.get("/.well-known/jwks.json").json()["keys"]
            self.assertEqual(len(keys), 2)
            # Active key first, so a client reading only keys[0] is correct.
            self.assertEqual(keys[0]["kid"], keyring().kid)
            self.assertEqual(keys[1]["kid"], self.old_kid)
            self.assertEqual({key["kty"] for key in keys}, {"RSA"})
            for key in keys:
                self.assertNotIn("d", key)

    def test_new_tokens_are_signed_with_the_new_key_only(self):
        with self.rotated(overlap=True):
            fresh = AccessToken.for_user(self.user).encode()
            self.assertEqual(jwt.get_unverified_header(fresh)["kid"], keyring().kid)
            self.assertNotEqual(jwt.get_unverified_header(fresh)["kid"], self.old_kid)

    def test_a_retired_key_cannot_be_used_to_forge_a_token_for_the_active_kid(self):
        """
        The rotation window must not become a downgrade attack: claiming the
        active `kid` while signing with the retired private key has to fail.
        """
        with self.rotated(overlap=True):
            forged = jwt.encode(
                AccessToken.for_user(self.user).payload,
                self.old_private,
                algorithm="RS256",
                headers={"kid": keyring().kid},
            )
            with self.assertRaises(TokenSignatureError):
                AccessToken.decode(forged)

    def test_a_key_that_was_never_published_is_still_refused(self):
        stranger_private, _ = generate_rsa_keypair(2048)
        with self.rotated(overlap=True):
            forged = jwt.encode(
                AccessToken.for_user(self.user).payload,
                stranger_private,
                algorithm="RS256",
            )
            with self.assertRaises(TokenSignatureError):
                AccessToken.decode(forged)

    def test_relying_party_picks_the_right_jwk_by_kid(self):
        """The real client-side flow: match the token's kid against the JWKS."""
        with self.rotated(overlap=True):
            keys = self.client.get("/.well-known/jwks.json").json()["keys"]
            by_kid = {key["kid"]: key for key in keys}

            token_kid = jwt.get_unverified_header(self.token_from_old_key)["kid"]
            self.assertIn(token_kid, by_kid)

            verification_key = jwt.algorithms.RSAAlgorithm.from_jwk(
                json.dumps(by_kid[token_kid])
            )
            claims = jwt.decode(
                self.token_from_old_key,
                verification_key,
                algorithms=["RS256"],
                audience=AccessToken.audience(),
                issuer=AccessToken.issuer(),
            )
            self.assertEqual(claims["sub"], str(self.user.pk))

    def test_the_active_key_listed_twice_is_published_once(self):
        """An operator who lists every key in one variable must not get a dupe."""
        with override_settings(
            JWT_PRIVATE_KEY=self.new_private,
            JWT_ADDITIONAL_PUBLIC_KEYS=self.new_public + self.old_public,
        ):
            keys = self.client.get("/.well-known/jwks.json").json()["keys"]
            self.assertEqual(len(keys), 2)
            self.assertEqual(len({key["kid"] for key in keys}), 2)

    def test_public_key_document_reports_the_drain_window(self):
        with self.rotated(overlap=True):
            data = self.client.get("/api/auth/keys/").json()
            self.assertEqual(data["kid"], keyring().kid)
            self.assertEqual(data["retired_kids"], [self.old_kid])

        reset_keyring()
        with self.rotated(overlap=False):
            self.assertEqual(
                self.client.get("/api/auth/keys/").json()["retired_kids"], []
            )


class RetiredKeyConfigurationTests(IdentityAPITestCase):
    """Bad retired-key configuration must fail loudly at boot, not silently."""

    def tearDown(self) -> None:
        reset_keyring()
        super().tearDown()

    def test_escaped_newline_pem_is_accepted(self):
        _, public_pem = generate_rsa_keypair(2048)
        escaped = public_pem.replace(chr(10), chr(92) + "n")
        reset_keyring()
        with override_settings(JWT_ADDITIONAL_PUBLIC_KEYS=escaped):
            self.assertEqual(len(keyring().retired_public_keys), 1)

    def test_a_private_key_in_the_public_slot_is_rejected(self):
        private_pem, _ = generate_rsa_keypair(2048)
        reset_keyring()
        with override_settings(JWT_ADDITIONAL_PUBLIC_KEYS=private_pem):
            with self.assertRaises(ImproperlyConfigured):
                keyring()

    def test_garbage_is_rejected(self):
        reset_keyring()
        with override_settings(
            JWT_ADDITIONAL_PUBLIC_KEYS=(
                "-----BEGIN PUBLIC KEY-----" + chr(10) + "nope" + chr(10)
                + "-----END PUBLIC KEY-----"
            )
        ):
            with self.assertRaises(ImproperlyConfigured):
                keyring()

    def test_a_weak_retired_key_is_rejected(self):
        """1024-bit material must not sneak back in through the overlap slot."""
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        # The weak key size is the subject of the assertion, hence the noqa.
        weak = rsa.generate_private_key(
            public_exponent=65537,
            key_size=1024,  # noqa: S505
        )
        weak_public = weak.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()

        reset_keyring()
        with override_settings(JWT_ADDITIONAL_PUBLIC_KEYS=weak_public):
            with self.assertRaises(ImproperlyConfigured):
                keyring()
