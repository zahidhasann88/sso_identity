"""
Cryptographic unit tests for the asymmetric issuance layer.

These exercise the "successful asymmetric decoding loop" (sign with the
private key, verify with the *public* key only) and every rejection path a
forged or misused token can take.
"""

from __future__ import annotations

import base64
import json
import uuid
from datetime import timedelta

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.test import TestCase, override_settings

from identity.crypto import b64url as _b64url
from identity.crypto import generate_rsa_keypair, keyring, reset_keyring
from identity.models import SystemRole
from identity.tests.base import IdentityAPITestCase
from identity.tokens import (
    AccessToken,
    BaseToken,
    RefreshToken,
    TokenError,
    TokenExpired,
    TokenSignatureError,
    TokenTypeMismatch,
    issue_token_pair,
)


class AsymmetricIssuanceTests(IdentityAPITestCase):
    """Happy-path signing/verification and claim-shape guarantees."""

    def setUp(self) -> None:
        super().setUp()
        self.user = self.make_user("crypto_user", role=SystemRole.DEVELOPER)

    def test_access_token_verifies_with_public_key_only(self):
        """The full asymmetric loop: private key signs, public key verifies."""
        token = AccessToken.for_user(self.user).encode()
        public_pem = keyring().public_pem()

        claims = jwt.decode(
            token,
            public_pem,                       # <- no private key involved
            algorithms=["RS256"],
            audience=AccessToken.audience(),
            issuer=AccessToken.issuer(),
        )
        self.assertEqual(claims["sub"], str(self.user.pk))
        self.assertEqual(claims["typ"], "access")
        self.assertEqual(claims["role"], SystemRole.DEVELOPER)
        self.assertNotIn("password", json.dumps(claims))

    def test_token_header_advertises_rs256_and_kid(self):
        header = jwt.get_unverified_header(AccessToken.for_user(self.user).encode())
        self.assertEqual(header["alg"], "RS256")
        self.assertEqual(header["typ"], "JWT")
        self.assertEqual(header["kid"], keyring().kid)

    def test_published_jwk_reconstructs_a_working_verification_key(self):
        """A relying party can verify offline using only the JWKS document."""
        jwk = keyring().public_jwk()
        token = AccessToken.for_user(self.user).encode()

        rebuilt = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwk))
        claims = jwt.decode(
            token,
            rebuilt,
            algorithms=["RS256"],
            audience=AccessToken.audience(),
            issuer=AccessToken.issuer(),
        )
        self.assertEqual(claims["sub"], str(self.user.pk))

    def test_private_key_cannot_be_derived_from_public_material(self):
        jwk = keyring().public_jwk()
        for private_param in ("d", "p", "q", "dp", "dq", "qi"):
            self.assertNotIn(private_param, jwk)
        self.assertNotIn("PRIVATE", keyring().public_pem())

    def test_standardized_claim_set_is_complete(self):
        payload = AccessToken.decode(AccessToken.for_user(self.user).encode())
        for claim in ("iss", "sub", "aud", "iat", "nbf", "exp", "jti", "typ",
                      "sid", "tv", "username", "email", "role", "scope"):
            self.assertIn(claim, payload, f"missing claim: {claim}")
        uuid.UUID(payload["jti"])  # raises if not a valid UUID

    def test_every_issuance_has_a_unique_jti(self):
        jtis = {AccessToken.for_user(self.user).jti for _ in range(50)}
        self.assertEqual(len(jtis), 50)

    def test_access_token_lifetime_is_15_minutes(self):
        token = AccessToken.for_user(self.user)
        delta = token.expires_at - token.issued_at
        self.assertEqual(delta, timedelta(minutes=15))

    def test_refresh_token_lifetime_is_7_days(self):
        token = RefreshToken.for_user(self.user)
        delta = token.expires_at - token.issued_at
        self.assertEqual(delta, timedelta(days=7))

    def test_refresh_token_is_claim_poor(self):
        """A leaked refresh token must not disclose profile data."""
        payload = RefreshToken.decode(RefreshToken.for_user(self.user).encode())
        self.assertNotIn("email", payload)
        self.assertNotIn("username", payload)
        self.assertNotIn("scope", payload)

    def test_session_id_is_shared_but_jtis_are_distinct(self):
        """
        The access token is bound to its refresh token's session, yet each
        has its own jti — so rotating (revoking) the refresh token does not
        accidentally revoke the live access token, while revoking the session
        revokes both.
        """
        refresh = RefreshToken.for_user(self.user)
        access = refresh.access_token(self.user)

        self.assertEqual(access.sid, refresh.sid)
        self.assertNotEqual(refresh.jti, refresh.sid)
        self.assertNotEqual(access.jti, refresh.jti)

    def test_issue_token_pair_shape(self):
        pair = issue_token_pair(self.user)
        self.assertEqual(pair["token_type"], "Bearer")
        # expires_in counts down from a truncated NumericDate `exp`, so a 900s
        # token legitimately reports 899 when issuance lands late in a wall-clock
        # second. Exact equality here would be a genuine flake.
        self.assertIn(pair["expires_in"], range(15 * 60 - 5, 15 * 60 + 1))
        self.assertIn(
            pair["refresh_expires_in"],
            range(7 * 24 * 3600 - 5, 7 * 24 * 3600 + 1),
        )
        self.assertNotEqual(pair["session_id"], pair["refresh_jti"])
        self.assertNotEqual(pair["access_jti"], pair["refresh_jti"])
        self.assertIn("identity:read", pair["scope"])


class TokenRejectionTests(IdentityAPITestCase):
    """Every way a token can be invalid must be rejected explicitly."""

    def setUp(self) -> None:
        super().setUp()
        self.user = self.make_user("reject_user")

    def test_tampered_payload_is_rejected(self):
        token = AccessToken.for_user(self.user).encode()
        header_b64, payload_b64, signature = token.split(".")

        raw = base64.urlsafe_b64decode(payload_b64 + "=" * (-len(payload_b64) % 4))
        claims = json.loads(raw)
        claims["role"] = "ADMIN"          # privilege escalation attempt
        forged_payload = base64.urlsafe_b64encode(
            json.dumps(claims).encode()
        ).rstrip(b"=").decode()

        with self.assertRaises(TokenSignatureError):
            AccessToken.decode(f"{header_b64}.{forged_payload}.{signature}")

    def test_alg_none_is_rejected(self):
        """The classic 'alg: none' downgrade must never be honoured."""
        payload = AccessToken.for_user(self.user).payload
        unsigned = jwt.encode(payload, key="", algorithm="none")
        with self.assertRaises(TokenSignatureError):
            AccessToken.decode(unsigned)

    def test_hs256_key_confusion_is_rejected(self):
        """
        The textbook RS256 -> HS256 confusion attack: the attacker takes the
        *published* public key and uses it as an HMAC secret, hoping the
        verifier trusts the header's `alg`. PyJWT refuses to encode this, so
        the token is forged byte-by-byte exactly as an attacker would.
        """
        import hashlib
        import hmac

        payload = AccessToken.for_user(self.user).payload
        header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
        body = _b64url(json.dumps(payload).encode())
        signing_input = f"{header}.{body}".encode()
        signature = _b64url(
            hmac.new(
                keyring().public_pem().encode(), signing_input, hashlib.sha256
            ).digest()
        )
        forged = f"{header}.{body}.{signature}"

        with self.assertRaises(TokenSignatureError):
            AccessToken.decode(forged)

    def test_token_signed_by_a_foreign_key_is_rejected(self):
        """An attacker with their own RSA keypair still cannot mint tokens."""
        rogue = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        rogue_pem = rogue.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()

        payload = dict(AccessToken.for_user(self.user).payload)
        forged = jwt.encode(payload, rogue_pem, algorithm="RS256")
        with self.assertRaises(TokenSignatureError):
            AccessToken.decode(forged)

    @override_settings(ACCESS_TOKEN_LIFETIME=timedelta(seconds=-120),
                       JWT_LEEWAY_SECONDS=0)
    def test_expired_token_is_rejected(self):
        expired = AccessToken.for_user(self.user).encode()
        with self.assertRaises(TokenExpired):
            AccessToken.decode(expired)

    def test_refresh_token_cannot_be_used_as_an_access_token(self):
        refresh = RefreshToken.for_user(self.user).encode()
        with self.assertRaises(TokenTypeMismatch):
            AccessToken.decode(refresh)

    def test_access_token_cannot_be_used_as_a_refresh_token(self):
        access = AccessToken.for_user(self.user).encode()
        with self.assertRaises(TokenTypeMismatch):
            RefreshToken.decode(access)

    def test_wrong_issuer_is_rejected(self):
        payload = dict(AccessToken.for_user(self.user).payload)
        payload["iss"] = "https://evil.example.com"
        forged = jwt.encode(
            payload, keyring().private_pem(), algorithm="RS256",
            headers={"kid": keyring().kid},
        )
        with self.assertRaises(TokenError):
            AccessToken.decode(forged)

    def test_wrong_audience_is_rejected(self):
        payload = dict(AccessToken.for_user(self.user).payload)
        payload["aud"] = ["some-other-service"]
        forged = jwt.encode(
            payload, keyring().private_pem(), algorithm="RS256",
            headers={"kid": keyring().kid},
        )
        with self.assertRaises(TokenError):
            AccessToken.decode(forged)

    def test_missing_required_claim_is_rejected(self):
        payload = dict(AccessToken.for_user(self.user).payload)
        payload.pop("jti")
        forged = jwt.encode(
            payload, keyring().private_pem(), algorithm="RS256",
            headers={"kid": keyring().kid},
        )
        with self.assertRaises(TokenError):
            AccessToken.decode(forged)

    def test_unknown_kid_is_rejected(self):
        payload = dict(AccessToken.for_user(self.user).payload)
        forged = jwt.encode(
            payload, keyring().private_pem(), algorithm="RS256",
            headers={"kid": "attacker-supplied-key-id"},
        )
        with self.assertRaises(TokenSignatureError):
            AccessToken.decode(forged)

    def test_garbage_input_is_rejected_cleanly(self):
        for candidate in ("", "not-a-jwt", "a.b.c", "Bearer x.y.z", None):
            with self.assertRaises(TokenError):
                AccessToken.decode(candidate)  # type: ignore[arg-type]

    def test_base_decode_accepts_either_type_when_unconstrained(self):
        access = AccessToken.for_user(self.user).encode()
        refresh = RefreshToken.for_user(self.user).encode()
        self.assertEqual(BaseToken.decode(access, expected_type=None)["typ"], "access")
        self.assertEqual(BaseToken.decode(refresh, expected_type=None)["typ"], "refresh")


class KeyManagementTests(TestCase):
    """Key loading, thumbprints and rejection of weak/invalid material."""

    def test_kid_is_a_deterministic_rfc7638_thumbprint(self):
        first = keyring().kid
        reset_keyring()
        self.assertEqual(first, keyring().kid)

    def test_generated_keypair_roundtrips(self):
        private_pem, public_pem = generate_rsa_keypair(2048)
        self.assertIn("BEGIN PRIVATE KEY", private_pem)
        self.assertIn("BEGIN PUBLIC KEY", public_pem)

        token = jwt.encode({"hello": "world"}, private_pem, algorithm="RS256")
        self.assertEqual(
            jwt.decode(token, public_pem, algorithms=["RS256"])["hello"], "world"
        )

    def test_weak_key_generation_is_refused(self):
        with self.assertRaises(ValueError):
            generate_rsa_keypair(1024)

    @override_settings(
        JWT_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\nnope\n-----END PRIVATE KEY-----"
    )
    def test_malformed_private_key_raises_configuration_error(self):
        from django.core.exceptions import ImproperlyConfigured

        reset_keyring()
        try:
            with self.assertRaises(ImproperlyConfigured):
                keyring()
        finally:
            reset_keyring()

    @override_settings(JWT_ALGORITHM="HS256")
    def test_symmetric_algorithm_is_refused_by_configuration(self):
        from django.core.exceptions import ImproperlyConfigured

        reset_keyring()
        try:
            with self.assertRaises(ImproperlyConfigured):
                keyring()
        finally:
            reset_keyring()

    def test_escaped_newline_pem_is_accepted(self):
        private_pem, _ = generate_rsa_keypair(2048)
        escaped = private_pem.replace("\n", "\\n")
        reset_keyring()
        try:
            with override_settings(JWT_PRIVATE_KEY=escaped):
                self.assertEqual(keyring().algorithm, "RS256")
        finally:
            reset_keyring()
