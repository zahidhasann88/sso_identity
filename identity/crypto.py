from __future__ import annotations

import base64
import hashlib
import json
import re
import threading
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey,
    RSAPublicKey,
)
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

ALLOWED_ALGORITHMS: tuple[str, ...] = ("RS256", "RS384", "RS512", "PS256")

MIN_RSA_KEY_SIZE = 2048

_LOCK = threading.Lock()


def b64url(raw: bytes) -> str:
    """Base64url-encode without padding (RFC 7515 §2)."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def int_to_b64url(value: int) -> str:
    """Encode a positive integer as a base64url big-endian octet string."""
    length = (value.bit_length() + 7) // 8 or 1
    return b64url(value.to_bytes(length, "big"))


def generate_rsa_keypair(key_size: int = 4096) -> tuple[str, str]:
    """Generate a fresh RSA keypair and return ``(private_pem, public_pem)``."""
    if key_size < MIN_RSA_KEY_SIZE:
        raise ValueError(f"RSA key size must be >= {MIN_RSA_KEY_SIZE} bits")

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    public_pem = (
        private_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
    )
    return private_pem, public_pem


@dataclass(frozen=True)
class KeyRing:
    """
    The active signing key, plus public keys that verify but no longer sign.

    ``retired_public_keys`` is what makes rotation zero-downtime rather than a
    mass logout: the previous key stays there until the last token it signed
    has expired.
    """

    private_key: RSAPrivateKey
    public_key: RSAPublicKey
    algorithm: str
    kid: str
    retired_public_keys: tuple[RSAPublicKey, ...] = ()

    def private_pem(self) -> str:
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")

    def public_pem(self) -> str:
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

    def public_jwk(self, public_key: RSAPublicKey | None = None) -> dict[str, Any]:
        """RFC 7517 public JWK; defaults to the active signing key."""
        key = public_key or self.public_key
        numbers = key.public_numbers()
        return {
            "kty": "RSA",
            "use": "sig",
            "key_ops": ["verify"],
            "alg": self.algorithm,
            "kid": _rfc7638_thumbprint(key),
            "n": int_to_b64url(numbers.n),
            "e": int_to_b64url(numbers.e),
        }

    def jwks(self) -> dict[str, Any]:
        """
        RFC 7517 JWK Set — the payload served at /.well-known/jwks.json.

        The active key comes first, so a relying party that reads only
        ``keys[0]`` still gets the one currently signing.
        """
        return {
            "keys": [self.public_jwk()]
            + [self.public_jwk(key) for key in self.retired_public_keys],
        }

    def retired_kids(self) -> tuple[str, ...]:
        return tuple(_rfc7638_thumbprint(key) for key in self.retired_public_keys)

    def _retired_pems(self) -> tuple[str, ...]:
        return tuple(
            key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode("utf-8")
            for key in self.retired_public_keys
        )

    def verification_pems(self, kid: str | None = None) -> tuple[str, ...]:
        """
        PEMs to try when verifying an incoming token.

        A ``kid`` is matched to exactly one key, so a retired key can never
        verify a token claiming to come from the active one, and an
        unrecognised ``kid`` yields no candidates at all. Without a ``kid``
        every published key is a candidate and the signature decides.
        """
        if kid is not None and kid == self.kid:
            return (self.public_pem(),)

        retired = self._retired_pems()
        if kid is None:
            return (self.public_pem(), *retired)

        for candidate, candidate_kid in zip(retired, self.retired_kids(), strict=True):
            if candidate_kid == kid:
                return (candidate,)
        return ()


def _rfc7638_thumbprint(public_key: RSAPublicKey) -> str:
    """
    Deterministic key id: SHA-256 thumbprint of the canonical JWK (RFC 7638).

    Derived from the key material, so every replica computes the same ``kid``
    for the same key without coordination or stored state.
    """
    numbers = public_key.public_numbers()
    canonical = json.dumps(
        {"e": int_to_b64url(numbers.e), "kty": "RSA", "n": int_to_b64url(numbers.n)},
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return b64url(hashlib.sha256(canonical).digest())


def _normalize_pem(raw: str) -> bytes:
    text = (raw or "").strip()
    if not text:
        raise ImproperlyConfigured("JWT_PRIVATE_KEY is empty.")
    if "\\n" in text and "-----BEGIN" in text:
        text = text.replace("\\n", "\n")
    return text.encode("utf-8")


def _load_private_key(pem: str) -> RSAPrivateKey:
    passphrase = getattr(settings, "JWT_PRIVATE_KEY_PASSPHRASE", None) or None
    try:
        key = serialization.load_pem_private_key(
            _normalize_pem(pem),
            password=passphrase.encode("utf-8") if passphrase else None,
        )
    except Exception as exc:
        raise ImproperlyConfigured(
            f"Unable to parse JWT_PRIVATE_KEY as a PEM private key: {exc}"
        ) from exc

    if not isinstance(key, RSAPrivateKey):
        raise ImproperlyConfigured(
            "JWT_PRIVATE_KEY must be an RSA private key; "
            f"got {type(key).__name__}."
        )
    if key.key_size < MIN_RSA_KEY_SIZE:
        raise ImproperlyConfigured(
            f"RSA signing key is {key.key_size} bits; "
            f"a minimum of {MIN_RSA_KEY_SIZE} bits is required."
        )
    return key


_PUBLIC_KEY_BLOCK = re.compile(
    r"-----BEGIN PUBLIC KEY-----.*?-----END PUBLIC KEY-----",
    re.DOTALL,
)


def _load_public_keys(raw: str) -> tuple[RSAPublicKey, ...]:
    """Parse zero or more concatenated ``PUBLIC KEY`` PEM blocks."""
    text = (raw or "").strip()
    if not text:
        return ()
    escaped_newline = chr(92) + "n"
    if escaped_newline in text:
        text = text.replace(escaped_newline, chr(10))

    blocks = _PUBLIC_KEY_BLOCK.findall(text)
    if not blocks:
        raise ImproperlyConfigured(
            "JWT_ADDITIONAL_PUBLIC_KEYS contains no '-----BEGIN PUBLIC KEY-----' "
            "block. Supply SubjectPublicKeyInfo PEM(s), not a private key."
        )

    keys: list[RSAPublicKey] = []
    for block in blocks:
        try:
            key = serialization.load_pem_public_key(block.encode("utf-8"))
        except Exception as exc:
            raise ImproperlyConfigured(
                f"Unable to parse a JWT_ADDITIONAL_PUBLIC_KEYS entry as a PEM "
                f"public key: {exc}"
            ) from exc
        if not isinstance(key, RSAPublicKey):
            raise ImproperlyConfigured(
                "Every JWT_ADDITIONAL_PUBLIC_KEYS entry must be an RSA public "
                f"key; got {type(key).__name__}."
            )
        if key.key_size < MIN_RSA_KEY_SIZE:
            raise ImproperlyConfigured(
                f"A retired verification key is {key.key_size} bits; "
                f"a minimum of {MIN_RSA_KEY_SIZE} bits is required."
            )
        keys.append(key)
    return tuple(keys)


@lru_cache(maxsize=1)
def keyring() -> KeyRing:
    with _LOCK:
        algorithm = getattr(settings, "JWT_ALGORITHM", "RS256")
        if algorithm not in ALLOWED_ALGORITHMS:
            raise ImproperlyConfigured(
                f"JWT_ALGORITHM={algorithm!r} is not an allowed asymmetric "
                f"algorithm. Choose one of {ALLOWED_ALGORITHMS}."
            )

        pem = getattr(settings, "JWT_PRIVATE_KEY", "")
        if not pem:
            raise ImproperlyConfigured(
                "JWT_PRIVATE_KEY is not configured. Generate one with "
                "`python manage.py generate_jwt_keys` and export "
                "JWT_PRIVATE_KEY (or JWT_PRIVATE_KEY_PATH)."
            )

        private_key = _load_private_key(pem)
        public_key = private_key.public_key()
        active_kid = _rfc7638_thumbprint(public_key)

        retired = tuple(
            key
            for key in _load_public_keys(
                getattr(settings, "JWT_ADDITIONAL_PUBLIC_KEYS", "")
            )
            # Listing every key in one variable is legitimate; publishing the
            # active one twice would put a duplicate kid in the JWKS.
            if _rfc7638_thumbprint(key) != active_kid
        )

        return KeyRing(
            private_key=private_key,
            public_key=public_key,
            algorithm=algorithm,
            kid=active_kid,
            retired_public_keys=retired,
        )


def reset_keyring() -> None:
    keyring.cache_clear()
