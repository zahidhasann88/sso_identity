from __future__ import annotations

import uuid
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from typing import Any, ClassVar

import jwt
from django.conf import settings

from identity.crypto import ALLOWED_ALGORITHMS, keyring


class TokenError(Exception):
    """Base class for every token failure. ``code`` is surfaced to clients."""

    code = "token_invalid"
    default_detail = "Token is invalid."

    def __init__(self, detail: str | None = None, code: str | None = None) -> None:
        self.detail = detail or self.default_detail
        if code:
            self.code = code
        super().__init__(self.detail)


class TokenExpired(TokenError):
    code = "token_expired"
    default_detail = "Token has expired."


class TokenTypeMismatch(TokenError):
    code = "token_type_mismatch"
    default_detail = "Token is not valid for this operation."


class TokenRevoked(TokenError):
    code = "token_revoked"
    default_detail = "Token has been revoked."


class TokenSignatureError(TokenError):
    code = "token_signature_invalid"
    default_detail = "Token signature verification failed."


def _utcnow() -> datetime:
    return datetime.now(tz=UTC)


def _epoch(moment: datetime) -> int:
    return int(moment.timestamp())


class BaseToken:
    token_type: ClassVar[str] = "base"
    lifetime_setting: ClassVar[str] = ""
    default_lifetime: ClassVar[timedelta] = timedelta(minutes=5)

    def __init__(self, payload: dict[str, Any] | None = None) -> None:
        self.payload: dict[str, Any] = dict(payload or {})

    @classmethod
    def lifetime(cls) -> timedelta:
        return getattr(settings, cls.lifetime_setting, cls.default_lifetime)

    @classmethod
    def issuer(cls) -> str:
        return getattr(settings, "JWT_ISSUER", "https://sso.identity.local")

    @classmethod
    def audience(cls) -> list[str]:
        aud = getattr(settings, "JWT_AUDIENCE", ["identity-clients"])
        return list(aud) if isinstance(aud, (list, tuple)) else [aud]

    @classmethod
    def base_claims(cls, user, *, session_id: str | None = None) -> dict[str, Any]:
        now = _utcnow()
        expiry = now + cls.lifetime()
        return {
            "iss": cls.issuer(),
            "sub": str(user.pk),
            "aud": cls.audience(),
            "iat": _epoch(now),
            "nbf": _epoch(now),
            "exp": _epoch(expiry),
            "jti": str(uuid.uuid4()),
            "typ": cls.token_type,
            "sid": session_id or str(uuid.uuid4()),
            "tv": user.token_version,
        }

    @classmethod
    def for_user(cls, user, *, session_id: str | None = None, **extra: Any):
        payload = cls.base_claims(user, session_id=session_id)
        payload.update(cls.extra_claims(user))
        payload.update(extra)
        return cls(payload)

    @classmethod
    def extra_claims(cls, user) -> dict[str, Any]:  # pragma: no cover - overridden
        return {}

    def encode(self) -> str:
        ring = keyring()
        return jwt.encode(
            self.payload,
            ring.private_pem(),
            algorithm=ring.algorithm,
            headers={"kid": ring.kid, "typ": "JWT"},
        )

    def __str__(self) -> str:
        return self.encode()

    @property
    def jti(self) -> str:
        return self.payload["jti"]

    @property
    def sid(self) -> str:
        return self.payload["sid"]

    @property
    def expires_at(self) -> datetime:
        return datetime.fromtimestamp(self.payload["exp"], tz=UTC)

    @property
    def issued_at(self) -> datetime:
        return datetime.fromtimestamp(self.payload["iat"], tz=UTC)

    @property
    def expires_in(self) -> int:
        return max(0, int(self.payload["exp"] - _epoch(_utcnow())))

    @classmethod
    def decode(
        cls,
        raw_token: str,
        *,
        verify_exp: bool = True,
        expected_type: str | None = "__self__",
        audience: Iterable[str] | None = None,
    ) -> dict[str, Any]:
        """
        Verify an incoming compact JWT and return its claims.

        Verification uses the **public** key only, which is what lets relying
        parties validate locally from the published JWKS.

        Raises a :class:`TokenError` subclass on every failure; never returns
        a partially-trusted payload.
        """
        if not raw_token or not isinstance(raw_token, str):
            raise TokenError("No token supplied.")

        ring = keyring()

        # The unverified header is read only to enforce the algorithm
        # allow-list, before any signature work happens.
        try:
            header = jwt.get_unverified_header(raw_token)
        except jwt.PyJWTError as exc:
            raise TokenError(f"Malformed token header: {exc}") from exc

        alg = header.get("alg")
        if alg not in ALLOWED_ALGORITHMS:
            raise TokenSignatureError(
                f"Unsupported or disallowed signing algorithm: {alg!r}."
            )

        kid = header.get("kid")
        candidates = ring.verification_pems(kid)
        if not candidates:
            raise TokenSignatureError("Token was signed with an unknown key id.")

        # PyJWT checks the signature before any claim, so the first candidate
        # that does not raise InvalidSignatureError is the key that signed this
        # token — every later failure is a real claim rejection, not a wrong key.
        payload = None
        signature_error: Exception | None = None
        for public_pem in candidates:
            try:
                payload = jwt.decode(
                    raw_token,
                    public_pem,
                    algorithms=list(ALLOWED_ALGORITHMS),
                    audience=list(audience) if audience else cls.audience(),
                    issuer=cls.issuer(),
                    leeway=getattr(settings, "JWT_LEEWAY_SECONDS", 10),
                    options={
                        "require": [
                            "exp", "iat", "nbf", "iss", "aud", "sub", "jti", "typ",
                        ],
                        "verify_signature": True,
                        "verify_exp": verify_exp,
                        "verify_nbf": True,
                        "verify_iat": True,
                        "verify_aud": True,
                        "verify_iss": True,
                    },
                )
                break
            except jwt.InvalidSignatureError as exc:
                signature_error = exc
                continue
            except jwt.ExpiredSignatureError as exc:
                raise TokenExpired() from exc
            except jwt.MissingRequiredClaimError as exc:
                raise TokenError(
                    f"Token is missing a required claim: {exc.claim}"
                ) from exc
            except jwt.InvalidAudienceError as exc:
                raise TokenError(
                    "Token audience is not accepted by this service."
                ) from exc
            except jwt.InvalidIssuerError as exc:
                raise TokenError("Token issuer is not trusted.") from exc
            except jwt.ImmatureSignatureError as exc:
                raise TokenError("Token is not valid yet (nbf in the future).") from exc
            except jwt.PyJWTError as exc:
                raise TokenError(f"Token could not be validated: {exc}") from exc

        if payload is None:
            raise TokenSignatureError() from signature_error

        # Type-confusion defence: a refresh token must not pass as an access
        # token, or vice versa.
        wanted = cls.token_type if expected_type == "__self__" else expected_type
        if wanted and payload.get("typ") != wanted:
            raise TokenTypeMismatch(
                f"Expected a '{wanted}' token but received '{payload.get('typ')}'."
            )

        if "sid" not in payload:
            raise TokenError("Token is missing the required 'sid' claim.")

        return payload


class AccessToken(BaseToken):
    """Short-lived (15 min) bearer credential carrying authorization claims."""

    token_type = "access"
    lifetime_setting = "ACCESS_TOKEN_LIFETIME"
    default_lifetime = timedelta(minutes=15)

    @classmethod
    def extra_claims(cls, user) -> dict[str, Any]:
        claims = user.public_claims()
        # 'scope' is a plain OAuth2-style space-delimited string so generic
        # resource servers can consume it without bespoke parsing.
        claims["scope"] = " ".join(scopes_for_role(user.system_role))
        return claims


class RefreshToken(BaseToken):
    """
    Long-lived (7 day) credential whose *only* powers are minting access
    tokens and terminating its own session. It deliberately carries no
    profile data, so a leaked refresh token discloses nothing about the user.

    ``sid`` is always a separate identifier from ``jti``: rotation consumes
    (blacklists) the refresh token's jti while the session — and therefore
    the access tokens carrying that sid — stays alive. Revoking the *session*
    is a distinct, deliberate act performed by logout and replay detection.
    """

    token_type = "refresh"
    lifetime_setting = "REFRESH_TOKEN_LIFETIME"
    default_lifetime = timedelta(days=7)

    @classmethod
    def extra_claims(cls, user) -> dict[str, Any]:
        return {"role": user.system_role}

    def access_token(self, user) -> AccessToken:
        """Mint an access token bound to this refresh token's session."""
        return AccessToken.for_user(user, session_id=self.payload["sid"])


ROLE_SCOPES: dict[str, tuple[str, ...]] = {
    "ADMIN": ("identity:read", "identity:write", "identity:admin", "users:manage"),
    "DEVELOPER": ("identity:read", "identity:write", "keys:read"),
    "USER": ("identity:read",),
}


def scopes_for_role(role: str) -> tuple[str, ...]:
    return ROLE_SCOPES.get(role, ROLE_SCOPES["USER"])


def issue_token_pair(user) -> dict[str, Any]:
    """
    Standard OAuth2-shaped token response.

    The access token is minted *from* the refresh token so both share a
    ``sid``; revoking the refresh token therefore also kills its access
    tokens without needing to track them individually.
    """
    refresh = RefreshToken.for_user(user)
    access = refresh.access_token(user)
    return {
        "token_type": "Bearer",
        "access_token": access.encode(),
        "refresh_token": refresh.encode(),
        "expires_in": access.expires_in,
        "refresh_expires_in": refresh.expires_in,
        "access_jti": access.jti,
        "refresh_jti": refresh.jti,
        "session_id": refresh.sid,
        "scope": access.payload.get("scope", ""),
        "issued_at": access.issued_at.isoformat().replace("+00:00", "Z"),
    }
