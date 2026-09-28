from __future__ import annotations

import logging

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError as DjangoValidationError
from rest_framework import HTTP_HEADER_ENCODING
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed

from identity.blacklist import get_blacklist
from identity.tokens import AccessToken, TokenError

logger = logging.getLogger("identity.security")

AUTH_HEADER_TYPES = ("bearer",)


class JWTAuthentication(BaseAuthentication):
    """Stateless bearer authentication with a stateful revocation veto."""

    keyword = "Bearer"
    www_authenticate_realm = "identity"
    token_class = AccessToken

    def get_header(self, request) -> bytes | None:
        header = request.META.get("HTTP_AUTHORIZATION")
        if isinstance(header, str):
            return header.encode(HTTP_HEADER_ENCODING)
        return header

    def get_raw_token(self, header: bytes) -> str | None:
        parts = header.split()
        if not parts:
            return None
        if parts[0].decode(HTTP_HEADER_ENCODING).lower() not in AUTH_HEADER_TYPES:
            return None
        if len(parts) != 2:
            raise AuthenticationFailed(
                {
                    "code": "bad_authorization_header",
                    "detail": "Authorization header must be exactly "
                              "'Bearer <token>'.",
                }
            )
        return parts[1].decode(HTTP_HEADER_ENCODING)

    def authenticate(self, request):
        header = self.get_header(request)
        if header is None:
            return None

        raw_token = self.get_raw_token(header)
        if raw_token is None:
            return None

        payload = self.validate_token(raw_token)
        user = self.get_user(payload)

        request.auth_payload = payload
        return user, payload

    def authenticate_header(self, request) -> str:
        return f'{self.keyword} realm="{self.www_authenticate_realm}"'

    def validate_token(self, raw_token: str) -> dict:
        try:
            payload = self.token_class.decode(raw_token)
        except TokenError as exc:
            raise AuthenticationFailed(
                {"code": exc.code, "detail": exc.detail}
            ) from exc

        blacklist = get_blacklist()

        jti = payload.get("jti")
        if blacklist.is_revoked(jti):
            logger.warning("auth.rejected reason=revoked_jti jti=%s", jti)
            raise AuthenticationFailed(
                {"code": "token_revoked", "detail": "This token has been revoked."}
            )

        sid = payload.get("sid")
        if sid and sid != jti and blacklist.is_revoked(sid):
            logger.warning("auth.rejected reason=revoked_session sid=%s", sid)
            raise AuthenticationFailed(
                {
                    "code": "session_revoked",
                    "detail": "The session this token belongs to has been "
                              "terminated.",
                }
            )

        return payload

    def get_user(self, payload: dict):
        user_model = get_user_model()
        try:
            user = user_model.objects.get(pk=payload["sub"])
        except (
            user_model.DoesNotExist,
            DjangoValidationError,  # a `sub` that is not a well-formed UUID
            ValueError,
            TypeError,
            KeyError,
        ) as exc:
            logger.warning("auth.rejected reason=unknown_subject sub=%s",
                           payload.get("sub"))
            raise AuthenticationFailed(
                {"code": "user_not_found", "detail": "No active account matches "
                                                     "this token."}
            ) from exc

        if not user.is_active:
            logger.warning("auth.rejected reason=inactive_user sub=%s", user.pk)
            raise AuthenticationFailed(
                {"code": "user_inactive", "detail": "This account is disabled."}
            )

        if int(payload.get("tv", 0)) != user.token_version:
            logger.warning(
                "auth.rejected reason=stale_token_version sub=%s token_tv=%s user_tv=%s",
                user.pk, payload.get("tv"), user.token_version,
            )
            raise AuthenticationFailed(
                {
                    "code": "token_version_stale",
                    "detail": "Credentials were invalidated; please sign in again.",
                }
            )

        return user


class OptionalJWTAuthentication(JWTAuthentication):
    """
    Same checks, but a malformed/absent header yields anonymous instead of a
    401.  Used by endpoints that are public yet want to personalise output
    when a valid token happens to be present.
    """

    def authenticate(self, request):
        try:
            return super().authenticate(request)
        except AuthenticationFailed:
            return None
