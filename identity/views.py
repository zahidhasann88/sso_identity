from __future__ import annotations

from datetime import UTC, datetime

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import check_password, make_password
from django.core.exceptions import ValidationError as DjangoValidationError
from django.db import transaction
from django.urls import reverse
from django.utils import timezone
from rest_framework import status
from rest_framework.decorators import (
    api_view,
    authentication_classes,
    permission_classes,
    throttle_classes,
)
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import SimpleRateThrottle

from identity.authentication import JWTAuthentication, OptionalJWTAuthentication
from identity.blacklist import get_blacklist, to_aware
from identity.crypto import keyring
from identity.models import BlacklistedToken, SystemRole
from identity.security import LoginGuard, audit, client_ip
from identity.serializers import (
    IntrospectSerializer,
    LoginSerializer,
    LogoutSerializer,
    PasswordChangeSerializer,
    RefreshSerializer,
    RegistrationSerializer,
    UserSerializer,
)
from identity.tokens import (
    AccessToken,
    BaseToken,
    RefreshToken,
    TokenError,
    issue_token_pair,
)

User = get_user_model()

_DUMMY_HASH = make_password("!user-enumeration-timing-equalizer!")


class _LiveRateThrottle(SimpleRateThrottle):
    """
    Per-endpoint limiter for function-based views.

    DRF's ``ScopedRateThrottle`` reads ``view.throttle_scope``, which
    ``@api_view`` functions do not have, so it would silently never throttle.
    The scope is fixed on the class instead, and the rate is re-read from
    settings on every instantiation.
    """

    scope = "default"

    def get_rate(self) -> str | None:
        from rest_framework.settings import api_settings

        return (api_settings.DEFAULT_THROTTLE_RATES or {}).get(self.scope)

    def get_cache_key(self, request, view) -> str:
        user = getattr(request, "user", None)
        ident = (
            str(user.pk)
            if user is not None and user.is_authenticated
            else self.get_ident(request)
        )
        return f"throttle:{self.scope}:{ident}"


def _scoped(scope_name: str):
    return type(
        f"{scope_name.title().replace('_', '')}Throttle",
        (_LiveRateThrottle,),
        {"scope": scope_name},
    )


LoginThrottle = _scoped("auth_login")
RegisterThrottle = _scoped("auth_register")
RefreshThrottle = _scoped("auth_refresh")
LogoutThrottle = _scoped("auth_logout")
IntrospectThrottle = _scoped("auth_introspect")
PasswordChangeThrottle = _scoped("auth_password_change")


def _subject(payload: dict):
    """
    Resolve the user a token claims to belong to.

    A malformed ``sub`` makes the UUID field raise rather than return no match,
    which would turn a 401 into a 500.
    """
    try:
        return User.objects.filter(pk=payload.get("sub")).first()
    except (DjangoValidationError, ValueError, TypeError):
        return None


def error(request, code: str, detail: str, http_status: int, **extra):
    """
    Build the standard error envelope.

    Mirrors :func:`identity.exceptions.rfc7807_exception_handler`, request id
    included: an auth failure raised here must be as traceable as one raised
    through DRF's handler.
    """
    body = {"error": {"code": code, "detail": detail, "status": http_status}}
    if extra:
        body["error"].update(extra)
    request_id = getattr(request, "request_id", None)
    if request_id:
        body["error"]["request_id"] = request_id
    return Response(body, status=http_status)


@api_view(["POST"])
@authentication_classes([JWTAuthentication])
@permission_classes([AllowAny])
@throttle_classes([RegisterThrottle])
def register(request):
    """
    Create an account.

    Anonymous callers always get the ``USER`` role; an authenticated ADMIN may
    provision elevated roles (enforced in the serializer, not here).
    """
    serializer = RegistrationSerializer(data=request.data, context={"request": request})
    if not serializer.is_valid():
        audit("register.rejected", request, errors=list(serializer.errors))
        return Response(
            {
                "error": {
                    "code": "validation_error",
                    "detail": "Registration payload failed validation.",
                    "status": status.HTTP_400_BAD_REQUEST,
                    "fields": serializer.errors,
                }
            },
            status=status.HTTP_400_BAD_REQUEST,
        )

    user = serializer.save()
    audit("register.success", request, sub=user.pk, role=user.system_role)

    tokens = issue_token_pair(user)
    return Response(
        {"user": UserSerializer(user).data, "tokens": tokens},
        status=status.HTTP_201_CREATED,
    )


@api_view(["POST"])
@authentication_classes([])
@permission_classes([AllowAny])
@throttle_classes([LoginThrottle])
def login(request):
    """Exchange credentials for an access + refresh pair."""
    serializer = LoginSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)

    identifier = serializer.validated_data["identifier"]
    password = serializer.validated_data["password"]
    ip = client_ip(request)

    if LoginGuard.is_locked(identifier, ip):
        audit("login.locked", request, identifier_len=len(identifier))
        response = error(
            request,
            "too_many_failed_attempts",
            "Too many failed sign-in attempts. Try again later.",
            status.HTTP_429_TOO_MANY_REQUESTS,
        )
        response["Retry-After"] = str(LoginGuard.retry_after())
        return response

    user = (
        User.objects.filter(username__iexact=identifier).first()
        or User.objects.filter(email__iexact=identifier).first()
    )

    if user is None:
        check_password(password, _DUMMY_HASH)  # constant-time-ish equalizer
        LoginGuard.register_failure(identifier, ip)
        audit("login.failed", request, reason="unknown_identifier")
        return error(
            request,
            "invalid_credentials",
            "Invalid credentials.",
            status.HTTP_401_UNAUTHORIZED,
        )

    if not user.check_password(password):
        attempts = LoginGuard.register_failure(identifier, ip)
        audit("login.failed", request, reason="bad_password", sub=user.pk,
              attempts=attempts)
        return error(
            request,
            "invalid_credentials",
            "Invalid credentials.",
            status.HTTP_401_UNAUTHORIZED,
        )

    if not user.is_active:
        audit("login.failed", request, reason="inactive", sub=user.pk)
        return error(
            request,
            "user_inactive",
            "This account is disabled.",
            status.HTTP_403_FORBIDDEN,
        )

    LoginGuard.reset(identifier, ip)
    user.last_login = timezone.now()
    user.save(update_fields=["last_login"])

    tokens = issue_token_pair(user)
    audit("login.success", request, sub=user.pk, sid=tokens["session_id"])
    return Response(
        {"user": UserSerializer(user).data, "tokens": tokens}, status=status.HTTP_200_OK
    )


def _deny_replay(request, blacklist, payload: dict, *, user=None):
    """
    Handle a refresh token that has already been consumed or revoked.

    The legitimate holder and whoever replayed it both hold descendants of
    this session and there is no way to tell which is which, so the whole
    family is revoked rather than guessing.
    """
    jti, sid = payload["jti"], payload["sid"]
    blacklist.revoke(
        sid,
        to_aware(payload["exp"]),
        user=user,
        token_type="session",
        reason=BlacklistedToken.Reason.REUSE_DETECTED,
    )
    audit("refresh.reuse_detected", request, jti=jti, sid=sid)
    return error(
        request,
        "token_revoked",
        "This refresh token has already been used or revoked. The session "
        "has been terminated.",
        status.HTTP_401_UNAUTHORIZED,
    )


@api_view(["POST"])
@authentication_classes([])
@permission_classes([AllowAny])
@throttle_classes([RefreshThrottle])
def refresh(request):
    """
    Trade an unexpired, unrevoked refresh token for a fresh access token.

    With ``JWT_ROTATE_REFRESH_TOKENS`` (default on) the presented refresh
    token is consumed and replaced. Replaying a consumed token is treated as
    theft: the entire session is revoked immediately.
    """
    serializer = RefreshSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    raw = serializer.validated_data["refresh"]

    try:
        payload = RefreshToken.decode(raw)
    except TokenError as exc:
        audit("refresh.rejected", request, code=exc.code)
        return error(request, exc.code, exc.detail, status.HTTP_401_UNAUTHORIZED)

    blacklist = get_blacklist()
    jti, sid = payload["jti"], payload["sid"]

    if blacklist.is_revoked(jti):
        return _deny_replay(request, blacklist, payload)

    if sid != jti and blacklist.is_revoked(sid):
        audit("refresh.rejected", request, code="session_revoked", sid=sid)
        return error(
            request,
            "session_revoked",
            "The session this token belongs to has been terminated.",
            status.HTTP_401_UNAUTHORIZED,
        )

    user = _subject(payload)
    if user is None or not user.is_active:
        audit("refresh.rejected", request, code="user_unavailable",
              sub=payload.get("sub"))
        return error(
            request,
            "user_not_found",
            "No active account matches this token.",
            status.HTTP_401_UNAUTHORIZED,
        )

    if int(payload.get("tv", 0)) != user.token_version:
        audit("refresh.rejected", request, code="token_version_stale", sub=user.pk)
        return error(
            request,
            "token_version_stale",
            "Credentials were invalidated; please sign in again.",
            status.HTTP_401_UNAUTHORIZED,
        )

    rotate = settings.JWT_ROTATE_REFRESH_TOKENS
    consume = rotate and settings.JWT_BLACKLIST_AFTER_ROTATION

    with transaction.atomic():
        if consume:
            # Inserting the jti is the compare-and-swap that makes rotation
            # single-use: it is the ledger's primary key (SET NX in the other
            # backends), so of N simultaneous callers exactly one claims it.
            # The is_revoked() read above cannot do that on its own.
            claimed = blacklist.revoke(
                jti,
                to_aware(payload["exp"]),
                user=user,
                token_type="refresh",
                reason=BlacklistedToken.Reason.ROTATION,
            )
            if not claimed:
                return _deny_replay(request, blacklist, payload, user=user)

        access = AccessToken.for_user(user, session_id=sid)
        body = {
            "token_type": "Bearer",
            "access_token": access.encode(),
            "expires_in": access.expires_in,
            "access_jti": access.jti,
            "session_id": sid,
            "scope": access.payload.get("scope", ""),
        }

        if rotate:
            # The new refresh token keeps the original sid: it is the same
            # login session, just a new credential in the chain.
            new_refresh = RefreshToken.for_user(user, session_id=sid)
            body["refresh_token"] = new_refresh.encode()
            body["refresh_expires_in"] = new_refresh.expires_in
            body["refresh_jti"] = new_refresh.jti

    audit("refresh.success", request, sub=user.pk, sid=sid, rotated=bool(rotate))
    return Response(body, status=status.HTTP_200_OK)


@api_view(["POST"])
@authentication_classes([OptionalJWTAuthentication])
@permission_classes([AllowAny])
@throttle_classes([LogoutThrottle])
def logout(request):
    """
    Revoke a refresh token.

    * default            -> revokes that refresh token *and* its session id,
                            so access tokens minted from it stop working
                            before their natural 15-minute expiry.
    * ``all_sessions``   -> additionally bumps the user's token version,
                            invalidating every token ever issued to them.

    The refresh token in the body is the credential, so the access token is
    optional and a bad Authorization header is ignored: a client whose access
    token has already expired must still be able to sign out. Expired-but-
    parseable refresh tokens are accepted too, and the endpoint is idempotent.
    """
    serializer = LogoutSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    raw = serializer.validated_data["refresh"]
    all_sessions = serializer.validated_data["all_sessions"]

    try:
        payload = RefreshToken.decode(raw, verify_exp=False)
    except TokenError as exc:
        audit("logout.rejected", request, code=exc.code)
        return error(request, exc.code, exc.detail, status.HTTP_401_UNAUTHORIZED)

    blacklist = get_blacklist()
    jti, sid = payload["jti"], payload["sid"]
    expires_at = to_aware(payload["exp"])
    user = _subject(payload)

    reason = (
        BlacklistedToken.Reason.LOGOUT_ALL if all_sessions
        else BlacklistedToken.Reason.LOGOUT
    )

    with transaction.atomic():
        newly = blacklist.revoke(
            jti, expires_at, user=user, token_type="refresh", reason=reason
        )
        # Revoking the session id is what stops already-issued access tokens
        # of this session immediately, rather than at their natural expiry.
        blacklist.revoke(
            sid, expires_at, user=user, token_type="session", reason=reason
        )

        revoked_everywhere = False
        if all_sessions and user is not None:
            user.bump_token_version()
            revoked_everywhere = True

    audit(
        "logout.success",
        request,
        sub=payload.get("sub"),
        sid=sid,
        all_sessions=all_sessions,
        already_revoked=not newly,
    )
    return Response(
        {
            "revoked": True,
            "token_jti": jti,
            "session_id": sid,
            "already_revoked": not newly,
            "all_sessions_revoked": revoked_everywhere,
            "token_version": user.token_version if user else None,
            "detail": "Token revoked." if not all_sessions
                      else "All sessions for this account have been revoked.",
        },
        status=status.HTTP_200_OK,
    )


@api_view(["POST"])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
@throttle_classes([IntrospectThrottle])
def introspect(request):
    """Report whether a token is currently usable, and why not if it isn't."""
    serializer = IntrospectSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    raw = serializer.validated_data["token"]

    try:
        payload = BaseToken.decode(raw, expected_type=None)
    except TokenError as exc:
        return Response(
            {"active": False, "reason": exc.code, "detail": exc.detail},
            status=status.HTTP_200_OK,
        )

    # RFC 7662 leaves the authorization model to the deployment. Without this,
    # any authenticated caller could read the subject, role and scope of
    # someone else's token.
    if (
        str(payload.get("sub")) != str(request.user.pk)
        and request.user.system_role != SystemRole.ADMIN
    ):
        audit("introspect.denied", request, sub=request.user.pk)
        return error(
            request,
            "not_token_owner",
            "A token may only be introspected by its own subject or an "
            "administrator.",
            status.HTTP_403_FORBIDDEN,
        )

    blacklist = get_blacklist()
    if blacklist.is_revoked(payload["jti"]) or (
        payload.get("sid") != payload["jti"] and blacklist.is_revoked(payload["sid"])
    ):
        return Response(
            {"active": False, "reason": "token_revoked", "jti": payload["jti"]},
            status=status.HTTP_200_OK,
        )

    user = _subject(payload)
    if user is None or not user.is_active:
        return Response(
            {"active": False, "reason": "user_unavailable"}, status=status.HTTP_200_OK
        )
    if int(payload.get("tv", 0)) != user.token_version:
        return Response(
            {"active": False, "reason": "token_version_stale"},
            status=status.HTTP_200_OK,
        )

    return Response(
        {
            "active": True,
            "jti": payload["jti"],
            "sid": payload["sid"],
            "sub": payload["sub"],
            "typ": payload["typ"],
            "scope": payload.get("scope", ""),
            "role": payload.get("role"),
            "iss": payload["iss"],
            "aud": payload["aud"],
            "iat": payload["iat"],
            "exp": payload["exp"],
            "expires_at": datetime.fromtimestamp(
                payload["exp"], tz=UTC
            ).isoformat().replace("+00:00", "Z"),
        },
        status=status.HTTP_200_OK,
    )


@api_view(["GET"])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def me(request):
    """Return the principal behind the presented access token."""
    return Response(
        {
            "user": UserSerializer(request.user).data,
            "token": {
                "jti": request.auth_payload.get("jti"),
                "sid": request.auth_payload.get("sid"),
                "scope": request.auth_payload.get("scope", ""),
                "expires_at": datetime.fromtimestamp(
                    request.auth_payload["exp"], tz=UTC
                ).isoformat().replace("+00:00", "Z"),
            },
        },
        status=status.HTTP_200_OK,
    )


@api_view(["POST"])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
@throttle_classes([PasswordChangeThrottle])
def change_password(request):
    """Rotate the password and force re-authentication on every device."""
    serializer = PasswordChangeSerializer(
        data=request.data, context={"request": request}
    )
    serializer.is_valid(raise_exception=True)

    user = request.user
    with transaction.atomic():
        user.set_password(serializer.validated_data["new_password"])
        user.mark_password_changed(save=False)
        user.bump_token_version(save=False)
        user.save(update_fields=["password", "metadata"])

    audit("password.changed", request, sub=user.pk)
    tokens = issue_token_pair(user)
    return Response(
        {
            "detail": "Password updated. All previously issued tokens were "
                      "invalidated.",
            "tokens": tokens,
        },
        status=status.HTTP_200_OK,
    )


@api_view(["GET"])
@authentication_classes([])
@permission_classes([AllowAny])
def public_key(request):
    """
    Structured distribution of the public verification key.

    Relying-party services fetch this once and then validate tokens locally —
    that is the whole point of asymmetric issuance: only this service ever
    holds the private key.
    """
    ring = keyring()
    return Response(
        {
            "algorithm": ring.algorithm,
            "kid": ring.kid,
            "issuer": BaseToken.issuer(),
            "audience": BaseToken.audience(),
            "public_key_pem": ring.public_pem(),
            "jwk": ring.public_jwk(),
            # Non-empty only mid-rotation; the JWKS carries the full keys.
            "retired_kids": list(ring.retired_kids()),
            "jwks_uri": request.build_absolute_uri(reverse("jwks")),
            "token_lifetimes": {
                "access_seconds": int(AccessToken.lifetime().total_seconds()),
                "refresh_seconds": int(RefreshToken.lifetime().total_seconds()),
            },
        },
        status=status.HTTP_200_OK,
    )


@api_view(["GET"])
@authentication_classes([])
@permission_classes([AllowAny])
def jwks(request):
    """RFC 7517 JWK Set — the machine-readable public key endpoint."""
    response = Response(keyring().jwks(), status=status.HTTP_200_OK)
    response["Cache-Control"] = "public, max-age=300"
    return response


@api_view(["GET"])
@authentication_classes([])
@permission_classes([AllowAny])
def openid_configuration(request):
    """
    Discovery document so clients can self-configure from one URL.

    Served at the OIDC well-known path and shaped like an OIDC document because
    that is what client libraries look for, but this service is an OAuth2-style
    token issuer, not a full OpenID Connect provider: there is no authorization
    code flow and no ``id_token``. ``id_token_signing_alg_values_supported``
    describes the algorithm its access tokens are signed with.
    """
    base = request.build_absolute_uri("/").rstrip("/")
    return Response(
        {
            "issuer": BaseToken.issuer(),
            "jwks_uri": f"{base}{reverse('jwks')}",
            "token_endpoint": f"{base}{reverse('auth-login')}",
            "token_refresh_endpoint": f"{base}{reverse('auth-refresh')}",
            "revocation_endpoint": f"{base}{reverse('auth-logout')}",
            "introspection_endpoint": f"{base}{reverse('auth-introspect')}",
            "registration_endpoint": f"{base}{reverse('auth-register')}",
            "userinfo_endpoint": f"{base}{reverse('auth-me')}",
            "id_token_signing_alg_values_supported": [keyring().algorithm],
            "response_types_supported": ["token"],
            "grant_types_supported": ["password", "refresh_token"],
            "token_endpoint_auth_methods_supported": ["client_secret_post"],
            "claims_supported": [
                "iss", "sub", "aud", "exp", "iat", "nbf", "jti", "typ",
                "sid", "tv", "username", "email", "role", "scope",
            ],
        },
        status=status.HTTP_200_OK,
    )


@api_view(["GET"])
@authentication_classes([])
@permission_classes([AllowAny])
def health(request):
    """Liveness + readiness: DB reachable and signing key loadable."""
    checks = {"database": "ok", "signing_key": "ok"}
    http_status = status.HTTP_200_OK

    try:
        User.objects.exists()
    except Exception as exc:  # noqa: BLE001
        checks["database"] = f"error: {exc.__class__.__name__}"
        http_status = status.HTTP_503_SERVICE_UNAVAILABLE

    try:
        keyring().public_jwk()
    except Exception as exc:  # noqa: BLE001
        checks["signing_key"] = f"error: {exc.__class__.__name__}"
        http_status = status.HTTP_503_SERVICE_UNAVAILABLE

    return Response(
        {
            "status": "ok" if http_status == 200 else "degraded",
            "service": "sso-identity",
            "time": timezone.now().isoformat().replace("+00:00", "Z"),
            "checks": checks,
        },
        status=http_status,
    )
