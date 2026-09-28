from __future__ import annotations

import uuid
from typing import Any

from django.contrib.auth.models import AbstractUser, UserManager
from django.db import models
from django.utils import timezone


class SystemRole(models.TextChoices):
    """Coarse-grained authorization tier stamped into every access token."""

    ADMIN = "ADMIN", "Administrator"
    DEVELOPER = "DEVELOPER", "Developer"
    USER = "USER", "User"


class CustomUserManager(UserManager):
    """Manager that keeps ``system_role`` consistent with Django's flags."""

    def create_superuser(self, username, email=None, password=None, **extra):
        extra.setdefault("system_role", SystemRole.ADMIN)
        return super().create_superuser(username, email, password, **extra)

    def get_by_natural_key(self, username: str):
        # Case-insensitive login on the username, matching the normalisation
        # performed by the registration serializer.
        return self.get(**{f"{self.model.USERNAME_FIELD}__iexact": username})


class CustomUser(AbstractUser):
    """
    Identity principal for the whole SSO estate.

    ``metadata`` is a free-form JSON bag for downstream services (tenant ids,
    feature flags, SCIM attributes...).  Two reserved keys are managed by this
    service itself:

    ``token_version``
        Monotonic counter mirrored into every token as the ``tv`` claim.
        Incrementing it invalidates *all* outstanding tokens for the user in
        O(1) — this is how "log out everywhere" works without enumerating
        every issued jti.
    ``password_changed_at``
        ISO-8601 timestamp of the last credential change, for audit trails.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    email = models.EmailField(
        "email address",
        unique=True,
        error_messages={"unique": "A user with that email already exists."},
    )
    system_role = models.CharField(
        max_length=16,
        choices=SystemRole.choices,
        default=SystemRole.USER,
        # No db_index: the (system_role, is_active) index below leads with
        # this column and already serves lookups on it.
        help_text="Authorization tier embedded in the access token 'role' claim.",
    )
    metadata = models.JSONField(
        default=dict,
        blank=True,
        help_text="Arbitrary JSON claims/attributes propagated to relying parties.",
    )

    objects = CustomUserManager()

    REQUIRED_FIELDS = ["email"]

    class Meta:
        db_table = "identity_user"
        verbose_name = "user"
        verbose_name_plural = "users"
        indexes = [
            models.Index(fields=["system_role", "is_active"], name="idx_user_role_active"),
        ]

    def __str__(self) -> str:
        return f"{self.username} <{self.email}> [{self.system_role}]"

    @property
    def token_version(self) -> int:
        try:
            return int((self.metadata or {}).get("token_version", 0))
        except (TypeError, ValueError):
            return 0

    def bump_token_version(self, *, save: bool = True) -> int:
        """
        Invalidate every token ever issued to this user (global sign-out).

        Returns the new version. Tokens carrying an older ``tv`` claim are
        rejected by :class:`identity.authentication.JWTAuthentication`.
        """
        meta = dict(self.metadata or {})
        meta["token_version"] = self.token_version + 1
        meta["tokens_revoked_at"] = timezone.now().isoformat()
        self.metadata = meta
        if save:
            self.save(update_fields=["metadata"])
        return meta["token_version"]

    def mark_password_changed(self, *, save: bool = True) -> None:
        meta = dict(self.metadata or {})
        meta["password_changed_at"] = timezone.now().isoformat()
        self.metadata = meta
        if save:
            self.save(update_fields=["metadata"])

    def public_claims(self) -> dict[str, Any]:
        """Non-sensitive attributes safe to embed inside a signed token."""
        meta = dict(self.metadata or {})
        return {
            "username": self.username,
            "email": self.email,
            "role": self.system_role,
            "is_staff": self.is_staff,
            "is_superuser": self.is_superuser,
            "tv": self.token_version,
            "meta": {
                key: value
                for key, value in meta.items()
                if key not in {"token_version", "password_changed_at", "tokens_revoked_at"}
            },
        }


class BlacklistedTokenQuerySet(models.QuerySet):
    def expired(self):
        return self.filter(expires_at__lte=timezone.now())

    def active(self):
        return self.filter(expires_at__gt=timezone.now())


class BlacklistedToken(models.Model):
    """
    Revocation ledger — one row per invalidated ``jti``.

    The primary key *is* the jti, so a revocation check is a single indexed
    point lookup and double-revocation is idempotent by construction.
    Rows are garbage-collectable once ``expires_at`` has passed: after natural
    expiry the signature check alone rejects the token, so retaining the row
    buys nothing.
    """

    class Reason(models.TextChoices):
        LOGOUT = "LOGOUT", "User logout"
        LOGOUT_ALL = "LOGOUT_ALL", "Global sign-out"
        ROTATION = "ROTATION", "Refresh token rotated"
        REUSE_DETECTED = "REUSE_DETECTED", "Replay of a consumed refresh token"
        ADMIN_REVOKE = "ADMIN_REVOKE", "Administrative revocation"
        PASSWORD_CHANGE = "PASSWORD_CHANGE", "Credential change"

    token_jti = models.CharField(
        primary_key=True,
        max_length=64,
        editable=False,
        help_text="Unique token identifier (jti claim) that is now revoked.",
    )
    invalidated_at = models.DateTimeField(auto_now_add=True, db_index=True)
    expires_at = models.DateTimeField(
        # Indexed as idx_blacklist_expires below, not here: two indexes on one
        # column cost writes and buy nothing.
        help_text="Natural expiry of the revoked token; row is prunable after this.",
    )

    user = models.ForeignKey(
        "identity.CustomUser",
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name="blacklisted_tokens",
        # Django would index this by default, but (user, invalidated_at)
        # below already leads with it and this table takes a write on every
        # logout and rotation.
        db_index=False,
    )
    token_type = models.CharField(max_length=16, default="refresh")
    reason = models.CharField(
        max_length=32, choices=Reason.choices, default=Reason.LOGOUT
    )

    objects = BlacklistedTokenQuerySet.as_manager()

    class Meta:
        db_table = "identity_blacklisted_token"
        verbose_name = "blacklisted token"
        verbose_name_plural = "blacklisted tokens"
        ordering = ("-invalidated_at",)
        indexes = [
            models.Index(fields=["expires_at"], name="idx_blacklist_expires"),
            models.Index(fields=["user", "invalidated_at"], name="idx_blacklist_user"),
        ]

    def __str__(self) -> str:
        return f"{self.token_jti} revoked at {self.invalidated_at:%Y-%m-%dT%H:%M:%SZ}"

    @property
    def is_expired(self) -> bool:
        return self.expires_at <= timezone.now()
