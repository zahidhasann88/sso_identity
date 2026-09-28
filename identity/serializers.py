from __future__ import annotations

import json
import re
from typing import Any

from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
from django.db import IntegrityError, transaction
from rest_framework import serializers

from identity.models import SystemRole

User = get_user_model()

USERNAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{2,149}$")
MAX_METADATA_BYTES = 8 * 1024
RESERVED_METADATA_KEYS = {"token_version", "password_changed_at", "tokens_revoked_at"}


class UserSerializer(serializers.ModelSerializer):
    """Safe projection of a principal — never exposes password material."""

    class Meta:
        model = User
        fields = (
            "id",
            "username",
            "email",
            "first_name",
            "last_name",
            "system_role",
            "metadata",
            "is_active",
            "date_joined",
            "last_login",
        )
        read_only_fields = fields


class RegistrationSerializer(serializers.ModelSerializer):
    """
    Account creation with strict field validation.

    Passwords are run through Django's full validator chain and stored as a
    salted Argon2/PBKDF2 hash via ``set_password`` — the plaintext never
    touches the database, logs or the response body.
    """

    password = serializers.CharField(
        write_only=True, min_length=12, max_length=128, trim_whitespace=False,
        style={"input_type": "password"},
    )
    password_confirm = serializers.CharField(
        write_only=True, max_length=128, trim_whitespace=False,
        style={"input_type": "password"},
    )
    system_role = serializers.ChoiceField(
        choices=SystemRole.choices, default=SystemRole.USER
    )
    metadata = serializers.JSONField(required=False, default=dict)

    class Meta:
        model = User
        fields = (
            "id",
            "username",
            "email",
            "first_name",
            "last_name",
            "password",
            "password_confirm",
            "system_role",
            "metadata",
        )
        read_only_fields = ("id",)
        extra_kwargs = {
            "first_name": {"required": False, "allow_blank": True, "max_length": 150},
            "last_name": {"required": False, "allow_blank": True, "max_length": 150},
        }

    def validate_username(self, value: str) -> str:
        value = (value or "").strip()
        if not USERNAME_RE.match(value):
            raise serializers.ValidationError(
                "Username must be 3-150 characters, start alphanumeric, and "
                "contain only letters, digits, dot, underscore or hyphen."
            )
        if User.objects.filter(username__iexact=value).exists():
            raise serializers.ValidationError("This username is already taken.")
        return value

    def validate_email(self, value: str) -> str:
        value = (value or "").strip().lower()
        if not value:
            raise serializers.ValidationError("Email is required.")
        if User.objects.filter(email__iexact=value).exists():
            raise serializers.ValidationError("A user with that email already exists.")
        return value

    def validate_metadata(self, value: Any) -> dict:
        if value in (None, ""):
            return {}
        if not isinstance(value, dict):
            raise serializers.ValidationError("metadata must be a JSON object.")
        reserved = RESERVED_METADATA_KEYS.intersection(value)
        if reserved:
            raise serializers.ValidationError(
                f"These metadata keys are reserved and managed by the service: "
                f"{sorted(reserved)}."
            )
        if len(json.dumps(value).encode()) > MAX_METADATA_BYTES:
            raise serializers.ValidationError(
                f"metadata exceeds the {MAX_METADATA_BYTES} byte limit."
            )
        return value

    def validate_system_role(self, value: str) -> str:
        """
        Privilege-escalation guard: only an authenticated ADMIN may create a
        privileged account. Anonymous self-registration is always USER.
        """
        request = self.context.get("request")
        actor = getattr(request, "user", None)
        actor_is_admin = bool(
            actor and actor.is_authenticated and actor.system_role == SystemRole.ADMIN
        )
        if value != SystemRole.USER and not actor_is_admin:
            raise serializers.ValidationError(
                "Only an administrator may provision an account with an "
                "elevated system_role."
            )
        return value

    def validate(self, attrs: dict) -> dict:
        if attrs.get("password") != attrs.get("password_confirm"):
            raise serializers.ValidationError(
                {"password_confirm": "Passwords do not match."}
            )

        probe = User(
            username=attrs.get("username", ""),
            email=attrs.get("email", ""),
            first_name=attrs.get("first_name", ""),
            last_name=attrs.get("last_name", ""),
        )
        try:
            validate_password(attrs["password"], user=probe)
        except DjangoValidationError as exc:
            raise serializers.ValidationError({"password": list(exc.messages)}) from exc
        return attrs

    def create(self, validated_data: dict):
        validated_data.pop("password_confirm", None)
        password = validated_data.pop("password")
        metadata = validated_data.pop("metadata", {}) or {}
        metadata["token_version"] = 0

        user = User(**validated_data, metadata=metadata)
        user.set_password(password)

        # The uniqueness validators above are reads, so two registrations for
        # the same username can both pass them and one then loses at the
        # constraint. That is a client error, not a 500. The savepoint keeps
        # the surrounding transaction usable afterwards.
        try:
            with transaction.atomic():
                user.full_clean(exclude=["password"])
                user.save()
        except DjangoValidationError as exc:
            raise serializers.ValidationError(
                getattr(exc, "message_dict", None)
                or {"non_field_errors": list(exc.messages)}
            ) from exc
        except IntegrityError as exc:
            raise serializers.ValidationError(
                {"non_field_errors": [
                    "That username or email address is already registered."
                ]}
            ) from exc
        return user


class LoginSerializer(serializers.Serializer):
    """Credential envelope. Accepts username *or* email in ``identifier``."""

    identifier = serializers.CharField(max_length=254, required=False, allow_blank=True)
    username = serializers.CharField(max_length=150, required=False, allow_blank=True)
    email = serializers.EmailField(required=False, allow_blank=True)
    password = serializers.CharField(
        write_only=True, max_length=128, trim_whitespace=False,
        style={"input_type": "password"},
    )

    def validate(self, attrs: dict) -> dict:
        identifier = (
            attrs.get("identifier") or attrs.get("username") or attrs.get("email") or ""
        ).strip()
        if not identifier:
            raise serializers.ValidationError(
                {"identifier": "Provide a username or email address."}
            )
        attrs["identifier"] = identifier
        return attrs


class RefreshSerializer(serializers.Serializer):
    refresh = serializers.CharField(max_length=4096, trim_whitespace=True)


class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField(max_length=4096, trim_whitespace=True)
    all_sessions = serializers.BooleanField(
        default=False,
        help_text="When true, invalidate every token ever issued to this user.",
    )


class PasswordChangeSerializer(serializers.Serializer):
    current_password = serializers.CharField(write_only=True, trim_whitespace=False)
    new_password = serializers.CharField(
        write_only=True, min_length=12, max_length=128, trim_whitespace=False
    )

    def validate_new_password(self, value: str) -> str:
        user = self.context["request"].user
        try:
            validate_password(value, user=user)
        except DjangoValidationError as exc:
            raise serializers.ValidationError(list(exc.messages)) from exc
        return value

    def validate_current_password(self, value: str) -> str:
        if not self.context["request"].user.check_password(value):
            raise serializers.ValidationError("Current password is incorrect.")
        return value

    def validate(self, attrs: dict) -> dict:
        if attrs["current_password"] == attrs["new_password"]:
            raise serializers.ValidationError(
                {"new_password": "New password must differ from the current one."}
            )
        return attrs


class IntrospectSerializer(serializers.Serializer):
    """RFC 7662-style introspection request."""

    token = serializers.CharField(max_length=4096, trim_whitespace=True)
    token_type_hint = serializers.ChoiceField(
        choices=("access", "refresh"), required=False
    )
