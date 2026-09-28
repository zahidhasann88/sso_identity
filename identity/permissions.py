from __future__ import annotations

from rest_framework.permissions import BasePermission

from identity.models import SystemRole


class HasSystemRole(BasePermission):
    """Grant access only to principals holding one of ``required_roles``."""

    required_roles: tuple[str, ...] = ()
    message = "Your system role is not permitted to perform this action."

    def has_permission(self, request, view) -> bool:
        user = request.user
        if not (user and user.is_authenticated):
            return False
        roles = getattr(view, "required_roles", None) or self.required_roles
        return not roles or user.system_role in roles


class IsAdminRole(HasSystemRole):
    required_roles = (SystemRole.ADMIN,)
    message = "Administrator role required."


class IsDeveloperOrAdmin(HasSystemRole):
    required_roles = (SystemRole.ADMIN, SystemRole.DEVELOPER)
    message = "Developer or administrator role required."


class HasTokenScope(BasePermission):
    """
    Enforce the OAuth2-style ``scope`` claim carried by the access token.

    Declare ``required_scopes = ("identity:write",)`` on the view; all listed
    scopes must be present in the token.
    """

    message = "Token is missing a required scope."

    def has_permission(self, request, view) -> bool:
        required = set(getattr(view, "required_scopes", ()) or ())
        if not required:
            return True
        payload = getattr(request, "auth_payload", None) or {}
        granted = set(str(payload.get("scope", "")).split())
        return required.issubset(granted)
