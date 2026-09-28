from django.apps import AppConfig


class IdentityConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "identity"
    verbose_name = "SSO Identity Provider"

    def ready(self) -> None:
        from django.conf import settings

        from identity import checks  # noqa: F401  - registers the system checks

        if getattr(settings, "JWT_WARM_KEYRING_ON_BOOT", True):
            from identity.crypto import keyring

            # Surface an unusable key or algorithm at boot, not on first use.
            keyring().public_jwk()
