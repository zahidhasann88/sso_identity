"""
Administrative global sign-out for a single principal.

    python manage.py revoke_user_tokens --username alice
    python manage.py revoke_user_tokens --email alice@example.com

Bumps the user's token version, which invalidates every access and refresh
token ever issued to them in O(1) — no enumeration of issued jtis needed.
"""

from __future__ import annotations

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError as DjangoValidationError
from django.core.management.base import BaseCommand, CommandError

User = get_user_model()


class Command(BaseCommand):
    help = "Invalidate every token issued to a user (incident response)."

    def add_arguments(self, parser) -> None:
        group = parser.add_mutually_exclusive_group(required=True)
        group.add_argument("--username", type=str)
        group.add_argument("--email", type=str)
        group.add_argument("--id", type=str, help="User UUID primary key.")
        parser.add_argument("--deactivate", action="store_true",
                            help="Also set is_active=False.")

    def handle(self, *args, **options):
        lookup = {}
        if options["username"]:
            lookup["username__iexact"] = options["username"]
        elif options["email"]:
            lookup["email__iexact"] = options["email"]
        else:
            lookup["pk"] = options["id"]

        try:
            user = User.objects.filter(**lookup).first()
        except (DjangoValidationError, ValueError) as exc:
            # --id with something that is not a UUID: a usage error, not a crash.
            raise CommandError(f"Invalid user lookup {lookup}: {exc}") from exc

        if user is None:
            raise CommandError(f"No user matches {lookup}.")

        version = user.bump_token_version()
        if options["deactivate"]:
            user.is_active = False
            user.save(update_fields=["is_active"])

        self.stdout.write(
            self.style.SUCCESS(
                f"All tokens for {user.username} revoked "
                f"(token_version -> {version})"
                + (", account deactivated." if options["deactivate"] else ".")
            )
        )
