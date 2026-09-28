"""
Prune revocation rows whose underlying token has already expired.

Once ``expires_at`` has passed, the signature/exp check rejects the token on
its own, so the row provides no additional security — only table bloat.

    python manage.py purge_blacklist            # delete expired rows
    python manage.py purge_blacklist --dry-run  # report only

Run it from cron/Celery beat once an hour.
"""

from __future__ import annotations

from django.core.management.base import BaseCommand

from identity.blacklist import get_blacklist
from identity.models import BlacklistedToken


class Command(BaseCommand):
    help = "Delete expired entries from the token revocation ledger."

    def add_arguments(self, parser) -> None:
        parser.add_argument("--dry-run", action="store_true",
                            help="Report what would be deleted without deleting.")

    def handle(self, *args, **options):
        expired = BlacklistedToken.objects.expired()
        count = expired.count()
        total = BlacklistedToken.objects.count()

        if options["dry_run"]:
            self.stdout.write(
                f"{count} of {total} revocation rows are expired and prunable."
            )
            return

        deleted = get_blacklist().purge_expired()
        self.stdout.write(
            self.style.SUCCESS(
                f"Purged {deleted} expired revocation rows "
                f"({total - count} active entries retained)."
            )
        )
