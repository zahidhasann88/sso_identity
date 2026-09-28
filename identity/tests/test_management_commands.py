"""
The operational commands: key generation and administrative revocation.

``generate_jwt_keys`` is how a deployment gets its signing key, so its guard
rails — a minimum size, and no silent overwrite of a key that is currently
signing — are part of the security posture.
"""

from __future__ import annotations

import tempfile
from io import StringIO
from pathlib import Path

from django.core.management import call_command
from django.core.management.base import CommandError

from identity.crypto import generate_rsa_keypair
from identity.models import SystemRole
from identity.tests.base import IdentityAPITestCase


class GenerateJwtKeysTests(IdentityAPITestCase):
    def setUp(self) -> None:
        super().setUp()
        self._tmp = tempfile.TemporaryDirectory()
        self.out_dir = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def generate(self, **options) -> str:
        out = StringIO()
        call_command(
            "generate_jwt_keys", out=str(self.out_dir), stdout=out, **options
        )
        return out.getvalue()

    def test_a_keypair_is_written_and_the_pair_matches(self):
        # 2048 keeps the test fast; the documented default is 4096.
        output = self.generate(size=2048)

        private_path = self.out_dir / "jwt_private.pem"
        public_path = self.out_dir / "jwt_public.pem"
        self.assertTrue(private_path.is_file())
        self.assertTrue(public_path.is_file())
        self.assertIn("BEGIN PRIVATE KEY", private_path.read_text())
        self.assertIn("BEGIN PUBLIC KEY", public_path.read_text())
        self.assertNotIn("PRIVATE", public_path.read_text())
        self.assertIn("private key", output)

        import jwt

        token = jwt.encode({"x": 1}, private_path.read_text(), algorithm="RS256")
        self.assertEqual(
            jwt.decode(token, public_path.read_text(), algorithms=["RS256"])["x"], 1
        )

    def test_a_weak_key_size_is_refused(self):
        with self.assertRaises(CommandError):
            self.generate(size=1024)
        self.assertFalse((self.out_dir / "jwt_private.pem").exists())

    def test_an_existing_key_is_not_silently_replaced(self):
        """
        Overwriting the signing key invalidates every outstanding token, so it
        has to be asked for explicitly.
        """
        self.generate(size=2048)
        original = (self.out_dir / "jwt_private.pem").read_text()

        with self.assertRaises(CommandError) as caught:
            self.generate(size=2048)
        self.assertIn("--force", str(caught.exception))
        self.assertEqual((self.out_dir / "jwt_private.pem").read_text(), original)

    def test_force_replaces_the_key(self):
        self.generate(size=2048)
        original = (self.out_dir / "jwt_private.pem").read_text()

        self.generate(size=2048, force=True)
        self.assertNotEqual((self.out_dir / "jwt_private.pem").read_text(), original)

    def test_print_env_emits_a_single_line_form(self):
        output = self.generate(size=2048, print_env=True)
        exported = next(
            line for line in output.splitlines() if line.startswith("JWT_PRIVATE_KEY=")
        )
        # One line, with the newlines escaped so it survives an env var.
        self.assertIn(chr(92) + "n", exported)
        self.assertNotIn("-----END PRIVATE KEY-----" + chr(10), exported)

    def test_the_operator_is_warned_not_to_commit_the_key(self):
        self.assertIn("Never commit the private key", self.generate(size=2048))


class RevokeUserTokensTests(IdentityAPITestCase):
    def test_revocation_by_username_email_and_id(self):
        for index, lookup in enumerate(("username", "email", "id")):
            user = self.make_user(f"revoked{index}")
            value = {
                "username": user.username,
                "email": user.email,
                "id": str(user.pk),
            }[lookup]

            out = StringIO()
            call_command("revoke_user_tokens", **{lookup: value}, stdout=out)

            user.refresh_from_db()
            self.assertEqual(user.token_version, 1, lookup)
            self.assertIn("token_version -> 1", out.getvalue())

    def test_deactivate_also_disables_the_account(self):
        user = self.make_user("gone", role=SystemRole.DEVELOPER)
        call_command(
            "revoke_user_tokens", username="gone", deactivate=True, stdout=StringIO()
        )
        user.refresh_from_db()
        self.assertFalse(user.is_active)
        self.assertEqual(user.token_version, 1)

    def test_an_unknown_user_is_a_usage_error(self):
        with self.assertRaises(CommandError):
            call_command("revoke_user_tokens", username="nobody", stdout=StringIO())

    def test_a_malformed_uuid_is_a_usage_error_not_a_traceback(self):
        """``--id not-a-uuid`` must report a usage problem, not crash."""
        with self.assertRaises(CommandError) as caught:
            call_command("revoke_user_tokens", id="not-a-uuid", stdout=StringIO())
        self.assertIn("Invalid user lookup", str(caught.exception))

    def test_revocation_takes_effect_on_live_tokens(self):
        self.make_user("live")
        tokens = self.login("live")
        self.assertEqual(
            self.client.get(
                "/api/auth/me/", **self.bearer(tokens["access_token"])
            ).status_code,
            200,
        )

        call_command("revoke_user_tokens", username="live", stdout=StringIO())

        probe = self.client.get("/api/auth/me/", **self.bearer(tokens["access_token"]))
        self.assertEqual(probe.status_code, 401)
        self.assertEqual(probe.data["error"]["code"], "token_version_stale")


class PurgeBlacklistDryRunTests(IdentityAPITestCase):
    def test_dry_run_reports_without_deleting(self):
        from datetime import timedelta

        from django.utils import timezone

        from identity.models import BlacklistedToken

        BlacklistedToken.objects.create(
            token_jti="old", expires_at=timezone.now() - timedelta(days=1)
        )
        out = StringIO()
        call_command("purge_blacklist", dry_run=True, stdout=out)

        self.assertIn("prunable", out.getvalue())
        self.assertEqual(BlacklistedToken.objects.count(), 1)


class KeypairHelperTests(IdentityAPITestCase):
    def test_the_generator_refuses_weak_sizes(self):
        with self.assertRaises(ValueError):
            generate_rsa_keypair(1024)
