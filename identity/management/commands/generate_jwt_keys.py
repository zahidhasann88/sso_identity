"""
Generate an RSA signing keypair for JWT issuance.

    python manage.py generate_jwt_keys --size 4096 --out ./keys

Prints the matching env-var form so the private key can be injected as a
secret instead of a file in containerised deployments.
"""

from __future__ import annotations

import os
from pathlib import Path

from django.core.management.base import BaseCommand, CommandError

from identity.crypto import generate_rsa_keypair


class Command(BaseCommand):
    help = "Generate an RSA keypair (PKCS#8 PEM) for asymmetric JWT signing."

    def add_arguments(self, parser) -> None:
        parser.add_argument("--size", type=int, default=4096,
                            help="RSA modulus size in bits (min 2048).")
        parser.add_argument("--out", type=str, default="keys",
                            help="Output directory for the PEM files.")
        parser.add_argument("--force", action="store_true",
                            help="Overwrite an existing private key.")
        parser.add_argument("--print-env", action="store_true",
                            help="Also print a single-line JWT_PRIVATE_KEY export.")

    def handle(self, *args, **options):
        size = options["size"]
        if size < 2048:
            raise CommandError("Refusing to generate a key smaller than 2048 bits.")

        out_dir = Path(options["out"]).resolve()
        out_dir.mkdir(parents=True, exist_ok=True)
        private_path = out_dir / "jwt_private.pem"
        public_path = out_dir / "jwt_public.pem"

        if private_path.exists() and not options["force"]:
            raise CommandError(
                f"{private_path} already exists. Re-run with --force to replace it "
                f"(this invalidates every outstanding token)."
            )

        self.stdout.write(f"Generating {size}-bit RSA keypair...")
        private_pem, public_pem = generate_rsa_keypair(size)

        private_path.write_text(private_pem, encoding="utf-8")
        os.chmod(private_path, 0o600)
        public_path.write_text(public_pem, encoding="utf-8")
        os.chmod(public_path, 0o644)

        self.stdout.write(self.style.SUCCESS(f"  private key -> {private_path} (0600)"))
        self.stdout.write(self.style.SUCCESS(f"  public  key -> {public_path} (0644)"))

        if options["print_env"]:
            one_line = private_pem.replace("\n", "\\n")
            self.stdout.write("\nExport for container/secret injection:\n")
            self.stdout.write(f'JWT_PRIVATE_KEY="{one_line}"')

        self.stdout.write(
            self.style.WARNING(
                "\nNever commit the private key. Distribute only the public key "
                "(or point relying parties at /.well-known/jwks.json)."
            )
        )
