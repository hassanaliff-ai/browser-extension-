"""Generate local administrator credentials for the API configuration."""

from __future__ import annotations

import getpass
import argparse

import pyotp
from argon2 import PasswordHasher


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate administrator enrollment values")
    parser.add_argument('--reviewer', action='store_true', help='Generate independent policy reviewer configuration')
    options = parser.parse_args()
    default_name = "reviewer" if options.reviewer else "head-of-administrator"
    username = input(f"Administrator username [{default_name}]: ").strip() or default_name
    password = getpass.getpass("Administrator password: ")
    confirmation = getpass.getpass("Confirm password: ")
    if len(password) < 12:
        raise SystemExit("Use an administrator password of at least 12 characters.")
    if password != confirmation:
        raise SystemExit("Passwords did not match.")
    secret = pyotp.random_base32()
    password_hash = PasswordHasher().hash(password)
    enrollment_uri = pyotp.TOTP(secret).provisioning_uri(
        name=username, issuer_name="ExtSecure"
    )
    print("\nStore these values securely in the API host environment:")
    prefix = 'ADMIN_REVIEWER' if options.reviewer else 'ADMIN'
    print(f"{prefix}_USERNAME={username}")
    print(f"{prefix}_PASSWORD_HASH={password_hash}")
    print(f"{prefix}_TOTP_SECRET={secret}")
    print("\nAdd this URI to an authenticator app before starting the API:")
    print(enrollment_uri)


if __name__ == "__main__":
    main()
