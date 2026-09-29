"""Generate local administrator credentials for the API configuration."""

from __future__ import annotations

import getpass

import pyotp
from argon2 import PasswordHasher


def main() -> None:
    username = input("Administrator username [admin]: ").strip() or "admin"
    password = getpass.getpass("Administrator password: ")
    confirmation = getpass.getpass("Confirm password: ")
    if len(password) < 12:
        raise SystemExit("Use an administrator password of at least 12 characters.")
    if password != confirmation:
        raise SystemExit("Passwords did not match.")
    secret = pyotp.random_base32()
    password_hash = PasswordHasher().hash(password)
    enrollment_uri = pyotp.TOTP(secret).provisioning_uri(
        name=username, issuer_name="Alba Security Analyzer"
    )
    print("\nStore these values securely in the API host environment:")
    print(f"ADMIN_USERNAME={username}")
    print(f"ADMIN_PASSWORD_HASH={password_hash}")
    print(f"ADMIN_TOTP_SECRET={secret}")
    print("\nAdd this URI to an authenticator app before starting the API:")
    print(enrollment_uri)


if __name__ == "__main__":
    main()
