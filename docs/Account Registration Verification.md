# Account registration and login

Registration has no invitation code. Enter a username and matching password of
at least 12 characters, scan the private QR code with an authenticator (or use
the collapsible manual setup key) and
verify its code within 15 minutes. This creates a pending request, not a session.
Only the Head of Administrator can authorize access, select a role and record
the review reason in Accounts. Pending, rejected, disabled and unapproved
accounts cannot log in or use existing sessions. Password-only challenges and
enrollment tokens are never accepted as dashboard sessions.

QR images are generated locally in memory from the backend's ExtSecure TOTP
enrollment URI. No external QR provider receives the secret. QR and manual
enrollment use the same secret and generate the same six-digit codes; neither
adds an authentication factor. Invalid, expired and cancelled enrollment
details are removed from the registration UI. Keep enrollment images and keys
private. The password-plus-TOTP sign-in remains backend enforced for every role.

For the existing main account, run
`python -m alba_security.provision_head --env .env --export-qr` on the server.
It exports an offline QR setup page and PNG
to the restricted `.private` folder without changing any credentials or settings.
Fresh owner provisioning includes these files too. The HTML page has no external
resources or scripts, and contains no password. Remove enrollment copies when
no longer required, retaining any recovery material securely.

Approved users log in with a password and fresh authenticator code. An enrollment
code cannot be reused for login. Administrator, Manager and Normal user have
separate backend permissions and dashboard navigation. The main administrator
alone controls approval, role changes and disabling. Role changes and disabling
revoke sessions; the main account cannot be demoted or disabled through the API.
Configured reviewers also require main-administrator approval.

Passwords are hashed with Argon2id. TOTP secrets use Fernet authenticated
encryption and opaque enrollment/session tokens are stored as hashes.
Registration, login and code verification share rate limits. Authentication
responses use no-store caching. A dedicated ADMIN_ACCOUNT_ENCRYPTION_KEY can be
set before registration; otherwise encryption derives from the primary TOTP
secret. Retain the encryption key with database backups. Password recovery and
encryption-key rotation are not implemented.

On upgrade, earlier registered accounts without verifiable owner approval return
to pending review with their credential hashes and encrypted secrets preserved.
Legacy invitation endpoints are retired and old enrollment tokens are unusable.
New registrations use the separate account_registration_enrollments table.

Normal-user file checks use a server-assigned device identity and authenticated
scan ownership. They cannot retrieve another person's personal scan, query
organization monitoring or change security settings. The original scan endpoint
also requires approved access when monitoring is enabled.

See [Account roles and access](Account%20Roles%20and%20Access.md) for privileges
and verification coverage. Tests use temporary SQLite databases and isolated
service integrations. Live PostgreSQL and independent users remain deployment
verification tasks. The demonstration uses synthetic data and disposable accounts.
