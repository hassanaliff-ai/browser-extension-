# Private Gmail alert setup

The sender display name is ExtSecure. Gmail still requires an actual authenticated sender address behind that name.

Run scripts/configure_gmail_alerts.py with the project Python runtime (pythonw on Windows keeps the console hidden). The local window reads the sender/recipient from private configuration and masks the app-password entry. Supply the Gmail app password rather than the ordinary account password. It verifies TLS authentication and saves settings only after success; it does not send an email.

Restart TestAPI after successful setup so it loads the verified settings. A recreated temporary public tunnel may require the latest ZIP on other devices. Do not publish .env, app passwords or private backups in Git. Authentication setup does not prove that a real email has been delivered; verify delivery separately with a clearly labelled approved test.

Official Gmail references: https://support.google.com/mail/answer/185833 and https://developers.google.com/workspace/gmail/imap/imap-smtp

The local input accepts at least six characters and has no application-level maximum. It preserves the credential exactly, including spaces and symbols. Gmail still validates authentication, and settings are saved only after acceptance. This input rule does not change Gmail account/provider requirements.
