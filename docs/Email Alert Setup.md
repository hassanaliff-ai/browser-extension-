# Private Gmail alert setup

The sender display name is ExtSecure. Gmail still requires an actual authenticated sender address behind that name.

Run scripts/configure_gmail_alerts.py with the project Python runtime (pythonw on Windows keeps the console hidden). The local window reads the sender/recipient from private configuration and masks the app-password entry. Supply the Gmail app password rather than the ordinary account password. It verifies TLS authentication and saves settings only after success; it does not send an email.

Restart TestAPI after successful setup so it loads the verified settings. A recreated temporary public tunnel may require the latest ZIP on other devices. Do not publish .env, app passwords or private backups in Git. Authentication setup does not prove that a real email has been delivered; verify delivery separately with a clearly labelled approved test.

Official Gmail references: https://support.google.com/mail/answer/185833 and https://developers.google.com/workspace/gmail/imap/imap-smtp

The local input accepts at least six characters and has no application-level maximum. It preserves the credential exactly, including spaces and symbols. Gmail still validates authentication, and settings are saved only after acceptance. This input rule does not change Gmail account/provider requirements.

Connection diagnostics distinguish Gmail SMTP disconnections/authentication failures from TestAPI reachability. Successful TCP/TLS connectivity does not prove sender authentication. Rejected or disconnected verification attempts do not save the submitted password or send mail.

Gmail authentication uses exactly one AUTH PLAIN challenge after STARTTLS. Automatic retries across authentication mechanisms were removed because a later disconnect could hide Gmail's original 535 credential rejection. The UI distinguishes SMTP 535, additional authorization (534), a true disconnect and a network/TLS problem. Verification received 535 for the submitted credential; it was not saved, and no mail was sent. Eighteen setup regression tests pass.

## Automatic Gmail sending without Google Cloud setup

Use the masked local setup window and choose **Open Google app passwords**. Enable Google two-step verification if required, generate an app password named ExtSecure, and enter it locally. An ordinary Gmail sign-in password is not a substitute. No OAuth client or Google Cloud project is required for this route. If the Google account does not offer app passwords, account restrictions must be resolved or OAuth used instead.

The sender remains ExtSecure. Authentication must succeed before credentials are saved. Until then automatic email is not configured. After verification, restart TestAPI to load settings and separately verify an authorized test message in the recipient mailbox. SMTP acceptance does not guarantee inbox delivery. The extension and public GitHub repository contain no email credentials.
