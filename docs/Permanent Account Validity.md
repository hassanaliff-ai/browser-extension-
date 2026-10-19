# Permanent account validity — 19 October 2026

Registered ExtSecure accounts have no expiry date or age-based deactivation. The registered_administrators table contains account status and approval metadata, without an account-expiry field. The directory checks approval and explicit access status, not how old the account or approval is. Completed registrations waiting for review are also persistent; they are not temporary authenticator-setup records.

Version 0.8.37 makes this policy visible as Account validity: Unlimited (no expiry) in My account and the approved-accounts table, with English and Arabic text. The login screen explains that session expiry requires another login using the same account, never another registration.

Separate lifetimes remain unchanged: login sessions last 24 hours by default; the password-to-authenticator challenge is short-lived; unfinished authenticator setup expires after 15 minutes; authenticator codes rotate. None of those time limits deletes or expires a registered account. An authorized administrator can still disable or delete access explicitly. Existing account deletions requested by the owner were not reversed.

Regression checks cover an account with approval/creation dates ten years old signing in ten further years later, and an expired login session followed by successful password/authenticator login with the same original account and credentials. No automatic re-registration, password change or 2FA bypass is used.

Verification: 251 JavaScript tests and 13 backend registration tests passed, including both account-lifetime regressions.
