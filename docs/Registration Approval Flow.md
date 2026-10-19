# Registration and approval flow — 18 October 2026

Extension **0.8.34** makes the distinction between creating an account and
signing in explicit. The login page uses the existing **Register account** option, with no duplicate
account-creation button. Switching preserves the username only; it does not carry a password
into a new account or create an account automatically after a failed login.

Version 0.8.36 corrects the earlier failed-login advice. Failed sign-in now asks
users to use their existing credentials and have the head administrator check
approval or access status. It does not tell already registered users to create
another account or reveal whether an arbitrary username exists.

After successful authenticator verification, a **Registration submitted** screen
shows the server-confirmed username, requested role and destination API address.
The receipt contains no password, authenticator secret, code, bearer token or
enrollment token. It remains in trusted extension session storage across popup
and console page closure, until dismissed, successful sign-in or the browser
session ends. It is shown only for its matching configured API origin. The
receipt proves submission, not approval or continued approval status.

The Accounts screen explains that only completed authenticator enrollments enter
the pending queue. It refreshes every 15 seconds when visible and no form is
being edited, using the same guarded refresh used by inventory. Role filtering,
identity review, backend approval and two-factor login enforcement are retained.

## Verification

- 250 JavaScript tests passed, including receipt validation, omission of secrets,
  escaped display and authenticated-state separation.
- Real Chromium MV3 verification passed nine checks: unknown-login guidance,
  the existing Register account option with username-only preservation, real registration and
  authenticator verification, confirmation after page reload, denial before
  approval, appearance in the head administrator's queue, approval through the
  real form, password/authenticator login after approval, and no page errors.
- 16 backend registration and hierarchical approval regression tests passed.

The browser test used generated credentials and `signup-example` in an isolated
database and browser profile. It did not create or approve Basel's live account,
choose his password or bypass authenticator enrollment. Subsequent live checks
confirmed Basel completed registration and approval. On 19 October his account
was found disabled; the owner's requested repair restored its previously approved
access while preserving the existing password and authenticator. He should use
Log in with the existing account, rather than register again.
