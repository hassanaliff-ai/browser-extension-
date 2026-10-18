# Registration and approval flow — 18 October 2026

Extension **0.8.33** makes the distinction between creating an account and
signing in explicit. The login page has a prominent **Create a new account**
button. Switching preserves the username only; it does not carry a password
into a new account or create an account automatically after a failed login.

Failed sign-in guidance explains that a new user must register, finish
authenticator verification and receive approval. The response does not reveal
whether an arbitrary username exists.

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
  direct registration with username-only preservation, real registration and
  authenticator verification, confirmation after page reload, denial before
  approval, appearance in the head administrator's queue, approval through the
  real form, password/authenticator login after approval, and no page errors.
- 16 backend registration and hierarchical approval regression tests passed.

The browser test used generated credentials and `signup-example` in an isolated
database and browser profile. It did not create or approve Basel's live account,
choose his password or bypass authenticator enrollment. Basel must personally
complete registration against the current public API using the updated package.
