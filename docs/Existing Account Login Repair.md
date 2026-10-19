# Existing-account login repair — 19 October 2026

Version 0.8.36 corrects failed-login guidance that previously suggested registration for every rejected password sign-in. That message could mislead an already approved user whose access had been disabled. The replacement keeps the user on Log in, advises use of the existing credentials and directs access-status questions to the head administrator. The English and Arabic messages do not reveal whether a submitted username exists.

The live diagnosis found the affected account disabled, with an account-disable event in the audit trail. At the project owner's request, its previously approved access was restored transactionally and a separate account_reenabled audit event was added. Existing password hash, encrypted authenticator secret and original approval were preserved. Old revoked sessions remain revoked. No 2FA bypass, new account or new authenticator enrollment was introduced. The authenticator configuration could be decrypted successfully and the account was not locked.

Verification: 251 JavaScript tests passed; 31 backend registration/authentication/audit tests passed; 11 real Chromium MV3 checks passed against generated accounts in an isolated database. Browser coverage includes rejection before approval, actual administrator approval, password/authenticator sign-in, incorrect-password guidance for an existing account and a second successful sign-in using the same password and authenticator. The live user's password and current authenticator code were not requested or used for those browser tests.

Install the current ZIP over the same existing unpacked-extension directory and click Reload at chrome://extensions. Choose Log in and use the existing username, password and current authenticator code. Registration is a one-time process. If access is deliberately disabled again, login must fail; a failed login never automatically reactivates an account.

The public API health check returned 200. Its current address is embedded in the distributed ZIP; the temporary tunnel can change and is not a permanent hosting address. GitHub uploads do not automatically replace unpacked installations on another computer.
