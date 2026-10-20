# Gmail with Sign in with Google

The administrator authorizes the local ExtSecure email service in Google’s browser page. Gmail passwords are never collected by ExtSecure. This is sender authorization, not a replacement for ExtSecure user sign-in or administrator approval.

## One-time Google setup

1. Open https://console.cloud.google.com/ and create or select the ExtSecure project.
2. Enable the Gmail API in APIs & Services / Library.
3. Configure Google Auth Platform branding, audience and consent. For personal testing, choose External and add the sender account as a test user. Request only `openid`, `email`, and `https://www.googleapis.com/auth/gmail.send`.
4. Under Clients, create a **Desktop app** OAuth client named ExtSecure mail. Download its JSON into a private local folder, never the extension or repository.
5. Open `scripts/configure_google_mail.py` using the project Python runtime. Choose the JSON file and enter the administrator recipient.
6. Click **Sign in with Google**. Choose the sender account and enter any credentials only on Google’s HTTPS page. Approve email sending. The sender display name is ExtSecure.
7. After successful setup, restart TestAPI to load `EMAIL_PROVIDER=gmail_oauth`. Separately verify a labelled test alert or report in the recipient mailbox before treating email as operational.

Without a real OAuth client and consent, the setup cannot connect. Google may restrict unverified applications and require verification for broader use. External apps in Testing can have refresh tokens expire after seven days when requesting Gmail scope; production authorization is needed for durable use. Revocation or account policy changes can also require sign-in again. There is no promise of permanent authorization or inbox delivery.

## Security and behavior

The local service uses loopback callback on 127.0.0.1, random state, and PKCE S256. Network requests use fixed Google HTTPS endpoints with bounded timeouts and no redirects. The callback listener expires after five minutes and suppresses authorization-code logs. Mail scope is send-only; ExtSecure does not ask to read or delete mailbox messages. OpenID email scope verifies which sender consented.

The refresh token and OAuth client settings are encrypted in `.private/gmail-oauth/authorization.enc` using a domain-separated key derived from the server account encryption key, or its existing high-entropy TOTP server secret when no separate encryption key is configured. Preserve that server key privately; loss requires reconnection. Neither credentials nor tokens enter the extension, database events, GitHub, or exported reports. The setup sends no email and switches providers only after authorization succeeds. If authorization fails, there is no automatic fallback to a Gmail password. Existing scan logging and blocking do not depend on mail success.

Each administrator receives a separate message. A successful Gmail API response means Google accepted the message, not that it reached the inbox. Sending requests are not automatically retried after ambiguous failures. Revoke access in your Google Account to disconnect; remove private authorization locally to remove the stored grant. This feature uses the existing alert/report delivery paths and does not change their schedules.

Official references:
- https://developers.google.com/identity/protocols/oauth2/native-app
- https://developers.google.com/workspace/gmail/api/auth/scopes
- https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages.send
- https://developers.google.com/identity/protocols/oauth2#expiration
