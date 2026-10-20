# Current TestAPI connection

The distributed ExtSecure Chrome Extension.zip and the installed workspace extension use the public TestAPI endpoint:

https://joan-designated-explosion-result.trycloudflare.com

Verified on 20 October 2026: local and public /health return service TestAPI; the account-registration endpoint is reachable and rejects an invalid empty request with 422. No test registration was added to the live database.

On another computer, replace files in the existing unpacked-extension folder with this ZIP and click Reload at chrome://extensions. Connection diagnostics must show the HTTPS address above, rather than that computer's localhost or a different server. Register once, complete authenticator verification and receive account approval; then log in with that same account. Registered accounts have no expiry.

The source extension directory retains localhost for development; use the supplied ZIP for another device. The public endpoint is a temporary tunnel and can change after recreation. The host and tunnel must remain running. GitHub uploads do not update unpacked installations on other computers automatically.
