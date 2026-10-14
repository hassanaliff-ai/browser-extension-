# Install ExtSecure on another device

The device installation ZIP is `ExtSecure Chrome Extension.zip` in the installed project folder. The LAN build points to the configured HTTPS gateway instead of the receiving computer's localhost. The ordinary source extension retains the local API origin for development.

On the host, keep the existing API running on loopback port 8765. The HTTPS gateway binds only to the configured LAN address on port 8766 and forwards API requests to that local service. PostgreSQL remains on its existing local connection. `Start ExtSecure.cmd` also restarts the gateway when `.private/lan/config.json` exists. The Windows firewall rule allows port 8766 from the configured subnet only; enabling that rule needs Windows administrator rights. No router port forwarding is configured.

On the receiving Windows computer, extract the ZIP. Install the included public **ExtSecure API Trust Certificate.cer** into the current user's **Trusted Root Certification Authorities** after confirming it came from the project owner. Restart Chrome, then open the API `/health` address listed in **INSTALL ON ANOTHER DEVICE.txt**. It must report TestAPI without a certificate warning. Load the extracted folder through `chrome://extensions` → Developer mode → Load unpacked.

Register or sign in with the receiving user's own account, complete account approval and 2FA as required, then open My account and Add this device. Approve its access where required. Click Connect Chrome extensions and allow Chrome's optional management permission. The administrator can then select the device in Inventory → Extensions.

The host computer must stay on, and the devices must be able to communicate over the same network. Guest Wi-Fi can isolate clients even when the API and firewall are configured correctly. If the host address changes, regenerate the gateway's server certificate and rebuild the ZIP. The included certificate is for this local deployment; a managed deployment should use an organization-approved HTTPS endpoint.

Only the public trust certificate is distributed. Private certificate keys, database passwords, browser tokens, `.env` and administrator credentials remain outside the ZIP and Git. The gateway rejects requests outside its configured subnet, unsupported routes/methods, and oversized request bodies. Forwarded client headers are generated from the actual connecting peer.
