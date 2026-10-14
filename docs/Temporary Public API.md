# Temporary public API

The device-installation ZIP can be built with a temporary Cloudflare Quick Tunnel HTTPS origin. It works across networks and uses a publicly trusted certificate, so users do not need to install the LAN trust certificate. This is an interim testing deployment until Basel supplies the permanent API.

The tunnel forwards to a restricted gateway on loopback port 8768, which forwards permitted API routes to TestAPI on loopback port 8765. PostgreSQL is never published. Account approval, authenticator verification, role permissions and device approval remain enforced by the existing backend. Public visibility does not grant access to protected records.

The gateway accepts only its local connector in public mode, sanitizes forwarded client addresses, restricts methods/routes, caps request size and limits sign-in/registration starts to ten per minute per client and other API requests to 120 per minute. Public HTTPS terminates at Cloudflare before traffic travels through the tunnel, so the deployment uses Cloudflare as a transport provider. Do not upload sensitive Alba data to this temporary testing deployment without the organization's authorization.

Start with `scripts/start_public_api.py` using the existing project Python environment. `Start ExtSecure.cmd` checks an already configured public tunnel. Stop with `scripts/stop_public_api.py`; it verifies process identities and leaves the local API and PostgreSQL running. After stopping, starting again generates a new address and rebuilds the ZIP; redistribute that ZIP. The source extension retains its development localhost address, while the distributed ZIP uses the active public address.

The laptop, local API and tunnel must remain running. Quick Tunnels provide a temporary address, have no uptime guarantee and allow up to 200 concurrent in-flight requests. They are for testing, not permanent public production hosting. See [Cloudflare Quick Tunnels](https://developers.cloudflare.com/tunnel/get-started/quick-tunnels/).

The tunnel executable is downloaded from Cloudflare's official GitHub release and checked against that release's SHA-256 digest. Binaries, process state, logs, credentials and private keys remain under the ignored `.private` folder. The ZIP includes installation instructions and extension files only.
