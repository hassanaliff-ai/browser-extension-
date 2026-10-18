# TestAPI automatic startup and recovery

The Windows task **ExtSecure API Supervisor** starts a hidden Python supervisor at boot and user logon. A repeating trigger and Task Scheduler restart settings recover a stopped supervisor. A single-instance lock prevents duplicate API supervisors.

The installed machine-startup task uses the ordinary Windows account with S4U batch logon and limited privileges. Administrator elevation is required to register startup, but the project does not run as SYSTEM or with administrator runtime privileges. No Windows account password is stored by these scripts. The Python environment, repository and local configuration must remain available on disk.

The supervisor checks the loopback TestAPI every 20 seconds. A missing worker is started; three failed checks of a running worker trigger a verified restart. Healthy providers are preserved. The public gateway and Cloudflare process are checked against their recorded identities before replacement. A transient public DNS/network failure does not rotate an otherwise live tunnel.

While enabled, the supervisor requests that Windows remain awake; it does not keep the screen on. Shutdown, forced sleep, lid/power policy, loss of internet and hardware failure can still interrupt access. PostgreSQL already runs as an automatic Windows service. The API continues to use its existing database and authentication.

## Starting and stopping

- `scripts/install_api_autostart.ps1 -Pythonw <absolute-venv-pythonw-path> -Machine` registers boot startup from an elevated administrator session. Without elevation, the installer attempts batch startup and otherwise installs a logon-only task, reporting its actual mode.
- `scripts/start_api_autostart.ps1` enables supervision again without replacing the registered startup mode.
- `scripts/stop_api_autostart.ps1` asks the running supervisor to stop its own API and public connection, waits for confirmation, then disables its scheduled task. PostgreSQL and stored records remain intact. Do not forcibly terminate the supervisor to request a complete shutdown.

Runtime configuration, health status and logs are under `.private/api-supervisor` and `.private/public-api`; credentials and these private files are excluded from Git.

## Temporary public address

Cloudflare Quick Tunnel addresses are temporary. The supervisor keeps the existing live tunnel rather than rotating it on a failed network probe. If the tunnel process is lost or the computer restarts, a replacement can receive a different address. The supervisor rebuilds **ExtSecure Chrome Extension.zip** with the reachable address and refreshes configured workspace copies.

The supervisor also replaces a tunnel whose current-generation log explicitly reports `Unauthorized: Tunnel not found`, even if its process is still running. Each new tunnel records its log offset so an old tunnel's rejection cannot trigger repeated replacement. Missing logs and ordinary connection/DNS failures do not count as terminal rejection.

The extension on the host continues using localhost. Extensions installed on other devices must receive the rebuilt package when its temporary address changes. This setup cannot provide a permanent public URL or remotely update an already-installed unpacked extension. A named tunnel/domain or permanent hosted API is required for that.

## Validation

Recovery-policy tests cover disabled configuration, duplicate-safe supervision policy, missing API startup, delayed restart after consecutive failures, preservation of live tunnels during DNS failure, package refresh and operator stop ownership. A live recovery check stops only the verified TestAPI worker, confirms automatic replacement, tests public HTTPS and authentication boundaries, and compares existing database record counts. Boot and sign-out settings are inspected without rebooting or signing the user out.

On 15 October 2026, all 11 recovery-policy tests passed. A live stop/recovery test replaced the API worker in 15.4 seconds, restored public HTTPS, retained authentication requirements, and preserved 16 scans, 16 security events, 5 devices, 8 extension records and 16 scan ownership records. No separate manual API start was used during that test.

On 18 October 2026, 15 recovery-policy tests passed, including terminal tunnel rejection, separation of current and previous log generations, transient connection failures and missing-log handling.
