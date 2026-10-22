# Run the SecureScope primary API with the existing ExtSecure services.
# The root project's private .env must supply VT_API_KEY. If the monitoring
# settings are configured there, its database-backed routes are also mounted.
$projectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$pythonPath = Join-Path $projectRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $pythonPath)) {
    throw 'Install the root requirements in .venv before starting the combined server.'
}
$env:TLDEXTRACT_CACHE = Join-Path $env:TEMP 'securescope-tld-cache'
Push-Location -LiteralPath $projectRoot
try {
    & $pythonPath -m uvicorn prototypes.securescope.backend.primary:create_app --factory --host 127.0.0.1 --port 8001
} finally {
    Pop-Location
}
