# setup.ps1 — one-command bootstrap for AppSec Pipeline Sentinel on Windows
# Run with: powershell -ExecutionPolicy Bypass -File setup.ps1

Write-Host "Setting up AppSec Pipeline Sentinel..." -ForegroundColor Cyan

$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) {
    $python = Get-Command python3 -ErrorAction SilentlyContinue
}
if (-not $python) {
    Write-Host "Error: Python is required but not found on PATH." -ForegroundColor Red
    exit 1
}

& $python.Source -m pip install -r requirements.txt --quiet

Write-Host ""
Write-Host "Setup complete!" -ForegroundColor Green
Write-Host ""

$ffuf = Get-Command ffuf -ErrorAction SilentlyContinue
if ($ffuf) {
    Write-Host "ffuf detected - route discovery will use real fuzzing" -ForegroundColor Green
} else {
    Write-Host "ffuf not found - route discovery will use a slower built-in fallback." -ForegroundColor Yellow
    Write-Host "  Install ffuf: go install github.com/ffuf/ffuf/v2@latest" -ForegroundColor Yellow
    Write-Host "  (or download a release binary from https://github.com/ffuf/ffuf/releases and add it to PATH)" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Try it out:"
Write-Host "  python sentinel.py status"
Write-Host "  python sentinel.py demo"
Write-Host "  python sentinel.py scan scanner/test_fixtures --type all"
Write-Host "  python sentinel.py discover http://127.0.0.1:5050"
Write-Host "  python sentinel.py vulns --severity critical"
Write-Host "  python sentinel.py dashboard --type full"
Write-Host "  python sentinel.py automate --dry-run"
Write-Host ""
Write-Host "Docker:"
Write-Host "  docker build -t appsec-sentinel ."
Write-Host "  docker run --rm appsec-sentinel status"
