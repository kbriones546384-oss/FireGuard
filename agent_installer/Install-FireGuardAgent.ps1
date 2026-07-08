# FireGuard Agent Installer
# Run this ONCE on the second (target) laptop to set it up as a managed endpoint.
# It does NOT need to run as Administrator - only STARTING the agent afterwards does.

Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "      FireGuard Agent - One-Time Setup" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host ""

# ── 1. Check Python is installed ────────────────────────────────────────────
Write-Host "Checking for Python..." -ForegroundColor Yellow
$pythonOk = $false
try {
    $pyver = & python --version 2>&1
    if ($pyver -match "Python 3") { $pythonOk = $true }
} catch {}

if (-not $pythonOk) {
    Write-Host ""
    Write-Host "ERROR: Python 3 was not found on this machine." -ForegroundColor Red
    Write-Host "Install it from https://www.python.org/downloads/ first." -ForegroundColor Yellow
    Write-Host "IMPORTANT: check 'Add python.exe to PATH' during installation," -ForegroundColor Yellow
    Write-Host "then close this window and run this installer again." -ForegroundColor Yellow
    Write-Host ""
    Pause
    exit 1
}
Write-Host "Found: $pyver" -ForegroundColor Green
Write-Host ""

# ── 2. Ask for the two values shown on the server's /endpoints page ────────
Write-Host "Log in to the FireGuard dashboard as Administrator and open the" -ForegroundColor Cyan
Write-Host "'Endpoints' page. Copy the 'Server URL' and 'Global Registration Key'" -ForegroundColor Cyan
Write-Host "shown in the 'Endpoint Self-Registration' box, and paste them below." -ForegroundColor Cyan
Write-Host "This works whether the server is on the same Wi-Fi (e.g. http://192.168.1.10:5000)" -ForegroundColor Cyan
Write-Host "or hosted online, like Render (e.g. https://your-app.onrender.com)." -ForegroundColor Cyan
Write-Host ""

$ServerUrl = Read-Host "Server URL (e.g. https://your-app.onrender.com)"
while ([string]::IsNullOrWhiteSpace($ServerUrl)) {
    $ServerUrl = Read-Host "Server URL is required. Enter it now"
}
$ServerUrl = $ServerUrl.Trim().TrimEnd('/')

$RegKey = Read-Host "Global Registration Key"
while ([string]::IsNullOrWhiteSpace($RegKey)) {
    $RegKey = Read-Host "Registration key is required. Enter it now"
}
$RegKey = $RegKey.Trim()

# ── 3. Install required Python packages ─────────────────────────────────────
Write-Host ""
Write-Host "Installing required Python packages (psutil, requests)..." -ForegroundColor Yellow
python -m pip install --quiet --disable-pip-version-check psutil requests
Write-Host "Done." -ForegroundColor Green

# ── 4. Write agent_config.json next to this script ─────────────────────────
$InstallDir = $PSScriptRoot
$configObj = [ordered]@{
    server_url         = $ServerUrl
    registration_key   = $RegKey
    agent_token         = ""
    heartbeat_interval = 30
}
$configJson = $configObj | ConvertTo-Json
$configPath = Join-Path $InstallDir "agent_config.json"
$configJson | Set-Content -Path $configPath -Encoding UTF8
Write-Host "Configuration saved to $configPath" -ForegroundColor Green

# ── 5. Quick connectivity test (does not need Administrator) ───────────────
Write-Host ""
Write-Host "Testing connection to the server..." -ForegroundColor Yellow
try {
    $resp = Invoke-WebRequest -Uri "$ServerUrl/login" -UseBasicParsing -TimeoutSec 6
    Write-Host "Server reachable (HTTP $($resp.StatusCode)). Good." -ForegroundColor Green
} catch {
    Write-Host "Could not reach $ServerUrl from this machine." -ForegroundColor Red
    Write-Host "Check that: the FireGuard server is running and reachable, and that" -ForegroundColor Yellow
    Write-Host "the Server URL is correct (no typo, matches http/https, includes the" -ForegroundColor Yellow
    Write-Host "right port if self-hosted on a LAN)." -ForegroundColor Yellow
    Write-Host "  - Same-Wi-Fi setup: confirm both machines share a network and the" -ForegroundColor Yellow
    Write-Host "    server's Windows Firewall allows inbound connections on its port." -ForegroundColor Yellow
    Write-Host "  - Render/cloud setup: confirm this machine has internet access and" -ForegroundColor Yellow
    Write-Host "    the URL uses https:// (Render redirects http:// to https://, which" -ForegroundColor Yellow
    Write-Host "    can break the agent's registration request)." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "=============================================" -ForegroundColor Green
Write-Host " Setup complete!" -ForegroundColor Green
Write-Host "=============================================" -ForegroundColor Green
Write-Host ""
Write-Host "Next step: run 'Start-FireGuardAgent.ps1' (or right-click it and choose" -ForegroundColor Cyan
Write-Host "'Run with PowerShell') to launch the agent. It will ask for Administrator" -ForegroundColor Cyan
Write-Host "approval - that is required so it can apply firewall rules with netsh." -ForegroundColor Cyan
Write-Host ""
Pause
