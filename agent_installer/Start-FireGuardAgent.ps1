# Launches the FireGuard Agent as Administrator (needed so it can apply
# firewall rules via netsh). Run Install-FireGuardAgent.ps1 first, once.

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)

if (-not $isAdmin) {
    Write-Host ""
    Write-Host "The FireGuard Agent needs Administrator privileges to apply firewall rules." -ForegroundColor Red
    Write-Host "Attempting auto-elevation..." -ForegroundColor Yellow

    try {
        Start-Process powershell.exe -Verb RunAs -ArgumentList @(
            "-NoExit",
            "-ExecutionPolicy", "Bypass",
            "-Command", "Set-Location '$PSScriptRoot'; python agent.py"
        ) -ErrorAction Stop
        Write-Host "Launched elevated window. Check for a new PowerShell window." -ForegroundColor Green
    } catch {
        Write-Host ""
        Write-Host "Auto-elevation failed. Please do this manually:" -ForegroundColor Yellow
        Write-Host "  1. Press the Windows key, type: PowerShell" -ForegroundColor Cyan
        Write-Host "  2. Right-click it -> 'Run as administrator'" -ForegroundColor Cyan
        Write-Host "  3. In the Admin window, run:" -ForegroundColor Cyan
        Write-Host "       Set-Location '$PSScriptRoot'" -ForegroundColor White
        Write-Host "       python agent.py" -ForegroundColor White
    }
    exit 1
}

Set-Location -Path $PSScriptRoot
Write-Host ""
Write-Host "Starting FireGuard Agent as Administrator..." -ForegroundColor Green
Write-Host "Leave this window open during the demo. Press Ctrl+C to stop." -ForegroundColor Cyan
Write-Host ""
python agent.py
