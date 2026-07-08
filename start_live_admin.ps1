$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)

if (-not $isAdmin) {
    Write-Host ""
    Write-Host "FireGuard Live Mode requires Administrator privileges." -ForegroundColor Red
    Write-Host ""
    Write-Host "Attempting auto-elevation..." -ForegroundColor Yellow

    try {
        Start-Process powershell.exe -Verb RunAs -ArgumentList @(
            "-NoExit",
            "-ExecutionPolicy", "Bypass",
            "-Command", "Set-Location 'C:\IT21'; Get-Process python -ErrorAction SilentlyContinue | Stop-Process -Force; `$env:FIREGUARD_APPLY_FIREWALL='1'; python app.py"
        ) -ErrorAction Stop
        Write-Host "Launched elevated window. Check for a new PowerShell window." -ForegroundColor Green
    } catch {
        Write-Host "" -ForegroundColor DarkYellow
        Write-Host "Auto-elevation failed. Please do this manually:" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  1. Press Windows key, type: PowerShell" -ForegroundColor Cyan
        Write-Host "  2. Right-click > 'Run as administrator'" -ForegroundColor Cyan
        Write-Host "  3. In the Admin window, run:" -ForegroundColor Cyan
        Write-Host "       Set-Location C:\IT21" -ForegroundColor White
        Write-Host "       Get-Process python -ErrorAction SilentlyContinue | Stop-Process -Force" -ForegroundColor White
        Write-Host "       `$env:FIREGUARD_APPLY_FIREWALL='1'; python app.py" -ForegroundColor White
    }
    exit 1
}

# Already running as Administrator — kill any old Python servers first
Write-Host ""
Write-Host "Stopping any existing FireGuard server instances..." -ForegroundColor Yellow
Get-Process python -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Milliseconds 800

Set-Location -Path $PSScriptRoot
$env:FIREGUARD_APPLY_FIREWALL = "1"
Write-Host ""
Write-Host "FireGuard starting in LIVE MODE as Administrator..." -ForegroundColor Green
Write-Host "Windows Firewall rules will be applied automatically." -ForegroundColor Cyan
Write-Host ""
python app.py
