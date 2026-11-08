param(
    [string]$Component = ""
)

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Defensive Listener Lab Launcher" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$pythonVersion = (python --version 2>&1)
if ($?) {
    Write-Host "Python found: $pythonVersion" -ForegroundColor Green
} else {
    Write-Host "Python not found. Install Python 3.10+" -ForegroundColor Red
    exit 1
}

if (!(Test-Path "venv")) {
    Write-Host "Creating virtual environment..." -ForegroundColor Yellow
    python -m venv venv
}

& ".\venv\Scripts\Activate.ps1"

if (!(Test-Path ".installed")) {
    Write-Host "Installing dependencies..." -ForegroundColor Yellow
    pip install -r requirements.txt
    New-Item -ItemType File ".installed" | Out-Null
}

if (!(Test-Path ".env")) {
    Write-Host "Copying .env.example to .env..." -ForegroundColor Yellow
    Copy-Item ".env.example" ".env"
}

Write-Host ""
Write-Host "1. Lab server"
Write-Host "2. Heartbeat simulator"
Write-Host "3. Listener CLI"
Write-Host "4. Local audit upload"
Write-Host ""

if ($Component -eq "") {
    $choice = Read-Host "Select option (1-4)"
} else {
    $choice = $Component
}

switch ($choice) {
    "1" {
        Write-Host "Starting lab server..." -ForegroundColor Green
        Set-Location server
        python main.py
    }
    "2" {
        Write-Host "Starting heartbeat simulator..." -ForegroundColor Green
        Set-Location agent
        python beacon.py --server http://127.0.0.1:8000 --listener listener_1
    }
    "3" {
        Write-Host "Starting listener CLI..." -ForegroundColor Green
        Set-Location server
        python listener_cli.py
    }
    "4" {
        Write-Host "Starting local audit upload workflow..." -ForegroundColor Green
        & ".\run_local_audit.ps1"
    }
    default {
        Write-Host "Invalid option" -ForegroundColor Red
        exit 1
    }
}
