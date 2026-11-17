# ReadyHai single-binary installer for Windows PowerShell
[CmdletBinding()]
param(
    [string]$InstallPath = "$env:LOCALAPPDATA\Programs\readyhai"
)

$ErrorActionPreference = "Stop"

Write-Host "ReadyHai Single-Binary Installer for Windows" -ForegroundColor Cyan

# Ensure target program directory exists
if (-not (Test-Path $InstallPath)) {
    New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null
}

$ConfigDir = "$env:APPDATA\readyhai"
if (-not (Test-Path $ConfigDir)) {
    New-Item -ItemType Directory -Path $ConfigDir -Force | Out-Null
}

$DataDir = "$env:LOCALAPPDATA\readyhai\data"
if (-not (Test-Path $DataDir)) {
    New-Item -ItemType Directory -Path $DataDir -Force | Out-Null
}

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$TargetExe = Join-Path $InstallPath "readyhai.exe"

# If built locally
$LocalExe = Join-Path $ScriptDir "target\release\readyhai.exe"
if (Test-Path $LocalExe) {
    Write-Host "Installing locally built binary from target\release\readyhai.exe..." -ForegroundColor Green
    Copy-Item -Path $LocalExe -Destination $TargetExe -Force
} else {
    # Check if cargo is available to build locally
    if (Get-Command cargo -ErrorAction SilentlyContinue) {
        Write-Host "Building readyhai from local source..." -ForegroundColor Green
        cargo build --release
        Copy-Item -Path $LocalExe -Destination $TargetExe -Force
    } else {
        Write-Host "Downloading release binary from GitHub..." -ForegroundColor Yellow
        # In a published repo, download prebuilt release zip:
        # Invoke-WebRequest -Uri "https://github.com/deziss/readyhai/releases/latest/download/readyhai-x86_64-pc-windows-msvc.zip" -OutFile "$InstallPath\readyhai.zip"
        # Expand-Archive -Path "$InstallPath\readyhai.zip" -DestinationPath $InstallPath -Force
        # Remove-Item "$InstallPath\readyhai.zip"
    }
}

# Generate default scope.toml if missing
$ScopeFile = Join-Path $ConfigDir "scope.toml"
if (-not (Test-Path $ScopeFile)) {
    $ExampleScope = Join-Path $ScriptDir "scope.example.toml"
    if (Test-Path $ExampleScope) {
        Copy-Item -Path $ExampleScope -Destination $ScopeFile -Force
        Write-Host "Created default scope configuration: $ScopeFile" -ForegroundColor Green
    }
}

# Generate default .env if missing
$EnvFile = Join-Path $ConfigDir ".env"
if (-not (Test-Path $EnvFile)) {
    $Bytes = New-Object Byte[] 24
    (New-Object Security.Cryptography.RNGCryptoServiceProvider).GetBytes($Bytes)
    $Token = -join ($Bytes | ForEach-Object { "{0:x2}" -f $_ })

    $EnvContent = @"
# ReadyHai Standalone Configuration
READYHAI_TOKEN=$Token
READYHAI_DATA=$DataDir
READYHAI_SCOPE=$ScopeFile
READYHAI_PORT=8080
"@
    Set-Content -Path $EnvFile -Value $EnvContent
    Write-Host "Generated default environment configuration: $EnvFile" -ForegroundColor Green
}

# Update User PATH if not already added
$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($UserPath -notlike "*$InstallPath*") {
    Write-Host "Adding $InstallPath to User PATH..." -ForegroundColor Cyan
    [Environment]::SetEnvironmentVariable("Path", "$UserPath;$InstallPath", "User")
    $env:Path = "$env:Path;$InstallPath"
}

Write-Host "Installation successful!" -ForegroundColor Green
Write-Host "Run 'readyhai.exe --help' or 'readyhai.exe doctor' to get started." -ForegroundColor White
