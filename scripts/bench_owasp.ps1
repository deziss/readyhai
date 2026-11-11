<#
.SYNOPSIS
Opt-in local benchmark harness against real OWASP training apps (Juice Shop / VAmPI / crAPI)
or ReadyHai's deterministic security-deep + whitebox-exploit eval suites.
NOT invoked by default CI/unit tests.

.EXAMPLE
.\scripts\bench_owasp.ps1 -Suite
.\scripts\bench_owasp.ps1 -Target http://127.0.0.1:3000 -Profile deep -AllowNonprod
#>
param(
    [switch]$Suite,
    [string]$Target = "",
    [ValidateSet("standard", "deep")][string]$Profile = "deep",
    [string]$Spec = "",
    [string]$Scope = "",
    [string]$RepoPath = "",
    [string]$DiffBase = "HEAD",
    [string]$OutDir = (Join-Path ([System.IO.Path]::GetTempPath()) "readyhai-owasp-bench"),
    [switch]$AllowNonprod
)

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

if ($Suite -or [string]::IsNullOrWhiteSpace($Target)) {
    Write-Host "[bench_owasp] Running security-deep + whitebox-exploit eval suites -> $OutDir"
    cargo run --quiet -- eval --suite security-deep --k 2 --out (Join-Path $OutDir "security-deep")
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    cargo run --quiet -- eval --suite whitebox-exploit --k 2 --out (Join-Path $OutDir "whitebox-exploit")
    exit $LASTEXITCODE
}

if (-not $AllowNonprod -and $env:READYHAI_ALLOW_NONPROD -ne "1") {
    Write-Error "Refusing active security benchmark without -AllowNonprod or READYHAI_ALLOW_NONPROD=1."
    exit 2
}

$maxSteps = if ($Profile -eq "standard") { "20" } else { "50" }
if ([string]::IsNullOrWhiteSpace($env:READYHAI_VERIFY_K)) {
    $env:READYHAI_VERIFY_K = "2"
}

$argsList = @("run", "--quiet", "--", "agent", $Target, "--max-steps", $maxSteps)
if (-not [string]::IsNullOrWhiteSpace($Spec)) {
    $argsList += @("--spec", $Spec)
}
if (-not [string]::IsNullOrWhiteSpace($Scope)) {
    $argsList += @("--scope", $Scope)
}
if (-not [string]::IsNullOrWhiteSpace($RepoPath)) {
    $argsList += @("--repo", $RepoPath, "--diff-base", $DiffBase)
}

$logPath = Join-Path $OutDir "live-agent.log"
Write-Host "[bench_owasp] Launching ReadyHai agent (profile=$Profile, max_steps=$maxSteps) against $Target -> $logPath"
& cargo @argsList | Tee-Object -FilePath $logPath
exit $LASTEXITCODE
exit $LASTEXITCODE

