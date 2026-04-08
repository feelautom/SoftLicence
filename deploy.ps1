#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Build, transfer and deploy SoftLicence in one command.
.DESCRIPTION
    1. Git: push develop + merge main via coandploy
    2. Docker: build image locally (fast, no VPS RAM issues)
    3. SSH: transfer image to VPS via docker save/load
    4. Docker: trigger redeploy (restart with new image)
.EXAMPLE
    .\deploy.ps1                        # Full deploy
    .\deploy.ps1 -SkipBuild             # Git + transfer cached image + deploy
    .\deploy.ps1 -SkipGit               # Build + transfer + deploy (git already done)
    .\deploy.ps1 -Message "feat: xxx"   # Commit with message before deploying
#>

param(
    [string]$Message,
    [switch]$SkipBuild,
    [switch]$SkipGit,
    [switch]$IgnoreSshConfig
)

$ErrorActionPreference = "Stop"

# === CONFIG ===
$IMAGE = "softlicence-server"
$TAG = "latest"
$FULL_IMAGE = "${IMAGE}:${TAG}"
$REPO_ROOT = $PSScriptRoot
$VPS_HOST = "ubuntu@10.10.0.1"
$VPS_PORT = "2200"
$COMPOSE_PROJECT = "compose-compress-multi-byte-driver-xdlzxc"
$COMPOSE_FILE = "/etc/Docker/compose/$COMPOSE_PROJECT/code/docker-compose.yml"

# SSH/SCP helpers (scp uses -P uppercase, ssh uses -p lowercase)
if ($IgnoreSshConfig) {
    function Invoke-Ssh  { ssh  -p $VPS_PORT -F NUL $VPS_HOST $args }
    function Invoke-Scp  { scp  -P $VPS_PORT -F NUL @args }
    Write-Host "SSH config ignored (-IgnoreSshConfig)." -ForegroundColor DarkGray
} else {
    function Invoke-Ssh  { ssh  -p $VPS_PORT $VPS_HOST $args }
    function Invoke-Scp  { scp  -P $VPS_PORT @args }
}
# =============

Write-Host "`n=== SoftLicence - Local Build & Deploy ===" -ForegroundColor Cyan

# 1. Git: coandploy
if (-not $SkipGit) {
    Write-Host "`n[1/4] Git deploy (coandploy)..." -ForegroundColor Yellow
    if ($Message) {
        coandploy -Message $Message -Deploy
    } else {
        coandploy -Deploy -NoCommit
    }
    if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) { throw "coandploy failed" }
    Write-Host "Git deploy complete" -ForegroundColor Green
} else {
    Write-Host "`n[1/4] Skipping git (--SkipGit)" -ForegroundColor DarkGray
}

# 2. Docker build
if (-not $SkipBuild) {
    Write-Host "`n[2/4] Building Docker image..." -ForegroundColor Yellow
    $buildStart = Get-Date
    docker build `
        -f "$REPO_ROOT/src/SoftLicence.Server/Dockerfile" `
        -t $FULL_IMAGE `
        "$REPO_ROOT"

    if ($LASTEXITCODE -ne 0) { throw "Docker build failed" }
    $buildDuration = (Get-Date) - $buildStart
    Write-Host "Build completed in $([math]::Round($buildDuration.TotalSeconds))s" -ForegroundColor Green
} else {
    Write-Host "`n[2/4] Skipping build (cached image)" -ForegroundColor DarkGray
}

# 3. Transfer image to VPS via file + scp (PowerShell corrupts binary pipes)
Write-Host "`n[3/4] Transferring image to VPS..." -ForegroundColor Yellow
$transferStart = Get-Date
$tempFile = Join-Path ([System.IO.Path]::GetTempPath()) "softlicence-server-image.tar"

Write-Host "  Saving image to temp file..." -ForegroundColor DarkGray
docker save -o $tempFile $FULL_IMAGE
if ($LASTEXITCODE -ne 0) { throw "docker save failed" }
$sizeMB = [math]::Round((Get-Item $tempFile).Length / 1MB)
Write-Host "  Image saved: ${sizeMB}MB" -ForegroundColor DarkGray

Write-Host "  Uploading to VPS (scp progress below)..." -ForegroundColor DarkGray
Invoke-Scp $tempFile "${VPS_HOST}:/tmp/softlicence-server-image.tar"
if ($LASTEXITCODE -ne 0) { throw "scp transfer failed" }

Write-Host "  Loading image on VPS..." -ForegroundColor DarkGray
Invoke-Ssh "docker load -i /tmp/softlicence-server-image.tar && rm /tmp/softlicence-server-image.tar"
if ($LASTEXITCODE -ne 0) { throw "Remote docker load failed" }

Remove-Item $tempFile -ErrorAction SilentlyContinue
$transferDuration = (Get-Date) - $transferStart
Write-Host "Transfer completed in $([math]::Round($transferDuration.TotalSeconds))s" -ForegroundColor Green

# 4. Restart container via SSH (docker compose recreates with the new image)
Write-Host "`n[4/4] Restarting container on VPS..." -ForegroundColor Yellow
Invoke-Ssh "docker compose -p $COMPOSE_PROJECT -f $COMPOSE_FILE up -d --force-recreate server"
if ($LASTEXITCODE -ne 0) { throw "docker compose up failed" }
Write-Host "Container restarted" -ForegroundColor Green

Write-Host "`n=== Deploy complete! ===" -ForegroundColor Cyan
Write-Host "Image: $FULL_IMAGE`n" -ForegroundColor Green
