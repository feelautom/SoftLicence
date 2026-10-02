<#
.SYNOPSIS
Runs the selected compatibility regression against one owned, disposable PostgreSQL 17 container.
.DESCRIPTION
Uses an already installed image with no pull and a loopback-only port. No user volume is mounted.
The caller must approve the exact campaign and own the worktree outputs. Container deletion is
unconditional in finally; logs and TRX remain in the one canonical task evidence directory.
Client source is read only. No application is installed, deployed or contacted.
#>
param(
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-z0-9-]+$')][string]$Campaign,
    [string]$Filter = 'FullyQualifiedName~Compat991_',
    [Parameter(Mandatory=$true)][string]$ConsumerRepository,
    [int]$Port = 55992
)
$ErrorActionPreference = 'Stop'
$repo = (git -C $PSScriptRoot rev-parse --show-toplevel).Trim()
$evidence = Join-Path $repo 'artifacts/tkt-000991-runtime-compat'
if (-not (Test-Path -LiteralPath $evidence -PathType Container)) { throw 'Create and approve the evidence directory before running.' }
$container = 'softlicence-991-compat-' + $Campaign
$oldPostgres = $env:SOFTLICENCE_RUNTIME_TEST_POSTGRES
$oldConsumers = $env:SOFTLICENCE_RUNTIME_CONSUMER_REPOSITORY
$oldEvidence = $env:SOFTLICENCE_RUNTIME_COMPAT_EVIDENCE
$created = $false
$runExit = 1
try {
    $existing = docker ps -a --filter "name=^/$container`$" --format '{{.Names}}'
    if ($existing) { throw 'An existing campaign container must be investigated, never reused or removed automatically.' }
    docker run -d --pull never --name $container --label 'codex.ticket=TKT-000991-compat' --memory 1g --tmpfs /var/lib/postgresql/data:rw,size=768m -p "127.0.0.1:${Port}:5432" -e POSTGRES_PASSWORD=compat991-synthetic -e POSTGRES_DB=runtime_compat postgres:17-alpine | Out-File (Join-Path $evidence "$Campaign-container.log")
    if ($LASTEXITCODE -ne 0) { throw 'Could not create owned PostgreSQL container.' }
    $created = $true
    $ready = $false
    for ($attempt=0; $attempt -lt 30; $attempt++) {
        docker exec $container pg_isready -U postgres -d runtime_compat *> $null
        if ($LASTEXITCODE -eq 0) { $ready=$true; break }
        Start-Sleep -Milliseconds 500
    }
    if (-not $ready) { throw 'Disposable PostgreSQL did not become ready.' }
    $env:SOFTLICENCE_RUNTIME_TEST_POSTGRES = "Host=127.0.0.1;Port=$Port;Database=runtime_compat;Username=postgres;Password=compat991-synthetic"
    $env:SOFTLICENCE_RUNTIME_CONSUMER_REPOSITORY = $ConsumerRepository
    $env:SOFTLICENCE_RUNTIME_COMPAT_EVIDENCE = $evidence
    dotnet test (Join-Path $repo 'tests/SoftLicence.Tests/SoftLicence.Tests.csproj') -c Release --no-build --no-restore --filter $Filter --logger "trx;LogFileName=$Campaign.trx" --results-directory $evidence *> (Join-Path $evidence "$Campaign.log")
    $runExit = $LASTEXITCODE
    Get-Content -LiteralPath (Join-Path $evidence "$Campaign.log") -Tail 24
    docker stats $container --no-stream --format '{{.Name}} {{.MemUsage}} {{.BlockIO}}' | Out-File (Join-Path $evidence "$Campaign-resources.log")
}
finally {
    if ($created) {
        docker logs $container *> (Join-Path $evidence "$Campaign-postgres.log")
        docker rm -f $container | Out-File (Join-Path $evidence "$Campaign-cleanup.log")
        if ($LASTEXITCODE -ne 0) { throw "Owned container cleanup failed: $container" }
    }
    $env:SOFTLICENCE_RUNTIME_TEST_POSTGRES = $oldPostgres
    $env:SOFTLICENCE_RUNTIME_CONSUMER_REPOSITORY = $oldConsumers
    $env:SOFTLICENCE_RUNTIME_COMPAT_EVIDENCE = $oldEvidence
}
exit $runExit
