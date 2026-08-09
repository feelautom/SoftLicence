$ErrorActionPreference = "Stop"

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$environmentHelper = Join-Path $repositoryRoot "scripts\Build.Environment.ps1"
$guard = Join-Path $repositoryRoot "scripts\Test-TrackedSecrets.ps1"
$workflowPath = Join-Path $repositoryRoot ".github\workflows\publish.yml"
$failures = 0

function Assert-True {
    param([bool]$Condition, [string]$Name)
    if (-not $Condition) {
        $script:failures++
        Write-Error "$Name failed." -ErrorAction Continue
    }
}

function Assert-ThrowsContaining {
    param([scriptblock]$Action, [string]$ExpectedText, [string]$Name)
    try {
        & $Action
        $script:failures++
        Write-Error "$Name failed. Expected an exception." -ErrorAction Continue
    }
    catch {
        Assert-True `
            -Condition ($_.Exception.Message.IndexOf($ExpectedText, [StringComparison]::OrdinalIgnoreCase) -ge 0) `
            -Name $Name
    }
}

. $environmentHelper

$environmentName = "AdminSettings__ApiSecret"
$previousValue = [Environment]::GetEnvironmentVariable($environmentName, [EnvironmentVariableTarget]::Process)
try {
    [Environment]::SetEnvironmentVariable($environmentName, $null, [EnvironmentVariableTarget]::Process)
    Assert-ThrowsContaining `
        -Action { Assert-SoftLicenceRunEnvironment } `
        -ExpectedText "must be set in the process environment" `
        -Name "Missing admin secret is rejected"

    $syntheticValue = "  synthetic-value-with-mixed-Case-and-unicode-é  "
    [Environment]::SetEnvironmentVariable($environmentName, $syntheticValue, [EnvironmentVariableTarget]::Process)
    Assert-SoftLicenceRunEnvironment
    $observedValue = [Environment]::GetEnvironmentVariable($environmentName, [EnvironmentVariableTarget]::Process)
    Assert-True -Condition ($observedValue -ceq $syntheticValue) -Name "Admin secret is preserved exactly"
}
finally {
    [Environment]::SetEnvironmentVariable($environmentName, $previousValue, [EnvironmentVariableTarget]::Process)
}

$temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) "SoftLicenceSecretGuard-$([guid]::NewGuid().ToString('N'))"
try {
    New-Item -ItemType Directory -Path $temporaryRoot -Force | Out-Null
    & git -C $temporaryRoot init --quiet
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to initialize the temporary Git repository."
    }

    $adminKey = "AdminSettings__Api" + "Secret"
    $mcpKey = "SOFTLICENCE_ADMIN" + "_SECRET"
    $safePath = Join-Path $temporaryRoot "safe.env"
    [IO.File]::WriteAllText($safePath, "$adminKey=`${ADMIN_API_SECRET}`n$mcpKey=CHANGE_ME_ADMIN_SECRET`n")
    & git -C $temporaryRoot add safe.env
    & $guard -RepositoryRoot $temporaryRoot | Out-Null

    $syntheticLiteral = "synthetic-secret-that-must-never-be-printed"
    $unsafePath = Join-Path $temporaryRoot "unsafe.ps1"
    [IO.File]::WriteAllText($unsafePath, '$env:' + $mcpKey + ' = "' + $syntheticLiteral + '"')
    & git -C $temporaryRoot add unsafe.ps1

    try {
        & $guard -RepositoryRoot $temporaryRoot | Out-Null
        $failures++
        Write-Error "Literal tracked admin secret detection failed." -ErrorAction Continue
    }
    catch {
        Assert-True -Condition ($_.Exception.Message -match 'unsafe\.ps1:1') -Name "Finding reports safe location"
        Assert-True -Condition ($_.Exception.Message -notmatch [regex]::Escape($syntheticLiteral)) -Name "Finding redacts secret value"
    }
}
finally {
    if (Test-Path -LiteralPath $temporaryRoot) {
        Remove-Item -LiteralPath $temporaryRoot -Recurse -Force
    }
}

$workflow = Get-Content -Raw -LiteralPath $workflowPath
$guardSource = Get-Content -Raw -LiteralPath $guard
Assert-True `
    -Condition ($guardSource -match 'catch\s+\[System\.Text\.DecoderFallbackException\]') `
    -Name "Decoder fallback exception is fully qualified for Windows PowerShell 5.1"
Assert-True `
    -Condition ($guardSource -match '\.IndexOf\("SECRET",\s*\[StringComparison\]::Ordinal\)\s+-ge\s+0') `
    -Name "Documentation placeholder comparison remains ordinal on Windows PowerShell 5.1"
Assert-True `
    -Condition ($guardSource -notmatch '[^\u0000-\u007F]') `
    -Name "Tracked secret guard source remains ASCII-compatible with Windows PowerShell 5.1"
Assert-True `
    -Condition ($workflow -match '(?m)^\s*run:\s*\.\/scripts\/Test-TrackedSecrets\.ps1\s*$') `
    -Name "CI runs tracked administrator secret guard"

& $guard -RepositoryRoot $repositoryRoot | Out-Null

if ($failures -gt 0) {
    throw "$failures administrator secret guard test(s) failed."
}

Write-Output "Administrator secret guard tests passed on PowerShell $($PSVersionTable.PSVersion)."
