$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "..\..\scripts\Update-LocalMcp.ps1")

$failures = 0

function Assert-Equal {
    param([object]$Expected, [object]$Actual, [string]$Name)
    if ($Expected -ne $Actual) {
        $script:failures++
        Write-Error "$Name failed. Expected '$Expected', observed '$Actual'." -ErrorAction Continue
    }
}

function Assert-True {
    param([bool]$Value, [string]$Name)
    if (-not $Value) {
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
        if ($_.Exception.Message.IndexOf($ExpectedText, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) {
            $script:failures++
            Write-Error "$Name failed. Unexpected message '$($_.Exception.Message)'." -ErrorAction Continue
        }
    }
}

$testRoot = Join-Path ([System.IO.Path]::GetTempPath()) "SoftLicenceMcpUpdaterTests-$([guid]::NewGuid().ToString('N'))"
try {
    $sourceDirectory = Join-Path $testRoot "source"
    $installDirectory = Join-Path $testRoot "SoftLicence.Mcp"
    New-Item -ItemType Directory -Path $sourceDirectory, $installDirectory -Force | Out-Null

    $source = Join-Path $sourceDirectory "SoftLicence.Mcp.exe"
    $target = Join-Path $installDirectory "SoftLicence.Mcp.exe"
    [System.IO.File]::WriteAllBytes($source, [byte[]](1..64))
    [System.IO.File]::WriteAllBytes($target, [byte[]](65..96))
    [System.IO.File]::WriteAllText((Join-Path $installDirectory "SoftLicence.Mcp.pdb"), "stale")
    [System.IO.File]::WriteAllText((Join-Path $installDirectory "SoftLicence.Mcp.exe.old-test"), "stale")
    New-Item -ItemType Directory -Path (Join-Path $installDirectory "runtimes") | Out-Null
    [System.IO.File]::WriteAllText((Join-Path $installDirectory "runtimes\stale.txt"), "stale")

    $result = Install-McpArtifact `
        -SourceExecutable $source `
        -InstallDirectory $installDirectory `
        -ProcessName "SoftLicence.Mcp.Test.Process.That.Does.Not.Exist" `
        -MaxReplaceAttempts 2 `
        -RetryDelayMilliseconds 1 `
        -SkipStandaloneSmoke

    Assert-Equal -Expected (Get-FileHash $source).Hash -Actual $result.Sha256 -Name "Installed hash"
    Assert-Equal -Expected 1 -Actual @(Get-ChildItem -LiteralPath $installDirectory -Force).Count -Name "Clean install file count"
    Assert-Equal -Expected "SoftLicence.Mcp.exe" -Actual (Get-ChildItem -LiteralPath $installDirectory -Force).Name -Name "Clean install filename"
    Assert-True -Value $result.ReloadRequired -Name "Reload required flag"

    $lockedSource = Join-Path $sourceDirectory "SoftLicence.Mcp.locked.exe"
    [System.IO.File]::WriteAllBytes($lockedSource, [byte[]](97..120))
    $oldHash = (Get-FileHash $target).Hash
    $lock = [System.IO.File]::Open($target, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
    try {
        Assert-ThrowsContaining `
            -Action {
                Install-McpArtifact `
                    -SourceExecutable $lockedSource `
                    -InstallDirectory $installDirectory `
                    -ProcessName "SoftLicence.Mcp.Test.Process.That.Does.Not.Exist" `
                    -MaxReplaceAttempts 2 `
                    -RetryDelayMilliseconds 1 `
                    -SkipStandaloneSmoke | Out-Null
            } `
            -ExpectedText "remained locked after 2" `
            -Name "Bounded locked-file failure"
    }
    finally {
        $lock.Dispose()
    }

    Assert-Equal -Expected $oldHash -Actual (Get-FileHash $target).Hash -Name "Locked target remains unchanged"
    Assert-Equal -Expected 0 -Actual @(Get-ChildItem -LiteralPath $installDirectory -Filter "*.new-*" -Force).Count -Name "Prepared artifact cleanup after failure"

    $filesystemRoot = [System.IO.Path]::GetPathRoot($testRoot)
    Assert-ThrowsContaining `
        -Action { Assert-InstallDirectory -InstallDirectory $filesystemRoot | Out-Null } `
        -ExpectedText "filesystem root" `
        -Name "Filesystem root rejection"

    Assert-ThrowsContaining `
        -Action { Assert-InstallDirectory -InstallDirectory (Join-Path $testRoot "wrong-name") | Out-Null } `
        -ExpectedText "must end with 'SoftLicence.Mcp'" `
        -Name "Install directory name rejection"
}
finally {
    if (Test-Path -LiteralPath $testRoot) {
        Remove-Item -LiteralPath $testRoot -Recurse -Force
    }
}

if ($failures -gt 0) {
    throw "$failures Update-LocalMcp test(s) failed."
}

Write-Output "Update-LocalMcp PowerShell tests passed on PowerShell $($PSVersionTable.PSVersion)."
