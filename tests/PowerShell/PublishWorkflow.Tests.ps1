$ErrorActionPreference = "Stop"

$workflowPath = Join-Path $PSScriptRoot "..\..\.github\workflows\publish.yml"
$workflow = Get-Content -Raw -LiteralPath $workflowPath
$failures = 0

function Assert-True {
    param(
        [Parameter(Mandatory = $true)]
        [bool]$Condition,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    if (-not $Condition) {
        $script:failures++
        Write-Error "$Name failed." -ErrorAction Continue
    }
}

function Get-RunBlocks {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string[]]$Lines
    )

    $blocks = [System.Collections.Generic.List[string]]::new()

    for ($index = 0; $index -lt $Lines.Count; $index++) {
        if ($Lines[$index] -notmatch '^(?<indent>\s*)run:\s*\|\s*$') {
            continue
        }

        $runIndent = $Matches.indent.Length
        $body = [System.Collections.Generic.List[string]]::new()

        for ($bodyIndex = $index + 1; $bodyIndex -lt $Lines.Count; $bodyIndex++) {
            $line = $Lines[$bodyIndex]
            if (-not [string]::IsNullOrWhiteSpace($line)) {
                $lineIndent = $line.Length - $line.TrimStart().Length
                if ($lineIndent -le $runIndent) {
                    break
                }
            }

            $body.Add($line)
        }

        $blocks.Add(($body -join "`n"))
    }

    return $blocks
}

$runBlocks = @(Get-RunBlocks -Lines ($workflow -split "`r?`n"))
Assert-True -Condition ($runBlocks.Count -gt 0) -Name "Workflow run blocks discovered"

$actionExpressionInRun = @($runBlocks | Where-Object { $_ -match '\$\{\{' })
Assert-True -Condition ($actionExpressionInRun.Count -eq 0) -Name "No GitHub Actions expression inside run blocks"

foreach ($mapping in @(
    @{ Name = "EVENT_NAME"; Context = "github.event_name" },
    @{ Name = "REF_NAME"; Context = "github.ref_name" },
    @{ Name = "RELEASE_TAG"; Context = "github.event.release.tag_name" },
    @{ Name = "REPOSITORY"; Context = "github.repository" },
    @{ Name = "SDK_VERSION"; Context = "steps.sdk_version.outputs.version" },
    @{ Name = "NUGET_API_KEY"; Context = "secrets.NUGET_API_KEY" }
)) {
    $envPattern = '(?m)^\s*' + [regex]::Escape($mapping.Name) + ':\s*\$\{\{\s*' +
        [regex]::Escape($mapping.Context) + '\s*\}\}\s*$'
    $readPattern = '\$env:' + [regex]::Escape($mapping.Name) + '\b'

    Assert-True -Condition ($workflow -match $envPattern) -Name "$($mapping.Name) is mapped through env"
    Assert-True -Condition (($runBlocks -join "`n") -match $readPattern) -Name "$($mapping.Name) is read from env"
}

$versionBlock = @($runBlocks | Where-Object { $_ -match 'Release event did not provide a tag name\.' })
Assert-True -Condition ($versionBlock.Count -eq 1) -Name "SDK version step discovered"

$syntheticPayload = 'v1.2.3"; $script:publishWorkflowInjected = $true; "'
$script:publishWorkflowInjected = $false
$previousEnvironment = @{
    EVENT_NAME = $env:EVENT_NAME
    REF_NAME = $env:REF_NAME
    RELEASE_TAG = $env:RELEASE_TAG
    GITHUB_OUTPUT = $env:GITHUB_OUTPUT
}

try {
    $releaseTag = $env:RELEASE_TAG
    $env:GITHUB_OUTPUT = "NUL"

    $env:EVENT_NAME = "release"
    $env:REF_NAME = $syntheticPayload
    $env:RELEASE_TAG = $syntheticPayload

    $releaseTag = $env:RELEASE_TAG
    Assert-True -Condition ($releaseTag -ceq $syntheticPayload) -Name "Environment value is preserved exactly"

    try {
        [scriptblock]::Create($versionBlock[0]).Invoke() | Out-Null
        $failures++
        Write-Error "Malicious release tag failed. Expected validation to reject the tag." -ErrorAction Continue
    }
    catch {
        Assert-True `
            -Condition ($_.Exception.Message -match 'must use vX\.Y\.Z format') `
            -Name "Malicious release tag is rejected by validation"
    }

    Assert-True -Condition (-not $script:publishWorkflowInjected) -Name "Environment value is not evaluated as PowerShell"

    $env:RELEASE_TAG = "v1.2.3-beta.1"
    try {
        [scriptblock]::Create($versionBlock[0]).Invoke() | Out-Null
    }
    catch {
        $failures++
        Write-Error "Valid release tag failed: $($_.Exception.Message)" -ErrorAction Continue
    }

    $env:EVENT_NAME = "push"
    $env:REF_NAME = "main"
    $env:RELEASE_TAG = ""
    try {
        [scriptblock]::Create($versionBlock[0]).Invoke() | Out-Null
    }
    catch {
        $failures++
        Write-Error "Non-release version lookup failed: $($_.Exception.Message)" -ErrorAction Continue
    }
}
finally {
    foreach ($name in $previousEnvironment.Keys) {
        [Environment]::SetEnvironmentVariable($name, $previousEnvironment[$name], "Process")
    }
}

if ($failures -gt 0) {
    throw "$failures publish workflow security test(s) failed."
}

Write-Output "Publish workflow security tests passed on PowerShell $($PSVersionTable.PSVersion)."
