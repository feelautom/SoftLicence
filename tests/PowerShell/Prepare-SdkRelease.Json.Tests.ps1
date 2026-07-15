$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "..\..\scripts\Prepare-SdkRelease.Json.ps1")

$failures = 0

function Assert-Equal {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Expected,

        [Parameter(Mandatory = $true)]
        [object]$Actual,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    if ($Expected -ne $Actual) {
        $script:failures++
        Write-Error "$Name failed. Expected '$Expected', observed '$Actual'." -ErrorAction Continue
    }
}

function Assert-ThrowsSafeMessage {
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [object]$Json,

        [Parameter(Mandatory = $true)]
        [string]$ExpectedMessage,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [string]$SensitiveMarker
    )

    try {
        @(ConvertFrom-ReleaseJsonList -Json $Json -SourceName "Test source") | Out-Null
        $script:failures++
        Write-Error "$Name failed. Expected an exception." -ErrorAction Continue
    }
    catch {
        Assert-Equal -Expected $ExpectedMessage -Actual $_.Exception.Message -Name "$Name message"

        if (-not [string]::IsNullOrEmpty($SensitiveMarker) -and $_.Exception.Message.Contains($SensitiveMarker)) {
            $script:failures++
            Write-Error "$Name leaked the input payload marker." -ErrorAction Continue
        }
    }
}

$empty = @(ConvertFrom-ReleaseJsonList -Json "[]" -SourceName "Test source")
Assert-Equal -Expected 0 -Actual $empty.Count -Name "Empty array"

$emptyWithWhitespace = @(ConvertFrom-ReleaseJsonList -Json "[ `r`n ]" -SourceName "Test source")
Assert-Equal -Expected 0 -Actual $emptyWithWhitespace.Count -Name "Empty array with whitespace"

$single = @(ConvertFrom-ReleaseJsonList `
    -Json '[{"number":1,"title":"One","url":"https://example.invalid/1"}]' `
    -SourceName "Test source")
Assert-Equal -Expected 1 -Actual $single.Count -Name "Single-item array count"
Assert-Equal -Expected 1 -Actual $single[0].number -Name "Single-item array value"

$multiple = @(ConvertFrom-ReleaseJsonList `
    -Json '[{"number":1},{"number":2}]' `
    -SourceName "Test source")
Assert-Equal -Expected 2 -Actual $multiple.Count -Name "Multiple-item array count"
Assert-Equal -Expected "1,2" -Actual (($multiple | ForEach-Object { $_.number }) -join ",") -Name "Multiple-item array values"

$bareObject = @(ConvertFrom-ReleaseJsonList `
    -Json '{"number":7}' `
    -SourceName "Test source")
Assert-Equal -Expected 1 -Actual $bareObject.Count -Name "Bare object count"
Assert-Equal -Expected 7 -Actual $bareObject[0].number -Name "Bare object value"

Assert-ThrowsSafeMessage `
    -Json $null `
    -ExpectedMessage "Test source returned an empty response." `
    -Name "Null process output"

Assert-ThrowsSafeMessage `
    -Json "   " `
    -ExpectedMessage "Test source returned an empty response." `
    -Name "Whitespace process output"

Assert-ThrowsSafeMessage `
    -Json "null" `
    -ExpectedMessage "Test source returned a null JSON response." `
    -Name "JSON null"

Assert-ThrowsSafeMessage `
    -Json '{"sensitive-payload-marker":' `
    -ExpectedMessage "Test source returned invalid JSON." `
    -Name "Invalid JSON" `
    -SensitiveMarker "sensitive-payload-marker"

if ($failures -gt 0) {
    throw "$failures Prepare-SdkRelease JSON parsing test(s) failed."
}

Write-Output "Prepare-SdkRelease JSON parsing tests passed on PowerShell $($PSVersionTable.PSVersion)."
