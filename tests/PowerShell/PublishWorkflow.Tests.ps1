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

# --- SDK assembly signature guard (TKT-001479) ---------------------------------------------
# An SDK whose assembly is not signed with the release certificate must never reach nuget.org.

. (Join-Path $PSScriptRoot "..\..\scripts\SdkSigning.ps1")

$pushBlock = @($runBlocks | Where-Object { $_ -match 'dotnet nuget push' })
Assert-True -Condition ($pushBlock.Count -eq 1) -Name "Push step discovered"
if ($pushBlock.Count -eq 1) {
    $guardIndex = $pushBlock[0].IndexOf('Assert-SdkPackageSignature', [System.StringComparison]::Ordinal)
    $pushIndex = $pushBlock[0].IndexOf('dotnet nuget push', [System.StringComparison]::Ordinal)
    Assert-True -Condition ($guardIndex -ge 0 -and $guardIndex -lt $pushIndex) -Name "Signature guard runs before the NuGet push"
    Assert-True -Condition ($pushBlock[0] -match '\./scripts/SdkSigning\.ps1') -Name "Push step loads the shared signing contract"
}

Assert-True `
    -Condition ($workflow -match "(?s)- name: Pack SDK\s.*?if: github\.event_name != 'release'") `
    -Name "A release never publishes a package built on the hosted runner"
Assert-True `
    -Condition (($runBlocks -join "`n") -match 'gh release download \$env:RELEASE_TAG') `
    -Name "A release publishes the package attached to it"
Assert-True -Condition ($workflow -match '(?m)^\s*GH_TOKEN:\s*\$\{\{\s*secrets\.GITHUB_TOKEN\s*\}\}\s*$') -Name "GH_TOKEN is mapped through env"

# Prepare-SdkRelease.ps1 stays in the private repository: the public mirror only carries the
# scripts the workflow needs, so these checks apply where the file exists.
$prepareScriptPath = Join-Path $PSScriptRoot "..\..\scripts\Prepare-SdkRelease.ps1"
$prepareScript = $null
$signStepIndex = -1
if (Test-Path -LiteralPath $prepareScriptPath -PathType Leaf) {
    $prepareScript = Get-Content -Raw -LiteralPath $prepareScriptPath
    $signStepIndex = $prepareScript.IndexOf('Invoke-SdkPackageAssemblySigning -PackagePath', [System.StringComparison]::Ordinal)
    $localGuardIndex = $prepareScript.IndexOf('Assert-SdkPackageSignature -PackagePath', [System.StringComparison]::Ordinal)
    Assert-True -Condition ($signStepIndex -ge 0 -and $localGuardIndex -gt $signStepIndex) -Name "Local preparation signs then verifies the SDK assembly"
}

# Builds a throwaway package holding the given entries.
function New-SdkPackageFixture {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Entries
    )

    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $path = Join-Path ([IO.Path]::GetTempPath()) ("softlicence-sdk-fixture-" + [Guid]::NewGuid().ToString("N") + ".nupkg")
    $archive = [IO.Compression.ZipFile]::Open($path, [IO.Compression.ZipArchiveMode]::Create)
    try {
        foreach ($name in $Entries.Keys) {
            $stream = $archive.CreateEntry($name).Open()
            try {
                $bytes = [byte[]]$Entries[$name]
                $stream.Write($bytes, 0, $bytes.Length)
            }
            finally {
                $stream.Dispose()
            }
        }
    }
    finally {
        $archive.Dispose()
    }

    return $path
}

# Runs the guard and returns its failure message, or $null when the package is accepted.
function Get-SdkSignatureGuardFailure {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PackagePath,

        [string]$ExpectedThumbprint
    )

    try {
        if ([string]::IsNullOrEmpty($ExpectedThumbprint)) {
            Assert-SdkPackageSignature -PackagePath $PackagePath | Out-Null
        }
        else {
            Assert-SdkPackageSignature -PackagePath $PackagePath -ExpectedThumbprint $ExpectedThumbprint | Out-Null
        }

        return $null
    }
    catch {
        return $_.Exception.Message
    }
}

# dotnet.exe carries an embedded Microsoft Authenticode signature on every supported machine,
# which gives a validly signed image that is not signed by the release certificate.
$signedImagePath = (Get-Command dotnet -ErrorAction Stop).Source
$signedImage = Get-AuthenticodeSignature -LiteralPath $signedImagePath
Assert-True -Condition ($signedImage.Status -eq "Valid") -Name "Signed fixture image is validly signed"

$assemblyEntry = "lib/netstandard2.0/SoftLicence.SDK.dll"
$fixtures = @()
try {
    $unsignedPackage = New-SdkPackageFixture -Entries @{ $assemblyEntry = [Text.Encoding]::ASCII.GetBytes("unsigned sdk") }
    $emptyPackage = New-SdkPackageFixture -Entries @{ "LICENSE" = [Text.Encoding]::ASCII.GetBytes("license") }
    $foreignPackage = New-SdkPackageFixture -Entries @{ $assemblyEntry = [IO.File]::ReadAllBytes($signedImagePath) }
    $fixtures = @($unsignedPackage, $emptyPackage, $foreignPackage)

    Assert-True `
        -Condition ((Get-SdkSignatureGuardFailure -PackagePath $unsignedPackage) -match 'no valid Authenticode signature') `
        -Name "Unsigned SDK assembly is refused"
    Assert-True `
        -Condition ((Get-SdkSignatureGuardFailure -PackagePath $emptyPackage) -match 'does not contain') `
        -Name "Package without the SDK assembly is refused"
    Assert-True `
        -Condition ((Get-SdkSignatureGuardFailure -PackagePath $foreignPackage) -match 'unexpected certificate') `
        -Name "SDK assembly signed with another certificate is refused"
    Assert-True `
        -Condition ($null -eq (Get-SdkSignatureGuardFailure -PackagePath $foreignPackage -ExpectedThumbprint $signedImage.SignerCertificate.Thumbprint.ToLowerInvariant())) `
        -Name "SDK assembly signed with the expected certificate is accepted"
    Assert-True `
        -Condition ((Get-SdkSigningCertificateThumbprint) -cmatch '^[0-9A-F]{40}$') `
        -Name "Release certificate thumbprint is a canonical SHA-1 thumbprint"
}
finally {
    foreach ($fixture in $fixtures) {
        Remove-Item -LiteralPath $fixture -Force -ErrorAction SilentlyContinue
    }
}

# --- Package identity, single assembly and timestamp (independent review of TKT-001479) ---------

# Builds a throwaway package from an ordered list of (name, bytes) pairs. A list, unlike a
# hashtable, can hold two entries whose names are equal or differ only by case.
function New-SdkPackageFixtureFromList {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$EntryList
    )

    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $path = Join-Path ([IO.Path]::GetTempPath()) ("softlicence-sdk-fixture-" + [Guid]::NewGuid().ToString("N") + ".nupkg")
    $archive = [IO.Compression.ZipFile]::Open($path, [IO.Compression.ZipArchiveMode]::Create)
    try {
        foreach ($pair in $EntryList) {
            $stream = $archive.CreateEntry([string]$pair[0]).Open()
            try {
                $bytes = [byte[]]$pair[1]
                $stream.Write($bytes, 0, $bytes.Length)
            }
            finally {
                $stream.Dispose()
            }
        }
    }
    finally {
        $archive.Dispose()
    }

    return $path
}

# Returns the failure message of a guard, or $null when it accepts.
function Get-GuardFailure {
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]$Guard
    )

    try {
        & $Guard | Out-Null
        return $null
    }
    catch {
        return $_.Exception.Message
    }
}

# Builds the bytes of a .nuspec declaring the given identity.
function New-NuspecBytes {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Id,

        [Parameter(Mandatory = $true)]
        [string]$Version
    )

    $xml = '<?xml version="1.0" encoding="utf-8"?><package xmlns="http://schemas.microsoft.com/packaging/2012/06/nuspec.xsd">' +
        "<metadata><id>$Id</id><version>$Version</version></metadata></package>"
    return [Text.Encoding]::UTF8.GetBytes($xml)
}

$signedBytes = [IO.File]::ReadAllBytes($signedImagePath)
$foreignThumbprint = $signedImage.SignerCertificate.Thumbprint
$identityFixtures = @()
try {
    $goodPackage = New-SdkPackageFixtureFromList -EntryList @(
        @("SoftLicence.SDK.nuspec", (New-NuspecBytes -Id "SoftLicence.SDK" -Version "2.0.0")),
        @($assemblyEntry, $signedBytes))
    $renamedPackage = New-SdkPackageFixtureFromList -EntryList @(
        @("SoftLicence.SDK.nuspec", (New-NuspecBytes -Id "SoftLicence.SDK" -Version "1.1.14")),
        @($assemblyEntry, $signedBytes))
    $otherIdPackage = New-SdkPackageFixtureFromList -EntryList @(
        @("SoftLicence.SDK.nuspec", (New-NuspecBytes -Id "Other.Package" -Version "2.0.0")),
        @($assemblyEntry, $signedBytes))
    $twoNuspecPackage = New-SdkPackageFixtureFromList -EntryList @(
        @("SoftLicence.SDK.nuspec", (New-NuspecBytes -Id "SoftLicence.SDK" -Version "2.0.0")),
        @("Other.nuspec", (New-NuspecBytes -Id "SoftLicence.SDK" -Version "1.1.14")))
    $noNuspecPackage = New-SdkPackageFixtureFromList -EntryList @(, @($assemblyEntry, $signedBytes))
    $duplicatePackage = New-SdkPackageFixtureFromList -EntryList @(
        @($assemblyEntry, $signedBytes),
        @($assemblyEntry, [Text.Encoding]::ASCII.GetBytes("unsigned twin")))
    $caseTwinPackage = New-SdkPackageFixtureFromList -EntryList @(
        @($assemblyEntry, $signedBytes),
        @("lib/netstandard2.0/softlicence.sdk.dll", [Text.Encoding]::ASCII.GetBytes("unsigned twin")))
    $slashTwinPackage = New-SdkPackageFixtureFromList -EntryList @(
        @($assemblyEntry, $signedBytes),
        @("lib\netstandard2.0\SoftLicence.SDK.dll", [Text.Encoding]::ASCII.GetBytes("unsigned twin")))
    $identityFixtures = @($goodPackage, $renamedPackage, $otherIdPackage, $twoNuspecPackage, $noNuspecPackage,
        $duplicatePackage, $caseTwinPackage, $slashTwinPackage)

    Assert-True `
        -Condition ($null -eq (Get-GuardFailure { Assert-SdkPackageIdentity -PackagePath $goodPackage -ExpectedVersion "2.0.0" })) `
        -Name "Package declaring the expected identity is accepted"
    Assert-True `
        -Condition ((Get-GuardFailure { Assert-SdkPackageIdentity -PackagePath $renamedPackage -ExpectedVersion "2.0.0" }) -match "declares version '1\.1\.14', expected '2\.0\.0'") `
        -Name "Renamed package of another version is refused"
    Assert-True `
        -Condition ((Get-GuardFailure { Assert-SdkPackageIdentity -PackagePath $otherIdPackage -ExpectedVersion "2.0.0" }) -match "declares the package id 'Other\.Package'") `
        -Name "Package with another id is refused"
    Assert-True `
        -Condition ((Get-GuardFailure { Assert-SdkPackageIdentity -PackagePath $twoNuspecPackage -ExpectedVersion "2.0.0" }) -match 'exactly one SoftLicence\.SDK\.nuspec') `
        -Name "Package with two nuspec files is refused"
    Assert-True `
        -Condition ((Get-GuardFailure { Assert-SdkPackageIdentity -PackagePath $noNuspecPackage -ExpectedVersion "2.0.0" }) -match 'exactly one SoftLicence\.SDK\.nuspec') `
        -Name "Package without a nuspec is refused"
    Assert-True `
        -Condition ((Get-GuardFailure { Assert-SdkPackageIdentity -PackagePath $goodPackage -ExpectedVersion "2.0.0`n" }) -match 'declares version') `
        -Name "Version comparison is exact"

    # A hand-made .nuspec could show this guard one identity and NuGet another. Each of these
    # declares 2.0.0 to a namespace-blind reader while NuGet would read something else.
    $nuspecNamespace = 'http://schemas.microsoft.com/packaging/2012/06/nuspec.xsd'
    $ambiguousNuspecs = [ordered]@{
        "Foreign-namespace version before the real one is refused" =
            "<package xmlns=`"$nuspecNamespace`" xmlns:x=`"urn:other`"><metadata><id>SoftLicence.SDK</id><x:version>2.0.0</x:version><version>1.1.14</version></metadata></package>"
        "Foreign-namespace id before the real one is refused" =
            "<package xmlns=`"$nuspecNamespace`" xmlns:x=`"urn:other`"><metadata><x:id>SoftLicence.SDK</x:id><id>Other.Package</id><version>2.0.0</version></metadata></package>"
        "Repeated version element is refused" =
            "<package xmlns=`"$nuspecNamespace`"><metadata><id>SoftLicence.SDK</id><version>2.0.0</version><version>1.1.14</version></metadata></package>"
        "Version element differing by case is refused" =
            "<package xmlns=`"$nuspecNamespace`"><metadata><id>SoftLicence.SDK</id><Version>2.0.0</Version><version>1.1.14</version></metadata></package>"
        "Second metadata element is refused" =
            "<package xmlns=`"$nuspecNamespace`"><metadata><id>SoftLicence.SDK</id><version>2.0.0</version></metadata><metadata><id>SoftLicence.SDK</id><version>1.1.14</version></metadata></package>"
        "Identity only in a foreign namespace is refused" =
            "<package xmlns=`"$nuspecNamespace`" xmlns:x=`"urn:other`"><metadata><x:id>SoftLicence.SDK</x:id><x:version>2.0.0</x:version></metadata></package>"
        "Root element other than package is refused" =
            "<bundle xmlns=`"$nuspecNamespace`"><metadata><id>SoftLicence.SDK</id><version>2.0.0</version></metadata></bundle>"
        "Document type declaration is refused" =
            "<!DOCTYPE package [<!ENTITY v `"2.0.0`">]><package xmlns=`"$nuspecNamespace`"><metadata><id>SoftLicence.SDK</id><version>&v;</version></metadata></package>"
    }
    foreach ($caseName in $ambiguousNuspecs.Keys) {
        $ambiguousPackage = New-SdkPackageFixtureFromList -EntryList @(
            @("SoftLicence.SDK.nuspec", [Text.Encoding]::UTF8.GetBytes($ambiguousNuspecs[$caseName])),
            @($assemblyEntry, $signedBytes))
        $identityFixtures += $ambiguousPackage
        Assert-True `
            -Condition ($null -ne (Get-GuardFailure { Assert-SdkPackageIdentity -PackagePath $ambiguousPackage -ExpectedVersion "2.0.0" })) `
            -Name $caseName
    }

    # A real package, as produced by dotnet pack, has no namespace prefix and stays accepted.
    $unprefixedPackage = New-SdkPackageFixtureFromList -EntryList @(
        @("SoftLicence.SDK.nuspec", [Text.Encoding]::UTF8.GetBytes('<package><metadata><version>2.0.0</version><id>SoftLicence.SDK</id></metadata></package>')),
        @($assemblyEntry, $signedBytes))
    $identityFixtures += $unprefixedPackage
    Assert-True `
        -Condition ($null -eq (Get-GuardFailure { Assert-SdkPackageIdentity -PackagePath $unprefixedPackage -ExpectedVersion "2.0.0" })) `
        -Name "Nuspec without a namespace and with reordered elements is accepted"

    foreach ($twin in @(
        @{ Name = "Duplicate assembly entry is refused"; Path = $duplicatePackage },
        @{ Name = "Assembly twin differing by case is refused"; Path = $caseTwinPackage },
        @{ Name = "Assembly twin differing by slash direction is refused"; Path = $slashTwinPackage }
    )) {
        $twinPath = $twin.Path
        Assert-True `
            -Condition ((Get-GuardFailure { Assert-SdkPackageSignature -PackagePath $twinPath -ExpectedThumbprint $foreignThumbprint }) -match 'exactly one') `
            -Name $twin.Name
    }

    Assert-True `
        -Condition ($null -eq (Get-GuardFailure { Assert-SdkPackageSignature -PackagePath $goodPackage -ExpectedThumbprint $foreignThumbprint })) `
        -Name "Single signed and timestamped assembly is accepted"
}
finally {
    foreach ($fixture in $identityFixtures) {
        Remove-Item -LiteralPath $fixture -Force -ErrorAction SilentlyContinue
    }
}

$signer = [pscustomobject]@{ Thumbprint = "ABCDEF" }
Assert-True `
    -Condition ($null -eq (Get-SdkSignatureFailure -ExpectedThumbprint "abcdef" -Signature ([pscustomobject]@{ Status = "Valid"; SignerCertificate = $signer; TimeStamperCertificate = $signer }))) `
    -Name "Valid timestamped signature from the expected certificate is acceptable"
Assert-True `
    -Condition ((Get-SdkSignatureFailure -ExpectedThumbprint "abcdef" -Signature ([pscustomobject]@{ Status = "Valid"; SignerCertificate = $signer; TimeStamperCertificate = $null })) -match 'without a timestamp') `
    -Name "Signature without a timestamp is refused"
Assert-True `
    -Condition ((Get-SdkSignatureFailure -ExpectedThumbprint "abcdef" -Signature ([pscustomobject]@{ Status = "NotSigned"; SignerCertificate = $null; TimeStamperCertificate = $null })) -match 'no valid Authenticode signature') `
    -Name "Unsigned image is refused before any other check"
Assert-True `
    -Condition ((Get-SdkSignatureFailure -ExpectedThumbprint "abcdef" -Signature $null) -match 'no readable') `
    -Name "Missing signature object is refused"
Assert-True -Condition ($null -ne $signedImage.TimeStamperCertificate) -Name "Signed fixture image is timestamped"

# The workflow must keep these guards on the publishing path.
if ($pushBlock.Count -eq 1) {
    $identityIndex = $pushBlock[0].IndexOf('Assert-SdkPackageIdentity', [System.StringComparison]::Ordinal)
    $pushCommandIndex = $pushBlock[0].IndexOf('dotnet nuget push', [System.StringComparison]::Ordinal)
    Assert-True -Condition ($identityIndex -ge 0 -and $identityIndex -lt $pushCommandIndex) -Name "Identity guard runs before the NuGet push"
    Assert-True -Condition (-not ($pushBlock[0] -match '--skip-duplicate')) -Name "A duplicate version fails the push instead of being skipped"
}
Assert-True `
    -Condition ($workflow -match '(?m)^permissions:\s*\r?\n\s+contents: read\s*\r?\n\s+pull-requests: read\s*$') `
    -Name "Workflow token permissions are declared read-only"
Assert-True `
    -Condition ($workflow -match '(?m)^\s*run:\s*\./tests/PowerShell/PublishWorkflow\.Tests\.ps1\s*$') `
    -Name "Workflow runs the publish guard tests"
if ($null -ne $prepareScript) {
    $localIdentityIndex = $prepareScript.IndexOf('Assert-SdkPackageIdentity -PackagePath', [System.StringComparison]::Ordinal)
    Assert-True -Condition ($localIdentityIndex -gt $signStepIndex) -Name "Local preparation verifies the package identity after signing"
}

# The public mirror is rebuilt without the private scripts directory. Every script the workflow
# loads must be on the synchroniser's allowlist, or the public workflow cannot run.
$syncScriptPath = Join-Path $PSScriptRoot "..\..\scripts\Sync-PublicRepo.ps1"
if (Test-Path -LiteralPath $syncScriptPath -PathType Leaf) {
    $syncScript = Get-Content -Raw -LiteralPath $syncScriptPath
    $workflowScripts = @([regex]::Matches($workflow, '\./scripts/([A-Za-z0-9.-]+\.ps1)') | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
    Assert-True -Condition ($workflowScripts.Count -ge 2) -Name "Workflow scripts discovered"
    foreach ($workflowScript in $workflowScripts) {
        Assert-True `
            -Condition ($syncScript.Contains('"' + $workflowScript + '"')) `
            -Name "Workflow script $workflowScript is published to the public mirror"
    }
}

# --- NuGet author signature (TKT-004207) -------------------------------------------------------
# nuget.org refuses any package of the FeelAutom account without an author signature made with its
# registered certificate (HTTP 400 on the SDK 3.0.0 push). The preparation signs the package, and
# the workflow accepts the .signature.p7s entry only when that signature is the expected one.

Add-Type -AssemblyName System.Security.Cryptography.Pkcs

# DER of the CommitmentTypeIndication attribute value naming proof-of-origin (author) or
# proof-of-receipt (repository), exactly as dotnet nuget sign writes it.
$authorCommitment = [byte[]](0x30, 0x0D, 0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x06, 0x01)
$repositoryCommitment = [byte[]](0x30, 0x0D, 0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x06, 0x02)

# Creates a throwaway self-signed RSA certificate with its private key, never stored anywhere.
function New-TestSigningCertificate {
    param([Parameter(Mandatory = $true)][string]$Name)

    $rsa = [Security.Cryptography.RSA]::Create(2048)
    $request = [Security.Cryptography.X509Certificates.CertificateRequest]::new(
        "CN=$Name", $rsa, [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.RSASignaturePadding]::Pkcs1)
    return $request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddDays(-1), [DateTimeOffset]::UtcNow.AddDays(30))
}

# Returns the uppercase SHA-256 fingerprint of a certificate, the form NuGet uses.
function Get-TestCertificateFingerprint {
    param([Parameter(Mandatory = $true)]$Certificate)

    return [BitConverter]::ToString([Security.Cryptography.SHA256]::HashData($Certificate.RawData)).Replace('-', '')
}

# Builds the bytes of a .signature.p7s shaped like a NuGet author signature. The switches remove or
# replace one element at a time so each structural refusal of the guard can be proven.
function New-TestAuthorSignatureBytes {
    param(
        [Parameter(Mandatory = $true)]$Certificate,
        [byte[]]$Commitment = $authorCommitment,
        [switch]$WithoutCommitment,
        [switch]$WithoutTimestamp,
        [switch]$TimestampNotTstInfo,
        [switch]$TwoSigners
    )

    $cms = [Security.Cryptography.Pkcs.SignedCms]::new([Security.Cryptography.Pkcs.ContentInfo]::new([byte[]](1, 2, 3)), $false)
    $signer = [Security.Cryptography.Pkcs.CmsSigner]::new($Certificate)
    $signer.DigestAlgorithm = [Security.Cryptography.Oid]::new('2.16.840.1.101.3.4.2.1')
    if (-not $WithoutCommitment) {
        $signer.SignedAttributes.Add([Security.Cryptography.AsnEncodedData]::new('1.2.840.113549.1.9.16.2.16', $Commitment)) | Out-Null
    }
    $cms.ComputeSignature($signer)
    if ($TwoSigners) {
        $cms.ComputeSignature($signer)
    }
    if (-not $WithoutTimestamp) {
        $tokenType = if ($TimestampNotTstInfo) { '1.2.840.113549.1.7.1' } else { '1.2.840.113549.1.9.16.1.4' }
        $token = [Security.Cryptography.Pkcs.SignedCms]::new(
            [Security.Cryptography.Pkcs.ContentInfo]::new([Security.Cryptography.Oid]::new($tokenType), [byte[]](4, 5, 6)), $false)
        $token.ComputeSignature([Security.Cryptography.Pkcs.CmsSigner]::new($Certificate))
        $cms.SignerInfos[0].AddUnsignedAttribute([Security.Cryptography.AsnEncodedData]::new('1.2.840.113549.1.9.16.2.14', $token.Encode()))
    }
    return $cms.Encode()
}

$authorCertificate = New-TestSigningCertificate -Name "SoftLicence author test"
$otherCertificate = New-TestSigningCertificate -Name "Other publisher test"
$authorFingerprint = Get-TestCertificateFingerprint -Certificate $authorCertificate

Assert-True `
    -Condition ((Get-SdkNuGetSigningCertificateFingerprint) -ceq 'A1515DCDB473469BC226F0DDF94DAD06E6EDF7B21C0732444BF3B34DE3B0CD33') `
    -Name "Registered NuGet certificate fingerprint is the SHA-256 of the release certificate"
Assert-True `
    -Condition ($null -eq (Get-SdkAuthorSignatureFailure -SignatureBytes (New-TestAuthorSignatureBytes -Certificate $authorCertificate) -ExpectedFingerprint $authorFingerprint)) `
    -Name "Timestamped author signature of the expected certificate is acceptable"
Assert-True `
    -Condition ($null -eq (Get-SdkAuthorSignatureFailure -SignatureBytes (New-TestAuthorSignatureBytes -Certificate $authorCertificate) -ExpectedFingerprint $authorFingerprint.ToLowerInvariant())) `
    -Name "Fingerprint comparison ignores hexadecimal case"
foreach ($case in @(
    @{ Name = "Author signature of another certificate is refused"; Bytes = (New-TestAuthorSignatureBytes -Certificate $otherCertificate); Pattern = 'unexpected certificate' },
    @{ Name = "Signature without commitment type is refused"; Bytes = (New-TestAuthorSignatureBytes -Certificate $authorCertificate -WithoutCommitment); Pattern = 'not an author signature' },
    @{ Name = "Repository signature is refused"; Bytes = (New-TestAuthorSignatureBytes -Certificate $authorCertificate -Commitment $repositoryCommitment); Pattern = 'not an author signature' },
    @{ Name = "Author signature without timestamp is refused"; Bytes = (New-TestAuthorSignatureBytes -Certificate $authorCertificate -WithoutTimestamp); Pattern = 'no timestamp' },
    @{ Name = "Timestamp attribute that is not an RFC 3161 token is refused"; Bytes = (New-TestAuthorSignatureBytes -Certificate $authorCertificate -TimestampNotTstInfo); Pattern = 'not an RFC 3161' },
    @{ Name = "Signature with two signers is refused"; Bytes = (New-TestAuthorSignatureBytes -Certificate $authorCertificate -TwoSigners); Pattern = 'exactly one signer' },
    @{ Name = "Undecodable signature is refused"; Bytes = [Text.Encoding]::ASCII.GetBytes("not a signature"); Pattern = 'cannot be decoded' }
)) {
    Assert-True `
        -Condition ((Get-SdkAuthorSignatureFailure -SignatureBytes $case.Bytes -ExpectedFingerprint $authorFingerprint) -match $case.Pattern) `
        -Name $case.Name
}

# Package level. nuget verify needs the registered certificate and a trusted chain, which a test
# fixture cannot have, so these cases inject the verifier; the real verifier runs on the real
# package in Prepare-SdkRelease.ps1, in the workflow, and below when a signed package is supplied.
$passingVerifier = { param($PackagePath, $Fingerprint) return $null }
$failingVerifier = { param($PackagePath, $Fingerprint) return "NU3018: simulated verification failure" }
$baseEntries = @(
    @("_rels/.rels", [Text.Encoding]::ASCII.GetBytes("rels")),
    @("[Content_Types].xml", [Text.Encoding]::ASCII.GetBytes("<Types/>")),
    @("LICENSE", [Text.Encoding]::ASCII.GetBytes("license")),
    @("PACKAGE_README.md", [Text.Encoding]::ASCII.GetBytes("readme")),
    @("SoftLicence.SDK.nuspec", (New-NuspecBytes -Id "SoftLicence.SDK" -Version "3.0.0")),
    @("icon.png", [byte[]](0x89, 0x50)),
    @($assemblyEntry, $signedBytes),
    @("package/services/metadata/core-properties/abc.psmdcp", [Text.Encoding]::ASCII.GetBytes("<coreProperties/>"))
)
$goodSignature = New-TestAuthorSignatureBytes -Certificate $authorCertificate
$authorFixtures = @()
try {
    $unsignedSdk = New-SdkPackageFixtureFromList -EntryList $baseEntries
    $authorSignedSdk = New-SdkPackageFixtureFromList -EntryList ($baseEntries + , @(".signature.p7s", $goodSignature))
    $junkSignedSdk = New-SdkPackageFixtureFromList -EntryList ($baseEntries + , @(".signature.p7s", [Text.Encoding]::ASCII.GetBytes("junk")))
    $otherSignedSdk = New-SdkPackageFixtureFromList -EntryList ($baseEntries + , @(".signature.p7s", (New-TestAuthorSignatureBytes -Certificate $otherCertificate)))
    $caseTwinSignatureSdk = New-SdkPackageFixtureFromList -EntryList ($baseEntries + @(@(".signature.p7s", $goodSignature), @(".Signature.p7s", $goodSignature)))
    $nestedSignatureSdk = New-SdkPackageFixtureFromList -EntryList ($baseEntries + , @("lib/.signature.p7s", $goodSignature))
    $extraFileSdk = New-SdkPackageFixtureFromList -EntryList ($baseEntries + , @("tools/install.ps1", [Text.Encoding]::ASCII.GetBytes("evil")))
    $authorFixtures = @($unsignedSdk, $authorSignedSdk, $junkSignedSdk, $otherSignedSdk, $caseTwinSignatureSdk, $nestedSignatureSdk, $extraFileSdk)

    Assert-True `
        -Condition ($null -eq (Get-GuardFailure { Assert-SdkPackageEntries -PackagePath $unsignedSdk -NuGetVerifier $failingVerifier })) `
        -Name "Unsigned package with only allowed entries passes the content check"
    Assert-True `
        -Condition ($null -eq (Get-GuardFailure { Assert-SdkPackageEntries -PackagePath $authorSignedSdk -ExpectedFingerprint $authorFingerprint -NuGetVerifier $passingVerifier })) `
        -Name "Author signature entry is accepted when the signature is the expected one"
    Assert-True `
        -Condition ((Get-GuardFailure { Assert-SdkPackageEntries -PackagePath $authorSignedSdk -ExpectedFingerprint $authorFingerprint -NuGetVerifier $failingVerifier }) -match 'nuget verify refused.*NU3018') `
        -Name "Author signature entry is refused when nuget verify fails"
    Assert-True `
        -Condition ((Get-GuardFailure { Assert-SdkPackageEntries -PackagePath $junkSignedSdk -ExpectedFingerprint $authorFingerprint -NuGetVerifier $passingVerifier }) -match 'cannot be decoded') `
        -Name "Undecodable signature entry is refused even if nuget verify would pass"
    Assert-True `
        -Condition ((Get-GuardFailure { Assert-SdkPackageEntries -PackagePath $otherSignedSdk -ExpectedFingerprint $authorFingerprint -NuGetVerifier $passingVerifier }) -match 'unexpected certificate') `
        -Name "Signature entry of another certificate is refused"
    Assert-True `
        -Condition ((Get-GuardFailure { Assert-SdkPackageEntries -PackagePath $caseTwinSignatureSdk -ExpectedFingerprint $authorFingerprint -NuGetVerifier $passingVerifier }) -match 'exactly one \.signature\.p7s') `
        -Name "Signature entry twin differing by case is refused"
    Assert-True `
        -Condition ((Get-GuardFailure { Assert-SdkPackageEntries -PackagePath $nestedSignatureSdk -ExpectedFingerprint $authorFingerprint -NuGetVerifier $passingVerifier }) -match 'Unexpected file in NuGet package: lib/\.signature\.p7s') `
        -Name "Signature entry outside the package root is refused"
    Assert-True `
        -Condition ((Get-GuardFailure { Assert-SdkPackageEntries -PackagePath $extraFileSdk -NuGetVerifier $passingVerifier }) -match 'Unexpected file in NuGet package: tools/install\.ps1') `
        -Name "Unexpected entry is still refused"
    Assert-True `
        -Condition ((Get-GuardFailure { Assert-SdkPackageAuthorSignature -PackagePath $unsignedSdk -NuGetVerifier $passingVerifier }) -match 'no NuGet author signature') `
        -Name "A package without author signature cannot be published"
    Assert-True `
        -Condition ($null -eq (Get-GuardFailure { Assert-SdkPackageAuthorSignature -PackagePath $authorSignedSdk -ExpectedFingerprint $authorFingerprint -NuGetVerifier $passingVerifier })) `
        -Name "A package with the expected author signature can be published"

    # The workflow content step itself, run as written in publish.yml against the fixtures.
    $verifyBlock = @($runBlocks | Where-Object { $_ -match 'Expected exactly one nupkg in out' })
    Assert-True -Condition ($verifyBlock.Count -eq 1) -Name "Package content step discovered"
    Assert-True -Condition ($verifyBlock.Count -eq 1 -and $verifyBlock[0] -notmatch '\$allowed\s*=\s*@\(') -Name "Package content step has no private copy of the allowlist"
    if ($verifyBlock.Count -eq 1) {
        $stepRoot = Join-Path ([IO.Path]::GetTempPath()) ("softlicence-publish-step-" + [Guid]::NewGuid().ToString("N"))
        $previousSdkVersion = $env:SDK_VERSION
        try {
            New-Item -ItemType Directory -Path (Join-Path $stepRoot "scripts"), (Join-Path $stepRoot "out") | Out-Null
            Copy-Item -LiteralPath (Join-Path $PSScriptRoot "..\..\scripts\SdkSigning.ps1") -Destination (Join-Path $stepRoot "scripts")
            $env:SDK_VERSION = "3.0.0"
            foreach ($stepCase in @(
                @{ Name = "Workflow content step accepts an unsigned package"; Package = $unsignedSdk; Pattern = $null },
                @{ Name = "Workflow content step refuses an invalid author signature"; Package = $junkSignedSdk; Pattern = 'cannot be decoded' }
            )) {
                Get-ChildItem -LiteralPath (Join-Path $stepRoot "out") | Remove-Item -Force
                Copy-Item -LiteralPath $stepCase.Package -Destination (Join-Path $stepRoot "out\SoftLicence.SDK.3.0.0.nupkg")
                Push-Location $stepRoot
                try {
                    $stepFailure = Get-GuardFailure ([scriptblock]::Create($verifyBlock[0]))
                }
                finally {
                    Pop-Location
                }
                $stepOk = if ($null -eq $stepCase.Pattern) { $null -eq $stepFailure } else { $stepFailure -match $stepCase.Pattern }
                Assert-True -Condition $stepOk -Name $stepCase.Name
            }
        }
        finally {
            $env:SDK_VERSION = $previousSdkVersion
            Remove-Item -LiteralPath $stepRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}
finally {
    foreach ($fixture in $authorFixtures) {
        Remove-Item -LiteralPath $fixture -Force -ErrorAction SilentlyContinue
    }
    $authorCertificate.Dispose()
    $otherCertificate.Dispose()
}

if ($pushBlock.Count -eq 1) {
    $authorGuardIndex = $pushBlock[0].IndexOf('Assert-SdkPackageAuthorSignature', [System.StringComparison]::Ordinal)
    $pushCommandIndex = $pushBlock[0].IndexOf('dotnet nuget push', [System.StringComparison]::Ordinal)
    Assert-True -Condition ($authorGuardIndex -ge 0 -and $authorGuardIndex -lt $pushCommandIndex) -Name "Author signature guard runs before the NuGet push"
}
if ($null -ne $prepareScript) {
    $authorSignIndex = $prepareScript.IndexOf('Invoke-SdkPackageAuthorSigning -PackagePath', [System.StringComparison]::Ordinal)
    $authorCheckIndex = $prepareScript.IndexOf('Assert-SdkPackageAuthorSignature -PackagePath', [System.StringComparison]::Ordinal)
    $contentCheckIndex = $prepareScript.IndexOf('Assert-SdkPackageEntries -PackagePath', [System.StringComparison]::Ordinal)
    Assert-True -Condition ($authorSignIndex -gt $signStepIndex) -Name "Local preparation author-signs the package after signing the assembly"
    Assert-True -Condition ($authorCheckIndex -gt $authorSignIndex) -Name "Local preparation verifies the author signature after signing"
    Assert-True -Condition ($contentCheckIndex -gt $authorSignIndex) -Name "Local preparation checks the content of the signed package"
}

# Real package proof, local only: the registered certificate is never available to the test run.
$realSignedPackage = $env:SOFTLICENCE_SIGNED_SDK_PACKAGE
if (-not [string]::IsNullOrWhiteSpace($realSignedPackage)) {
    Assert-True `
        -Condition ($null -eq (Get-GuardFailure { Assert-SdkPackageAuthorSignature -PackagePath $realSignedPackage })) `
        -Name "Real author-signed SDK package passes the guard with the real nuget verify"
    Assert-True `
        -Condition ($null -eq (Get-GuardFailure { Assert-SdkPackageEntries -PackagePath $realSignedPackage })) `
        -Name "Real author-signed SDK package passes the content check"
}

if ($failures -gt 0) {
    throw "$failures publish workflow security test(s) failed."
}

Write-Output "Publish workflow security tests passed on PowerShell $($PSVersionTable.PSVersion)."
