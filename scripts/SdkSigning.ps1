# Shared SDK signing contract, dot-sourced by scripts/Prepare-SdkRelease.ps1 and by
# .github/workflows/publish.yml so both apply exactly the same rule.
#
# nuget.org signs the package, not the assembly inside it. SoftLicence.SDK.dll was
# published without an Authenticode signature up to 1.1.14, and Windows Smart App
# Control then refuses to load it in consumer applications (TKT-001479).
#
# The release certificate key lives in Certum SimplySign and is only reachable from
# the release workstation, so the assembly is signed locally and the hosted workflow
# only verifies it before publishing the exact package attached to the GitHub Release.

$script:SdkSigningCertificateThumbprint = '8F494899512C05EAFCA95EE39D6C0E1F065D370F'
$script:SdkSigningTimestampServer = 'http://time.certum.pl'
$script:SdkPackageAssemblyEntry = 'lib/netstandard2.0/SoftLicence.SDK.dll'

# The same release certificate also author-signs the .nupkg (TKT-004207): since the YOUR_APP_NAME SDKs
# (TKT-002906/002916) the FeelAutom nuget.org account has this certificate registered, and nuget.org
# then refuses every package of the account that does not carry such a signature (HTTP 400).
# dotnet nuget sign and verify identify the certificate by its SHA-256 fingerprint, not by the SHA-1
# thumbprint above (the .NET SDK rejects a SHA-1 fingerprint with NU3043).
$script:SdkNuGetSigningCertificateFingerprint = 'A1515DCDB473469BC226F0DDF94DAD06E6EDF7B21C0732444BF3B34DE3B0CD33'
$script:SdkNuGetSignatureEntry = '.signature.p7s'

# Entries a SoftLicence.SDK package may hold, apart from the .psmdcp metadata and the author
# signature entry, which have their own rules in Assert-SdkPackageEntries.
$script:SdkPackageAllowedEntries = @(
    '_rels/.rels',
    '[Content_Types].xml',
    'LICENSE',
    'PACKAGE_README.md',
    'SoftLicence.SDK.nuspec',
    'icon.png',
    'lib/netstandard2.0/SoftLicence.SDK.dll'
)

# Returns the thumbprint of the only certificate allowed to sign a published SDK assembly.
function Get-SdkSigningCertificateThumbprint {
    return $script:SdkSigningCertificateThumbprint
}

# Opens a package archive after loading the compression assemblies on Windows PowerShell and PowerShell 7.
function Open-SdkPackageArchive {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PackagePath,

        [Parameter(Mandatory = $true)]
        [System.IO.Compression.ZipArchiveMode]$Mode
    )

    return [IO.Compression.ZipFile]::Open($PackagePath, $Mode)
}

# Copies the SDK assembly out of a package. Returns $false when the package has no such entry.
function Export-SdkPackageAssembly {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PackagePath,

        [Parameter(Mandatory = $true)]
        [string]$DestinationPath
    )

    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = Open-SdkPackageArchive -PackagePath $PackagePath -Mode Read
    try {
        foreach ($entry in $archive.Entries) {
            if ([string]::Equals($entry.FullName, $script:SdkPackageAssemblyEntry, [System.StringComparison]::Ordinal)) {
                $source = $entry.Open()
                try {
                    $target = [IO.File]::Create($DestinationPath)
                    try {
                        $source.CopyTo($target)
                    }
                    finally {
                        $target.Dispose()
                    }
                }
                finally {
                    $source.Dispose()
                }

                return $true
            }
        }
    }
    finally {
        $archive.Dispose()
    }

    return $false
}

# Lists the full names of every entry of a package archive.
function Get-SdkPackageEntryNames {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PackagePath
    )

    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = Open-SdkPackageArchive -PackagePath $PackagePath -Mode Read
    try {
        return @($archive.Entries | ForEach-Object { $_.FullName })
    }
    finally {
        $archive.Dispose()
    }
}

# Fails unless the package holds exactly one SDK assembly, at the canonical path. An archive may
# carry two entries with the same name, or names differing only by case or by slash direction;
# the signature guard reads one entry, so any such twin must be refused, not ignored.
function Assert-SdkPackageSingleAssembly {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PackagePath
    )

    $packageName = Split-Path -Leaf $PackagePath
    $candidates = @(Get-SdkPackageEntryNames -PackagePath $PackagePath | Where-Object {
        [string]::Equals($_.Replace('\', '/'), $script:SdkPackageAssemblyEntry, [System.StringComparison]::OrdinalIgnoreCase)
    })
    if ($candidates.Count -eq 0) {
        throw "$packageName does not contain $($script:SdkPackageAssemblyEntry)."
    }
    if ($candidates.Count -ne 1 -or
        -not [string]::Equals($candidates[0], $script:SdkPackageAssemblyEntry, [System.StringComparison]::Ordinal)) {
        throw "$packageName must contain exactly one $($script:SdkPackageAssemblyEntry) entry, found: $($candidates -join ', ')."
    }
}

# Fails unless the package really is SoftLicence.SDK at the expected version. NuGet publishes
# the identity written in the .nuspec, not the file name: a renamed package of another version
# must be refused before it is pushed.
function Assert-SdkPackageIdentity {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PackagePath,

        [Parameter(Mandatory = $true)]
        [string]$ExpectedVersion
    )

    if (-not (Test-Path -LiteralPath $PackagePath -PathType Leaf)) {
        throw "SDK package not found: $PackagePath"
    }

    $packageName = Split-Path -Leaf $PackagePath
    $nuspecEntries = @(Get-SdkPackageEntryNames -PackagePath $PackagePath | Where-Object {
        $_.EndsWith('.nuspec', [System.StringComparison]::OrdinalIgnoreCase)
    })
    if ($nuspecEntries.Count -ne 1 -or
        -not [string]::Equals($nuspecEntries[0], 'SoftLicence.SDK.nuspec', [System.StringComparison]::Ordinal)) {
        throw "$packageName must contain exactly one SoftLicence.SDK.nuspec at its root, found: $($nuspecEntries -join ', ')."
    }

    $archive = Open-SdkPackageArchive -PackagePath $PackagePath -Mode Read
    try {
        $entry = $archive.GetEntry('SoftLicence.SDK.nuspec')
        $stream = $entry.Open()
        try {
            $settings = New-Object System.Xml.XmlReaderSettings
            $settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
            $settings.XmlResolver = $null
            $xmlReader = [System.Xml.XmlReader]::Create($stream, $settings)
            try {
                $document = New-Object System.Xml.XmlDocument
                $document.XmlResolver = $null
                $document.Load($xmlReader)
            }
            finally {
                $xmlReader.Dispose()
            }
        }
        finally {
            $stream.Dispose()
        }
    }
    finally {
        $archive.Dispose()
    }

    # The identity must be unambiguous: NuGet reads <id> and <version> in the namespace of the
    # <package> root, so a look-alike element in another namespace, a second <metadata> or a
    # repeated element could show this guard one identity and NuGet another. Exactly one element
    # of each name is allowed, in the root namespace; anything else is refused.
    $root = $document.DocumentElement
    if ($null -eq $root -or -not [string]::Equals($root.LocalName, 'package', [System.StringComparison]::Ordinal)) {
        throw "$packageName has a .nuspec whose root element is not <package>."
    }

    $metadataNodes = @($root.ChildNodes | Where-Object {
        $_.NodeType -eq [System.Xml.XmlNodeType]::Element -and
        [string]::Equals($_.LocalName, 'metadata', [System.StringComparison]::OrdinalIgnoreCase)
    })
    if ($metadataNodes.Count -ne 1 -or
        -not [string]::Equals($metadataNodes[0].LocalName, 'metadata', [System.StringComparison]::Ordinal) -or
        -not [string]::Equals($metadataNodes[0].NamespaceURI, $root.NamespaceURI, [System.StringComparison]::Ordinal)) {
        throw "$packageName has a .nuspec with an ambiguous <metadata> element."
    }

    $identity = @{}
    foreach ($name in @('id', 'version')) {
        $nodes = @($metadataNodes[0].ChildNodes | Where-Object {
            $_.NodeType -eq [System.Xml.XmlNodeType]::Element -and
            [string]::Equals($_.LocalName, $name, [System.StringComparison]::OrdinalIgnoreCase)
        })
        if ($nodes.Count -ne 1 -or
            -not [string]::Equals($nodes[0].LocalName, $name, [System.StringComparison]::Ordinal) -or
            -not [string]::Equals($nodes[0].NamespaceURI, $root.NamespaceURI, [System.StringComparison]::Ordinal)) {
            throw "$packageName has a .nuspec with an ambiguous <$name> element ($($nodes.Count) found)."
        }
        $identity[$name] = [string]$nodes[0].InnerText
    }
    $id = $identity['id']
    $version = $identity['version']

    if (-not [string]::Equals($id, 'SoftLicence.SDK', [System.StringComparison]::Ordinal)) {
        throw "$packageName declares the package id '$id', expected 'SoftLicence.SDK'."
    }
    # Exact comparison on purpose: the release tag and the packed version come from the same
    # value, so any difference means the attached file is not the package of this release.
    if (-not [string]::Equals($version, $ExpectedVersion, [System.StringComparison]::Ordinal)) {
        throw "$packageName declares version '$version', expected '$ExpectedVersion'. The attached file is not the package of this release."
    }
}

# Returns why a signature must be refused, or $null when it is acceptable: valid, made with the
# expected certificate, and timestamped. Without a timestamp the signature stops being valid
# when the certificate expires, although it verifies today.
function Get-SdkSignatureFailure {
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        $Signature,

        [Parameter(Mandatory = $true)]
        [string]$ExpectedThumbprint
    )

    if ($null -eq $Signature) {
        return "has no readable Authenticode signature."
    }
    if ([string]$Signature.Status -ne "Valid") {
        return "has no valid Authenticode signature (Status=$($Signature.Status)). An unsigned SDK must not be published."
    }

    $thumbprint = if ($null -ne $Signature.SignerCertificate) { [string]$Signature.SignerCertificate.Thumbprint } else { "" }
    if (-not [string]::Equals($thumbprint, $ExpectedThumbprint, [System.StringComparison]::OrdinalIgnoreCase)) {
        return "is signed with an unexpected certificate ($thumbprint)."
    }
    if ($null -eq $Signature.TimeStamperCertificate) {
        return "is signed without a timestamp, so its signature would expire with the certificate."
    }

    return $null
}

# Fails unless the package holds exactly one SDK assembly and that assembly carries a valid,
# timestamped Authenticode signature made with the expected release certificate.
# Returns the signer thumbprint on success.
function Assert-SdkPackageSignature {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PackagePath,

        [string]$ExpectedThumbprint = $script:SdkSigningCertificateThumbprint
    )

    if (-not (Test-Path -LiteralPath $PackagePath -PathType Leaf)) {
        throw "SDK package not found: $PackagePath"
    }
    if ([string]::IsNullOrWhiteSpace($ExpectedThumbprint)) {
        throw "The expected SDK signing certificate thumbprint is required."
    }

    Assert-SdkPackageSingleAssembly -PackagePath $PackagePath

    $packageName = Split-Path -Leaf $PackagePath
    $workDirectory = Join-Path ([IO.Path]::GetTempPath()) ("softlicence-sdk-signature-" + [Guid]::NewGuid().ToString("N"))
    [IO.Directory]::CreateDirectory($workDirectory) | Out-Null
    try {
        $assemblyPath = Join-Path $workDirectory "SoftLicence.SDK.dll"
        if (-not (Export-SdkPackageAssembly -PackagePath $PackagePath -DestinationPath $assemblyPath)) {
            throw "$packageName does not contain $($script:SdkPackageAssemblyEntry)."
        }

        $signature = Get-AuthenticodeSignature -LiteralPath $assemblyPath
        $failure = Get-SdkSignatureFailure -Signature $signature -ExpectedThumbprint $ExpectedThumbprint
        if ($null -ne $failure) {
            throw "SoftLicence.SDK.dll in $packageName $failure"
        }

        return $signature.SignerCertificate.Thumbprint
    }
    finally {
        Remove-Item -LiteralPath $workDirectory -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# Locates signtool.exe from the Windows SDK, newest version first.
function Find-SdkSignTool {
    $found = Get-ChildItem "C:\Program Files (x86)\Windows Kits\10\bin\*\x64\signtool.exe" -ErrorAction SilentlyContinue |
        Sort-Object FullName -Descending | Select-Object -First 1
    if ($found) {
        return $found.FullName
    }

    $command = Get-Command "signtool.exe" -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }

    return $null
}

# Signs the SDK assembly of a freshly packed, not yet published package and writes the
# signed file back into the same package. Only the release workstation can do this.
function Invoke-SdkPackageAssemblySigning {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PackagePath,

        [string]$CertThumbprint = $script:SdkSigningCertificateThumbprint,

        [string]$TimestampServer = $script:SdkSigningTimestampServer
    )

    $signTool = Find-SdkSignTool
    if (-not $signTool) {
        throw "signtool.exe was not found. Install the Windows SDK before preparing an SDK release."
    }

    $workDirectory = Join-Path ([IO.Path]::GetTempPath()) ("softlicence-sdk-signing-" + [Guid]::NewGuid().ToString("N"))
    [IO.Directory]::CreateDirectory($workDirectory) | Out-Null
    try {
        $assemblyPath = Join-Path $workDirectory "SoftLicence.SDK.dll"
        if (-not (Export-SdkPackageAssembly -PackagePath $PackagePath -DestinationPath $assemblyPath)) {
            throw "$(Split-Path -Leaf $PackagePath) does not contain $($script:SdkPackageAssemblyEntry)."
        }

        & $signTool sign /sha1 $CertThumbprint /tr $TimestampServer /td sha256 /fd sha256 $assemblyPath
        if ($LASTEXITCODE -ne 0) {
            throw "signtool failed to sign SoftLicence.SDK.dll (exit code $LASTEXITCODE). Check that the SimplySign session is open."
        }

        $archive = Open-SdkPackageArchive -PackagePath $PackagePath -Mode Update
        try {
            $existing = @($archive.Entries | Where-Object {
                [string]::Equals($_.FullName, $script:SdkPackageAssemblyEntry, [System.StringComparison]::Ordinal)
            })
            foreach ($entry in $existing) {
                $entry.Delete()
            }

            $newEntry = $archive.CreateEntry($script:SdkPackageAssemblyEntry, [IO.Compression.CompressionLevel]::Optimal)
            $target = $newEntry.Open()
            try {
                $bytes = [IO.File]::ReadAllBytes($assemblyPath)
                $target.Write($bytes, 0, $bytes.Length)
            }
            finally {
                $target.Dispose()
            }
        }
        finally {
            $archive.Dispose()
        }
    }
    finally {
        Remove-Item -LiteralPath $workDirectory -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# --- NuGet author signature (TKT-004207) ------------------------------------------------------
# The Authenticode signature above protects the assembly for consumers; the author signature below
# is what nuget.org requires for the package itself once the account has a registered certificate.

$script:SdkCommitmentTypeIndicationOid = '1.2.840.113549.1.9.16.2.16'
$script:SdkSignatureTimestampTokenOid = '1.2.840.113549.1.9.16.2.14'
$script:SdkTstInfoContentTypeOid = '1.2.840.113549.1.9.16.1.4'
# DER of the CommitmentTypeIndication value naming proof-of-origin, which marks an author signature
# (a repository signature names proof-of-receipt). dotnet nuget sign writes exactly these bytes.
$script:SdkAuthorCommitmentDer = [byte[]](0x30, 0x0D, 0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x06, 0x01)
$script:SdkNuGetSignatureMaxBytes = 4MB

# Returns the SHA-256 fingerprint (64 uppercase hexadecimal characters) of the certificate registered
# on nuget.org for the FeelAutom account, the only one allowed to author-sign a published SDK package.
function Get-SdkNuGetSigningCertificateFingerprint {
    return $script:SdkNuGetSigningCertificateFingerprint
}

# Returns why the bytes of a .signature.p7s are not an acceptable author signature, or $null when they
# are: one signer, made with the certificate whose SHA-256 fingerprint is ExpectedFingerprint (compared
# without regard to hexadecimal case), marked as an author signature (proof-of-origin commitment), and
# carrying one RFC 3161 timestamp token, without which the signature would expire with the certificate.
# This is a structural check only: the cryptographic validity, the content hash and the trust chain are
# proven by nuget verify in Assert-SdkPackageAuthorSignature. Throws only on a malformed fingerprint.
# Needs PowerShell 7 (SHA256.HashData is .NET 5 or later), like the workflow and the preparation script.
function Get-SdkAuthorSignatureFailure {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [byte[]]$SignatureBytes,

        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[0-9A-Fa-f]{64}$')]
        [string]$ExpectedFingerprint
    )

    Add-Type -AssemblyName System.Security.Cryptography.Pkcs
    $cms = [Security.Cryptography.Pkcs.SignedCms]::new()
    try {
        $cms.Decode($SignatureBytes)
    }
    catch {
        return "cannot be decoded as a CMS signature ($($_.Exception.Message.Trim()))."
    }

    if ($cms.SignerInfos.Count -ne 1) {
        return "must have exactly one signer, found $($cms.SignerInfos.Count)."
    }
    $signer = $cms.SignerInfos[0]
    if ($null -eq $signer.Certificate) {
        return "does not embed its signer certificate."
    }

    $fingerprint = [BitConverter]::ToString([Security.Cryptography.SHA256]::HashData($signer.Certificate.RawData)).Replace('-', '')
    if (-not [string]::Equals($fingerprint, $ExpectedFingerprint, [System.StringComparison]::OrdinalIgnoreCase)) {
        return "is made with an unexpected certificate (SHA-256 $fingerprint)."
    }

    $commitments = @($signer.SignedAttributes | Where-Object { $_.Oid.Value -ceq $script:SdkCommitmentTypeIndicationOid })
    $isAuthor = $commitments.Count -eq 1 -and $commitments[0].Values.Count -eq 1 -and
        [Linq.Enumerable]::SequenceEqual([byte[]]$commitments[0].Values[0].RawData, $script:SdkAuthorCommitmentDer)
    if (-not $isAuthor) {
        return "is not an author signature (no single proof-of-origin commitment type)."
    }

    $timestamps = @($signer.UnsignedAttributes | Where-Object { $_.Oid.Value -ceq $script:SdkSignatureTimestampTokenOid })
    if ($timestamps.Count -ne 1 -or $timestamps[0].Values.Count -ne 1) {
        return "has no timestamp, so it would stop being valid when the certificate expires."
    }
    $token = [Security.Cryptography.Pkcs.SignedCms]::new()
    try {
        $token.Decode([byte[]]$timestamps[0].Values[0].RawData)
    }
    catch {
        return "has a timestamp attribute that is not an RFC 3161 token (undecodable)."
    }
    if ($token.ContentInfo.ContentType.Value -cne $script:SdkTstInfoContentTypeOid -or $token.SignerInfos.Count -ne 1) {
        return "has a timestamp attribute that is not an RFC 3161 token."
    }

    return $null
}

# Runs dotnet nuget verify on every signature of the package, restricted to the given SHA-256
# fingerprint. Returns $null when it accepts, otherwise the exit code and the raw output. This is the
# check that proves the package content was not changed after signing and that the chain is trusted.
function Invoke-SdkNuGetVerify {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PackagePath,

        [Parameter(Mandatory = $true)]
        [string]$Fingerprint
    )

    $output = & dotnet nuget verify $PackagePath --all --certificate-fingerprint $Fingerprint 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) {
        return "exit code $LASTEXITCODE. $($output.Trim())"
    }

    return $null
}

# Returns the bytes of the package's root .signature.p7s, or $null when the package has none. Refuses a
# twin differing only by case (the archive could then show one signature to this guard and another to
# NuGet), and an empty or oversized entry.
function Read-SdkPackageAuthorSignature {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PackagePath
    )

    $packageName = Split-Path -Leaf $PackagePath
    $candidates = @(Get-SdkPackageEntryNames -PackagePath $PackagePath | Where-Object {
        [string]::Equals($_, $script:SdkNuGetSignatureEntry, [System.StringComparison]::OrdinalIgnoreCase)
    })
    if ($candidates.Count -eq 0) {
        return $null
    }
    if ($candidates.Count -ne 1 -or
        -not [string]::Equals($candidates[0], $script:SdkNuGetSignatureEntry, [System.StringComparison]::Ordinal)) {
        throw "$packageName must contain exactly one $($script:SdkNuGetSignatureEntry) at its root, found: $($candidates -join ', ')."
    }

    $archive = Open-SdkPackageArchive -PackagePath $PackagePath -Mode Read
    try {
        $entry = $archive.GetEntry($script:SdkNuGetSignatureEntry)
        if ($entry.Length -le 0 -or $entry.Length -gt $script:SdkNuGetSignatureMaxBytes) {
            throw "$packageName has a $($script:SdkNuGetSignatureEntry) of $($entry.Length) bytes, expected 1 to $($script:SdkNuGetSignatureMaxBytes)."
        }
        $buffer = [IO.MemoryStream]::new()
        try {
            $stream = $entry.Open()
            try {
                $stream.CopyTo($buffer)
            }
            finally {
                $stream.Dispose()
            }
            # The comma keeps the byte array whole instead of letting PowerShell unroll it.
            return , $buffer.ToArray()
        }
        finally {
            $buffer.Dispose()
        }
    }
    finally {
        $archive.Dispose()
    }
}

# Fails unless the package carries a NuGet author signature that nuget.org will accept: structurally the
# expected one (Get-SdkAuthorSignatureFailure), then accepted by nuget verify for that fingerprint.
# NuGetVerifier replaces Invoke-SdkNuGetVerify only in tests, whose fixtures cannot hold the registered
# certificate; it receives (PackagePath, Fingerprint) and returns $null or a failure text.
# Returns the verified fingerprint in uppercase.
function Assert-SdkPackageAuthorSignature {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PackagePath,

        [ValidatePattern('^[0-9A-Fa-f]{64}$')]
        [string]$ExpectedFingerprint = $script:SdkNuGetSigningCertificateFingerprint,

        [scriptblock]$NuGetVerifier
    )

    if (-not (Test-Path -LiteralPath $PackagePath -PathType Leaf)) {
        throw "SDK package not found: $PackagePath"
    }

    $packageName = Split-Path -Leaf $PackagePath
    $signatureBytes = Read-SdkPackageAuthorSignature -PackagePath $PackagePath
    if ($null -eq $signatureBytes) {
        throw "$packageName has no NuGet author signature. nuget.org refuses unsigned packages of this account; prepare the package with scripts/Prepare-SdkRelease.ps1."
    }

    $failure = Get-SdkAuthorSignatureFailure -SignatureBytes $signatureBytes -ExpectedFingerprint $ExpectedFingerprint
    if ($null -ne $failure) {
        throw "The NuGet author signature of $packageName $failure"
    }

    # The structural check runs first: nuget verify alone would accept a valid signature of any
    # trusted certificate listed, and it gives no clear reason for a missing timestamp.
    $verifyFailure = if ($null -eq $NuGetVerifier) {
        Invoke-SdkNuGetVerify -PackagePath $PackagePath -Fingerprint $ExpectedFingerprint
    }
    else {
        & $NuGetVerifier $PackagePath $ExpectedFingerprint
    }
    if ($null -ne $verifyFailure) {
        throw "nuget verify refused the author signature of ${packageName}: $verifyFailure"
    }

    return $ExpectedFingerprint.ToUpperInvariant()
}

# Fails when the package holds an entry outside the SDK allowlist. A root .signature.p7s is allowed only
# when it is a valid author signature of the expected certificate (Assert-SdkPackageAuthorSignature):
# an unsigned package stays acceptable here (push and pull request runs pack one), while a package that
# carries any other signature, or a signature entry anywhere else, is refused. Entry names compare
# ordinally: NuGet and the archive are case-sensitive about them. NuGetVerifier is for tests only.
function Assert-SdkPackageEntries {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PackagePath,

        [ValidatePattern('^[0-9A-Fa-f]{64}$')]
        [string]$ExpectedFingerprint = $script:SdkNuGetSigningCertificateFingerprint,

        [scriptblock]$NuGetVerifier
    )

    $names = @(Get-SdkPackageEntryNames -PackagePath $PackagePath)
    # The signature is checked before the allowlist so a case twin is reported as such, not as an
    # unexpected file that would hide which entry NuGet would actually read.
    $hasSignature = @($names | Where-Object {
        [string]::Equals($_, $script:SdkNuGetSignatureEntry, [System.StringComparison]::OrdinalIgnoreCase)
    }).Count -gt 0
    if ($hasSignature) {
        Assert-SdkPackageAuthorSignature -PackagePath $PackagePath -ExpectedFingerprint $ExpectedFingerprint -NuGetVerifier $NuGetVerifier | Out-Null
    }

    foreach ($name in $names) {
        $isAllowed = $script:SdkPackageAllowedEntries -ccontains $name -or
            $name -clike 'package/services/metadata/core-properties/*.psmdcp' -or
            ($hasSignature -and $name -ceq $script:SdkNuGetSignatureEntry)
        if (-not $isAllowed) {
            throw "Unexpected file in NuGet package: $name"
        }
    }
}

# Author-signs a freshly prepared, not yet published package with the registered release certificate,
# exactly as the YOUR_APP_NAME SDKs are signed (SHA-256 fingerprint from the CurrentUser\My store, SHA-256
# digest, RFC 3161 timestamp from Certum), then proves the result with Assert-SdkPackageAuthorSignature.
# Never overwrites an existing signature: a package that is already signed is not the fresh output of
# the preparation. Needs the SimplySign session open, like the Authenticode signing. Returns the
# verified fingerprint.
function Invoke-SdkPackageAuthorSigning {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PackagePath,

        [ValidatePattern('^[0-9A-Fa-f]{64}$')]
        [string]$Fingerprint = $script:SdkNuGetSigningCertificateFingerprint,

        [string]$TimestampServer = $script:SdkSigningTimestampServer
    )

    & dotnet nuget sign $PackagePath `
        --certificate-fingerprint $Fingerprint `
        --certificate-store-name My `
        --certificate-store-location CurrentUser `
        --hash-algorithm SHA256 `
        --timestamper $TimestampServer `
        --timestamp-hash-algorithm SHA256
    if ($LASTEXITCODE -ne 0) {
        throw "dotnet nuget sign failed to author-sign $(Split-Path -Leaf $PackagePath) (exit code $LASTEXITCODE). Check that the SimplySign session is open."
    }

    return Assert-SdkPackageAuthorSignature -PackagePath $PackagePath -ExpectedFingerprint $Fingerprint
}
