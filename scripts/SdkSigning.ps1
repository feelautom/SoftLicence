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
