param(
    [string]$RepositoryRoot
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) {
    $RepositoryRoot = (& git rev-parse --show-toplevel).Trim()
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($RepositoryRoot)) {
        throw "Test-TrackedSecrets.ps1 must run inside a Git repository or receive -RepositoryRoot."
    }
}

$RepositoryRoot = [IO.Path]::GetFullPath($RepositoryRoot)
$gitCheck = & git -C $RepositoryRoot rev-parse --is-inside-work-tree
if ($LASTEXITCODE -ne 0 -or $gitCheck.Trim() -ne "true") {
    throw "RepositoryRoot is not a Git worktree."
}

function Test-AllowedSecretReference {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$RawValue,

        [Parameter(Mandatory = $true)]
        [string]$RelativePath
    )

    $value = $RawValue.Trim().Trim('`').TrimEnd(',', ';').TrimEnd()

    if ($value.Length -ge 2) {
        $first = $value[0]
        $last = $value[$value.Length - 1]
        if (($first -eq '"' -and $last -eq '"') -or ($first -eq "'" -and $last -eq "'")) {
            $value = $value.Substring(1, $value.Length - 2)
        }
    }

    if ([string]::IsNullOrEmpty($value)) {
        return $true
    }

    if ($value -match '^\$(?:env:)?[A-Za-z_][A-Za-z0-9_:]*$' `
        -or $value -match '^\$\{[^}]+\}$' `
        -or $value -match '^\$\(.+\)$' `
        -or $value -match '^\{\{[^}]+\}\}$' `
        -or $value -match '^%[A-Za-z_][A-Za-z0-9_]*%$') {
        return $true
    }

    $placeholder = $value.ToUpperInvariant()
    if ($placeholder -match '^(CHANGE_ME|REPLACE_ME|PLACEHOLDER|EXAMPLE|YOUR_[A-Z0-9_]+|<[^>]+>|__[A-Z0-9_]+__|NULL|\.\.\.)(?:[_-].*)?$') {
        return $true
    }

    $isDocumentation = [IO.Path]::GetExtension($RelativePath) -ieq ".md" `
        -or $RelativePath.Replace('\', '/') -ieq "src/SoftLicence.Server/Services/DocumentationService.cs"

    return $isDocumentation `
        -and $placeholder.IndexOf("SECRET", [StringComparison]::Ordinal) -ge 0 `
        -and $value -match '^[A-Za-z\u00C0-\u00D6\u00D8-\u00F6\u00F8-\u00FF]+(?:[-_ ][A-Za-z\u00C0-\u00D6\u00D8-\u00F6\u00F8-\u00FF]+)*$'
}

$keyPattern = '(?<key>AdminSettings__ApiSecret|SOFTLICENCE_ADMIN_SECRET)'
$assignmentPattern = '(?i)^\s*(?:-\s*)?[`"'']*(?:\$env:)?' + $keyPattern + '[`"'']*\s*(?:=|:)\s*(?<value>.+?)\s*$'
$findings = [System.Collections.Generic.List[string]]::new()
$trackedFiles = @(& git -C $RepositoryRoot ls-files)

if ($LASTEXITCODE -ne 0) {
    throw "Unable to enumerate tracked files."
}

foreach ($relativePath in $trackedFiles) {
    $fullPath = Join-Path $RepositoryRoot $relativePath
    if (-not [IO.File]::Exists($fullPath)) {
        continue
    }

    $reader = $null
    try {
        $reader = [IO.StreamReader]::new($fullPath, $true)
        $lineNumber = 0
        while (($line = $reader.ReadLine()) -ne $null) {
            $lineNumber++
            if ($line.IndexOf([char]0) -ge 0) {
                break
            }

            if ($line -notmatch $assignmentPattern) {
                continue
            }

            if (-not (Test-AllowedSecretReference -RawValue $Matches.value -RelativePath $relativePath)) {
                $safePath = $relativePath.Replace('\', '/')
                $findings.Add("$safePath`:$lineNumber [$($Matches.key)]")
            }
        }
    }
    catch [System.Text.DecoderFallbackException] {
        continue
    }
    finally {
        if ($null -ne $reader) {
            $reader.Dispose()
        }
    }
}

if ($findings.Count -gt 0) {
    throw "Tracked administrator secret assignment detected at: $($findings -join '; '). Values are intentionally omitted."
}

Write-Output "Tracked administrator secret guard passed for $($trackedFiles.Count) files."
