using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>
/// Pins the PowerShell Admin CLI to the explicit provider-owned provisioning contract.
/// </summary>
public sealed partial class AdminCliProvisioningContractTests
{
    /// <summary>
    /// Proves the real CLI function serializes exact authority inputs into one intercepted request and
    /// rejects whitespace references and an empty commercial subject before transport.
    /// </summary>
    [Fact]
    [Trait("Category", "PrivateRepository")]
    public async Task NewSoftLicense_RuntimeSerializesExactAuthorityAndFailsClosedBeforeTransport()
    {
        var scriptPath = AdminCliPath().Replace("'", "''", StringComparison.Ordinal);
        const string marker = "__TKT800_RUNTIME_RESULT__";
        var command = $$"""
            $ErrorActionPreference = 'Stop'
            . '{{scriptPath}}'
            $ServerUrl = 'network-disabled://tkt800'
            $script:Calls = [System.Collections.Generic.List[object]]::new()
            function global:Invoke-RestMethod {
                param($Uri, $Method, $Headers, $Body)
                $script:Calls.Add([pscustomobject]@{ Uri = $Uri; Method = $Method; Body = $Body })
                [pscustomobject]@{ LicenseKey = 'TEST-ONLY' }
            }
            $subject = [Guid]'80000000-0000-0000-0000-000000000001'
            New-SoftLicense -ProductName 'TestProduct' -CustomerName 'TestCustomer' -Email 'test@example.test' -Days 45 -Reference '  TKT800-CLI-001  ' -CommercialSubjectId $subject
            $validCallCount = $script:Calls.Count
            New-SoftLicense -ProductName 'TestProduct' -CustomerName 'TestCustomer' -Reference '   ' -CommercialSubjectId $subject -ErrorAction SilentlyContinue
            $afterWhitespaceCount = $script:Calls.Count
            New-SoftLicense -ProductName 'TestProduct' -CustomerName 'TestCustomer' -Reference 'TKT800-EMPTY-SUBJECT' -CommercialSubjectId ([Guid]::Empty) -ErrorAction SilentlyContinue
            $afterEmptySubjectCount = $script:Calls.Count
            $payload = $script:Calls[0].Body | ConvertFrom-Json
            $result = [ordered]@{
                CallCount = $validCallCount
                AfterWhitespaceCount = $afterWhitespaceCount
                AfterEmptySubjectCount = $afterEmptySubjectCount
                Uri = $script:Calls[0].Uri
                Method = [string]$script:Calls[0].Method
                Reference = $payload.reference
                CommercialSubjectId = [string]$payload.commercialSubjectId
                ProductName = $payload.productName
                DaysValidity = $payload.daysValidity
            }
            Write-Output ('{{marker}}' + ($result | ConvertTo-Json -Compress))
            """;

        var result = await RunPowerShellAsync(command);

        Assert.True(result.ExitCode == 0,
            $"PowerShell exited with {result.ExitCode}. Standard error: {result.StandardError}");
        var markerLine = result.StandardOutput.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
            .Single(line => line.StartsWith(marker, StringComparison.Ordinal));
        using var json = JsonDocument.Parse(markerLine[marker.Length..]);
        var root = json.RootElement;
        Assert.Equal(1, root.GetProperty("CallCount").GetInt32());
        Assert.Equal(1, root.GetProperty("AfterWhitespaceCount").GetInt32());
        Assert.Equal(1, root.GetProperty("AfterEmptySubjectCount").GetInt32());
        Assert.Equal("network-disabled://tkt800/api/admin/licenses", root.GetProperty("Uri").GetString());
        Assert.Equal("Post", root.GetProperty("Method").GetString());
        Assert.Equal("  TKT800-CLI-001  ", root.GetProperty("Reference").GetString());
        Assert.Equal("80000000-0000-0000-0000-000000000001",
            root.GetProperty("CommercialSubjectId").GetString());
        Assert.Equal("TestProduct", root.GetProperty("ProductName").GetString());
        Assert.Equal(45, root.GetProperty("DaysValidity").GetInt32());
    }

    /// <summary>Complements the runtime proof by pinning mandatory parameter declarations.</summary>
    [Fact]
    [Trait("Category", "PrivateRepository")]
    public async Task NewSoftLicense_SourceDeclaresRequiredAuthorityParameters()
    {
        var script = await File.ReadAllTextAsync(AdminCliPath());

        Assert.Matches(RequiredReferenceParameter(), script);
        Assert.Matches(RequiredCommercialSubjectParameter(), script);
        Assert.Matches(ReferenceBodyField(), script);
        Assert.Matches(CommercialSubjectBodyField(), script);
        Assert.DoesNotContain("if ($Reference)", script, StringComparison.Ordinal);
    }

    /// <summary>Runs an encoded PowerShell command without a profile and captures its complete result.</summary>
    /// <param name="command">The in-memory command that dot-sources and exercises the task-owned script.</param>
    /// <returns>The process exit code and captured standard streams.</returns>
    private static async Task<PowerShellResult> RunPowerShellAsync(string command)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = "pwsh",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        startInfo.ArgumentList.Add("-NoLogo");
        startInfo.ArgumentList.Add("-NoProfile");
        startInfo.ArgumentList.Add("-NonInteractive");
        startInfo.ArgumentList.Add("-EncodedCommand");
        startInfo.ArgumentList.Add(Convert.ToBase64String(Encoding.Unicode.GetBytes(command)));

        using var process = Process.Start(startInfo)
            ?? throw new InvalidOperationException("PowerShell could not be started for the Admin CLI contract test.");
        var standardOutput = process.StandardOutput.ReadToEndAsync();
        var standardError = process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync();
        return new PowerShellResult(process.ExitCode, await standardOutput, await standardError);
    }

    /// <summary>Finds the checked-out Admin CLI from the compiler-recorded source location.</summary>
    /// <param name="sourceFile">The current test source path, used only as a repository anchor.</param>
    /// <returns>The absolute path to the task-owned PowerShell script.</returns>
    private static string AdminCliPath([CallerFilePath] string sourceFile = "")
    {
        for (var directory = new DirectoryInfo(Path.GetDirectoryName(sourceFile)!);
             directory is not null;
             directory = directory.Parent)
        {
            var candidate = Path.Combine(directory.FullName, "scripts", "Admin-Cli.ps1");
            if (File.Exists(candidate))
                return candidate;
        }

        throw new FileNotFoundException("The SoftLicence Admin CLI script was not found.");
    }

    /// <summary>Matches a mandatory string Reference parameter without accepting a default value.</summary>
    [GeneratedRegex(@"(?s)\[Parameter\(Mandatory\s*=\s*\$true\)\]\s*\[ValidateNotNullOrEmpty\(\)\]\s*\[string\]\$Reference\s*(?:,|\r?\n)")]
    private static partial Regex RequiredReferenceParameter();

    /// <summary>Matches a mandatory GUID CommercialSubjectId parameter.</summary>
    [GeneratedRegex(@"(?s)\[Parameter\(Mandatory\s*=\s*\$true\)\]\s*\[Guid\]\$CommercialSubjectId\s*(?:,|\r?\n)")]
    private static partial Regex RequiredCommercialSubjectParameter();

    /// <summary>Matches the unconditional Reference field in the JSON source object.</summary>
    [GeneratedRegex(@"(?m)^\s*reference\s*=\s*\$Reference\s*$")]
    private static partial Regex ReferenceBodyField();

    /// <summary>Matches the unconditional CommercialSubjectId field in the JSON source object.</summary>
    [GeneratedRegex(@"(?m)^\s*commercialSubjectId\s*=\s*\$CommercialSubjectId\s*$")]
    private static partial Regex CommercialSubjectBodyField();

    /// <summary>Captures the observable result of the isolated PowerShell child process.</summary>
    /// <param name="ExitCode">The PowerShell process exit code.</param>
    /// <param name="StandardOutput">The complete standard output text.</param>
    /// <param name="StandardError">The complete standard error text.</param>
    private sealed record PowerShellResult(int ExitCode, string StandardOutput, string StandardError);
}
