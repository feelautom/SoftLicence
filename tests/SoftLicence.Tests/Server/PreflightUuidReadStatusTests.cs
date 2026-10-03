using System.Text.Json;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>
/// TKT-001277 review M1: only an explicit, exact <c>"systemUuidRead": "error"</c> observation turns an absent UUID into
/// the unreadable refusal (AR-02). Anything else keeps the absent refusal; nothing here can accept a machine.
/// </summary>
public sealed class PreflightUuidReadStatusTests
{
    [Theory]
    [InlineData("{\"systemUuidRead\":\"error\"}", true)]
    [InlineData("{\"systemUuidRead\":\"absent\"}", false)]
    [InlineData("{\"systemUuidRead\":\"present\"}", false)]
    [InlineData("{\"systemUuidRead\":\"ERROR\"}", false)]
    [InlineData("{\"systemUuidRead\":\" error\"}", false)]
    [InlineData("{\"systemUuidRead\":1}", false)]
    [InlineData("{\"machineName\":\"HOST\"}", false)]
    [InlineData("[\"error\"]", false)]
    public void ReportsUnreadableUuid_AcceptsOnlyTheExactErrorStatus(string json, bool expected)
    {
        using var document = JsonDocument.Parse(json);

        Assert.Equal(expected, RuntimeDistributionPreflightService.ReportsUnreadableUuid(document.RootElement.Clone()));
    }

    [Fact]
    public void ReportsUnreadableUuid_AbsentEvidenceIsNotAnError()
    {
        Assert.False(RuntimeDistributionPreflightService.ReportsUnreadableUuid(null));
    }
}
