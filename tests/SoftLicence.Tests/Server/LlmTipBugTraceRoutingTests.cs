using Microsoft.Extensions.Configuration;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>
/// Parsing and resolution contract of the BUGTRACE_LLM_TIP_TIA_PRODUCT_IDS setting (TKT-003093): explicit product
/// identifiers only, compared as GUID values, and a malformed value refuses every product.
/// </summary>
public sealed class LlmTipBugTraceRoutingTests
{
    private static readonly Guid Tia = Guid.Parse("808648bc-a4b9-4f71-bcb1-b7c7e67ca98e");
    private static readonly Guid Other = Guid.Parse("b0251940-0332-4e3c-81b3-b894b75b04ea");

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Resolve_WhenSettingIsAbsentOrBlank_IsValidAndRoutesNothing(string? value)
    {
        var routing = new LlmTipBugTraceRouting(value);

        Assert.True(routing.IsValid);
        Assert.Equal(LlmTipBugTraceProject.None, routing.Resolve(Tia));
        Assert.Equal(LlmTipBugTraceProject.None, routing.Resolve(null));
    }

    [Theory]
    [InlineData("808648bc-a4b9-4f71-bcb1-b7c7e67ca98e")]
    [InlineData("808648BC-A4B9-4F71-BCB1-B7C7E67CA98E")]
    [InlineData(" 808648bc-a4b9-4f71-bcb1-b7c7e67ca98e ; b0251940-0332-4e3c-81b3-b894b75b04ea ")]
    [InlineData("b0251940-0332-4e3c-81b3-b894b75b04ea,808648bc-a4b9-4f71-bcb1-b7c7e67ca98e")]
    [InlineData("808648bc-a4b9-4f71-bcb1-b7c7e67ca98e\n808648bc-a4b9-4f71-bcb1-b7c7e67ca98e")]
    public void Resolve_WhenProductIsListed_RoutesToTiaConnectWhateverTheHexCaseOrSeparator(string value)
    {
        var routing = new LlmTipBugTraceRouting(value);

        Assert.True(routing.IsValid);
        Assert.Equal(LlmTipBugTraceProject.TiaConnect, routing.Resolve(Tia));
    }

    [Fact]
    public void Resolve_WhenProductIsNotListedOrMissing_RefusesIt()
    {
        var routing = new LlmTipBugTraceRouting(Tia.ToString("D"));

        Assert.Equal(LlmTipBugTraceProject.None, routing.Resolve(Other));
        Assert.Equal(LlmTipBugTraceProject.None, routing.Resolve(null));
    }

    [Theory]
    [InlineData("808648bca4b94f71bcb1b7c7e67ca98e")]
    [InlineData("{808648bc-a4b9-4f71-bcb1-b7c7e67ca98e}")]
    [InlineData("TIAConnect")]
    [InlineData("00000000-0000-0000-0000-000000000000")]
    [InlineData("808648bc-a4b9-4f71-bcb1-b7c7e67ca98e,oops")]
    public void Resolve_WhenAnyEntryIsMalformed_InvalidatesTheWholeMapping(string value)
    {
        var routing = new LlmTipBugTraceRouting(value);

        Assert.False(routing.IsValid);
        Assert.Equal(LlmTipBugTraceProject.None, routing.Resolve(Tia));
    }

    [Fact]
    public void ConfigurationConstructor_ReadsTheDocumentedKey()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                [LlmTipBugTraceRouting.TiaProductIdsKey] = Tia.ToString("D")
            })
            .Build();

        var routing = new LlmTipBugTraceRouting(configuration);

        Assert.Equal("BUGTRACE_LLM_TIP_TIA_PRODUCT_IDS", LlmTipBugTraceRouting.TiaProductIdsKey);
        Assert.Equal(LlmTipBugTraceProject.TiaConnect, routing.Resolve(Tia));
    }
}
