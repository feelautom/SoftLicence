using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using SoftLicence.Server.Controllers;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>
/// TKT-003573 regression tests that need no database server: the bounded product-identifier cache
/// and the rule that a client disconnection neither loses the usage event nor produces a 503.
/// </summary>
public sealed class LlmTipFeedbackBurstTests
{
    [Fact]
    public void ProductIdCache_ReturnsStoredAnswer_UntilItsLifetimeEnds()
    {
        var clock = new ManualTimeProvider(DateTimeOffset.Parse("2026-11-10T09:30:00Z"));
        var cache = new LlmTipProductIdCache(clock);
        var productId = Guid.NewGuid();

        cache.Set("AppOne", productId);
        clock.Advance(LlmTipProductIdCache.FoundLifetime - TimeSpan.FromSeconds(1));
        Assert.True(cache.TryGet("AppOne", out var cached));
        Assert.Equal(productId, cached);

        clock.Advance(TimeSpan.FromSeconds(1));
        Assert.False(cache.TryGet("AppOne", out _));
        Assert.Equal(0, cache.Count);
    }

    [Fact]
    public void ProductIdCache_KeepsUnknownNamesOnlyForTheShortLifetime()
    {
        var clock = new ManualTimeProvider(DateTimeOffset.Parse("2026-11-10T09:30:00Z"));
        var cache = new LlmTipProductIdCache(clock);

        cache.Set("Unknown", null);
        Assert.True(cache.TryGet("Unknown", out var cached));
        Assert.Null(cached);

        clock.Advance(LlmTipProductIdCache.NotFoundLifetime);
        Assert.False(cache.TryGet("Unknown", out _));
    }

    [Fact]
    public void ProductIdCache_UsesOrdinalKeys_SoEachSpellingKeepsItsOwnDatabaseAnswer()
    {
        var cache = new LlmTipProductIdCache();
        var productId = Guid.NewGuid();

        cache.Set("AppOne", productId);

        Assert.False(cache.TryGet("appone", out _));
        Assert.False(cache.TryGet("AppOne ", out _));
        Assert.True(cache.TryGet("AppOne", out _));
    }

    [Fact]
    public void ProductIdCache_ClearsItselfInsteadOfGrowingPastItsBound()
    {
        var cache = new LlmTipProductIdCache();
        for (var i = 0; i < LlmTipProductIdCache.MaximumEntries; i++)
            cache.Set("app-" + i, Guid.NewGuid());
        Assert.Equal(LlmTipProductIdCache.MaximumEntries, cache.Count);

        cache.Set("one-more", Guid.NewGuid());

        Assert.Equal(1, cache.Count);
        Assert.True(cache.TryGet("one-more", out _));
    }

    [Fact]
    public async Task PostUsage_WhenClientAlreadyClosedTheConnection_StoresTheEventAndAnswers499WithoutError()
    {
        var options = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;
        var dbFactory = new Mock<IDbContextFactory<LicenseDbContext>>();
        dbFactory.Setup(f => f.CreateDbContextAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(() => new LicenseDbContext(options));
        var controller = new LlmTipFeedbackController(
            new LlmTipFeedbackService(dbFactory.Object),
            apiKeyAuth: null!,
            dbFactory.Object,
            NullLogger<LlmTipFeedbackController>.Instance);
        // Reproduces the incident: the request token was already cancelled when the action started,
        // because the client had given up waiting. Before the fix the first query threw and the
        // action answered 503 without storing anything.
        using var aborted = new CancellationTokenSource();
        aborted.Cancel();
        controller.ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext { RequestAborted = aborted.Token }
        };

        var result = await controller.PostUsage(new LlmTipFeedbackUsageRequest
        {
            AppName = "AppOne",
            SchemaVersion = "1",
            EventName = "llm_tip_searched"
        });

        var status = Assert.IsType<StatusCodeResult>(result);
        Assert.Equal(LlmTipFeedbackController.ClientClosedRequestStatusCode, status.StatusCode);
        await using var db = new LicenseDbContext(options);
        Assert.Equal("llm_tip_searched", (await db.LlmTipFeedbackEvents.SingleAsync()).EventName);
    }

    /// <summary>Test clock moved forward explicitly, so cache expiry is checked without waiting.</summary>
    private sealed class ManualTimeProvider(DateTimeOffset start) : TimeProvider
    {
        private DateTimeOffset _now = start;

        /// <inheritdoc/>
        public override DateTimeOffset GetUtcNow() => _now;

        /// <summary>Moves the clock forward by <paramref name="delta"/>.</summary>
        public void Advance(TimeSpan delta) => _now += delta;
    }
}
