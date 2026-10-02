using System.Net;
using System.Text.Json;
using System.Net.Http.Json;
using System.Reflection;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Npgsql;
using SoftLicence.Server.Controllers;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>Real local HTTP/PG evidence for additive migrations, atomic paid issuance, races and authority preservation.</summary>
public sealed class PersonalDayPassPostgreSqlTests
{
    /// <summary>Representative fixture values; production capability authority remains in the persisted catalogue.</summary>
    private static readonly IReadOnlyDictionary<string, string> FixturePaidFeatures = new Dictionary<string, string>(StringComparer.Ordinal)
    {
        ["CanDisablePrefix"] = "true", ["edition"] = "PRO", ["hasAi"] = "true", ["hasApi"] = "true",
        ["hasBugtrace"] = "true", ["hasCustomDocs"] = "true", ["hasMcp"] = "true", ["hasOpenApi"] = "true",
        ["hasPLCSim"] = "true", ["hasPrefix"] = "false", ["hasReports"] = "true", ["hasVcs"] = "true",
        ["hasTestHarness"] = "true", ["hasPatterns"] = "true", ["hasPipelines"] = "true", ["hasCodesys"] = "true",
        ["hasClassroom"] = "true", ["hasRemoteAccess"] = "true", ["hasRemoteArtifacts"] = "true",
        ["maxOpenProjects"] = "0", ["allowOffline"] = "false", ["maintenanceDurationDays"] = "365",
        ["maxApiPerDay"] = "true", ["maxApiPerHour"] = "true", ["maxCopilotPerDay"] = "true",
        ["maxCopilotPerHour"] = "true", ["maxMajorVersion"] = "2", ["maxMcpPerDay"] = "true",
        ["maxMcpPerHour"] = "true", ["version"] = "2"
    };

    /// <summary>New paid keys use the type policy; changing the type later never widens an existing key on renewal.</summary>
    [Theory]
    [InlineData("2.*")]
    [InlineData("2.4.50")]
    public async Task ProviderOwnsInitialAndRenewalVersionPolicy(string mask)
    {
        await using var f = await Fixture.CreateAsync();
        await using (var db = f.Db())
        {
            (await db.LicenseTypes.SingleAsync()).DefaultAllowedVersions = mask;
            await db.SaveChangesAsync();
        }
        var request = f.Request() with { AllowedVersions = null };
        var issued = await f.ReadResponseAsync(request);
        await using (var db = f.Db())
        {
            Assert.Equal(mask, (await db.Licenses.SingleAsync()).AllowedVersions);
            (await db.LicenseTypes.SingleAsync()).DefaultAllowedVersions = "*";
            await db.SaveChangesAsync();
        }
        var replay = await f.ReadResponseAsync(request);
        var renewed = await f.ReadResponseAsync(f.Extend(f.Request() with { AllowedVersions = null }, replay));
        Assert.Equal(issued.LicenseKey, renewed.LicenseKey);
        await using var verify = f.Db();
        Assert.Equal(mask, (await verify.Licenses.SingleAsync()).AllowedVersions);
        Assert.Equal(2, await verify.PersonalDayPassPayments.CountAsync());
    }

    /// <summary>A legacy Website assertion cannot override provider policy, including Portal labels or a wider wildcard.</summary>
    [Theory]
    [InlineData("V20,V21")]
    [InlineData("V17,V18,V19,V20,V21")]
    [InlineData("*")]
    public async Task WebsiteCannotChooseApplicationPolicy(string assertion)
    {
        await using var f = await Fixture.CreateAsync();
        using var response = await f.PostAsync(f.Request() with { AllowedVersions = assertion });
        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        await using var db = f.Db();
        Assert.Equal(0, await db.Licenses.CountAsync());
        Assert.Equal(0, await db.PersonalDayPassPayments.CountAsync());
    }

    /// <summary>The bounded type endpoints return one scoped contract and never require the complete catalogue.</summary>
    [Fact]
    public async Task ExactLicenseTypeReadsAreProductScoped()
    {
        await using var f = await Fixture.CreateAsync();
        var request = f.Request();
        Assert.Equal("products/{productName}/license-types/by-slug/{slug}",
            typeof(AdminController).GetMethod(nameof(AdminController.GetLicenseTypeBySlug))!.GetCustomAttribute<HttpGetAttribute>()!.Template);
        Assert.Equal("products/{productName}/license-types/by-id/{typeId:guid}",
            typeof(AdminController).GetMethod(nameof(AdminController.GetLicenseTypeById))!.GetCustomAttribute<HttpGetAttribute>()!.Template);
        var (bySlug, byId) = await f.ReadExactTypesAsync(PersonalDayPassPolicy.TypeSlug, request.LicenseTypeId);
        var slugBody = Assert.IsType<OkObjectResult>(bySlug).Value;
        using var slugJson = JsonDocument.Parse(JsonSerializer.Serialize(slugBody));
        Assert.Equal(request.LicenseTypeId, slugJson.RootElement.GetProperty("Id").GetGuid());
        Assert.Equal(PersonalDayPassPolicy.TypeSlug, slugJson.RootElement.GetProperty("Slug").GetString());
        var idBody = Assert.IsType<OkObjectResult>(byId).Value;
        using var idJson = JsonDocument.Parse(JsonSerializer.Serialize(idBody));
        Assert.Equal(request.LicenseTypeId, idJson.RootElement.GetProperty("Id").GetGuid());
        Assert.IsType<NotFoundObjectResult>((await f.ReadExactTypesAsync("missing", Guid.NewGuid())).BySlug);
        Assert.IsType<NotFoundObjectResult>((await f.ReadExactTypesAsync(PersonalDayPassPolicy.TypeSlug.ToLowerInvariant(), Guid.NewGuid())).BySlug);
        Assert.IsType<NotFoundObjectResult>((await f.ReadExactTypesAsync(PersonalDayPassPolicy.TypeSlug, Guid.NewGuid(), f.ProductName.ToUpperInvariant())).ById);
        Assert.IsType<NotFoundObjectResult>((await f.ReadExactTypesAsync(PersonalDayPassPolicy.TypeSlug, Guid.NewGuid())).ById);
    }

    /// <summary>The persisted Pro catalogue owns feature values while structural issuance guards remain fail-closed.</summary>
    [Fact]
    public async Task ProductionFeatureValuesRemainAuthoritativeForPaidIssuance()
    {
        await using var f = await Fixture.CreateAsync();
        await using (var db = f.Db())
        {
            var parameters = await db.LicenseTypeCustomParams.ToDictionaryAsync(parameter => parameter.Key);
            parameters["hasPrefix"].Value = "true";
            parameters["maxOpenProjects"].Value = "3";
            await db.SaveChangesAsync();
        }

        var request = f.Request();
        var issued = await f.ReadResponseAsync(request);
        var replay = await f.ReadResponseAsync(request);
        Assert.True(replay.Idempotent);
        Assert.Equal(issued.LicenseId, replay.LicenseId);
        Assert.Equal(issued.LicenseKey, replay.LicenseKey);

        await using var verify = f.Db();
        Assert.Equal(1, await verify.Licenses.CountAsync());
        Assert.Equal(1, await verify.PersonalDayPassPayments.CountAsync());
        Assert.Equal(1, await verify.PersonalDayPassOperations.CountAsync());
    }

    /// <summary>Disabling new activations refuses a new key but preserves paid extension of an existing key.</summary>
    [Fact]
    public async Task DisableNewActivationsDoesNotBlockExistingPaidExtension()
    {
        await using var existing = await Fixture.CreateAsync();
        var first = await existing.ReadResponseAsync(existing.Request());
        await using (var db = existing.Db())
        {
            var type = await db.LicenseTypes.SingleAsync();
            type.DisableNewActivations = true;
            await db.SaveChangesAsync();
        }
        var extended = await existing.ReadResponseAsync(existing.Extend(
            existing.Request() with { PaymentId = "disabled-new-extension" }, first));
        Assert.Equal(first.LicenseId, extended.LicenseId);
        Assert.Equal(first.LicenseKey, extended.LicenseKey);

        await using var fresh = await Fixture.CreateAsync();
        await using (var db = fresh.Db())
        {
            var type = await db.LicenseTypes.SingleAsync();
            type.DisableNewActivations = true;
            await db.SaveChangesAsync();
        }
        using var refused = await fresh.PostAsync(fresh.Request());
        Assert.Equal(HttpStatusCode.Conflict, refused.StatusCode);
    }

    /// <summary>Paid priority support follows its exact FIFO day and never changes seats, key, or duration.</summary>
    [Fact]
    public async Task PrioritySupportMaterializesOnlyForItsPaidFifoPeriod()
    {
        await using var f = await Fixture.CreateAsync();
        var supported = f.Request() with { PrioritySupport = true, AmountMinor = 3420 };
        var first = await f.ReadResponseAsync(supported);
        Assert.True(first.PeriodPrioritySupport);
        Assert.False(first.CurrentPrioritySupport);
        await f.ActivateAsync(first.LicenseKey, "A6D3EED100000010");
        first = await f.ReadResponseAsync(supported);
        var plain = f.Extend(f.Request() with { PaymentId = "plain-after-support", PaidAtUtc = supported.PaidAtUtc.AddSeconds(1) }, first);
        var second = await f.ReadResponseAsync(plain);
        Assert.False(second.PeriodPrioritySupport);
        Assert.True(second.CurrentPrioritySupport);
        await using var db = f.Db();
        var key = (await db.Licenses.AsNoTracking().SingleAsync()).LicenseKey;
        await f.MaterializeSeatsAsync(first.CurrentExpirationUtc!.Value);
        var pass = await db.PersonalDayPasses.AsNoTracking().SingleAsync();
        var license = await db.Licenses.AsNoTracking().SingleAsync();
        Assert.False(pass.CurrentPrioritySupport);
        Assert.Equal(key, license.LicenseKey);
        Assert.Equal(3, license.MaxSeats);
        Assert.Equal(pass.InitialPaidThroughUtc!.Value.AddDays(2), license.ExpirationDate);
    }

    /// <summary>Late monthly evidence moves the later daily seat boundary without rewriting either historical receipt.</summary>
    [Fact]
    public async Task LateMonthlyPaymentProjectsSeatsAtBothRealFifoBoundaries()
    {
        await using var f = await Fixture.CreateAsync();
        var monthlyStart = Fixture.PaidAt.AddDays(-1);
        var existing = await f.SeedExistingPaidLicenseAsync(monthlyStart.AddDays(-1), 2);
        var day = f.Request() with { PaymentId = "later-day", MaxSeats = 1, AmountMinor = 1000 };
        var issued = await f.ReadResponseAsync(day);
        var monthly = f.Extend(f.Request() with { PaymentId = "earlier-month", PaidAtUtc = monthlyStart,
            MaxSeats = 4, AmountMinor = 59_600, Offer = "subscription", DurationSeconds = 30 * 86_400 }, issued);
        var appended = await f.ReadResponseAsync(monthly);
        await using var db = f.Db();
        var receipts = await db.PersonalDayPassOperations.AsNoTracking().OrderBy(row => row.Id).ToListAsync();
        await f.MaterializeSeatsAsync(monthlyStart);
        Assert.Equal(4, (await db.Licenses.AsNoTracking().SingleAsync()).MaxSeats);
        // This is the obsolete daily receipt boundary, now inside the earlier monthly period.
        await f.MaterializeSeatsAsync(day.PaidAtUtc);
        Assert.Equal(4, (await db.Licenses.AsNoTracking().SingleAsync()).MaxSeats);
        await f.MaterializeSeatsAsync(monthlyStart.AddDays(30).AddTicks(-1));
        Assert.Equal(4, (await db.Licenses.AsNoTracking().SingleAsync()).MaxSeats);
        await f.MaterializeSeatsAsync(monthlyStart.AddDays(30));
        var current = await db.Licenses.AsNoTracking().SingleAsync();
        Assert.Equal(1, current.MaxSeats);
        Assert.Equal(existing.Id, current.Id);
        Assert.Equal(existing.LicenseKey, current.LicenseKey);
        Assert.Equal(monthlyStart.AddDays(31), current.ExpirationDate);
        Assert.Equal(appended.CurrentExpirationUtc, current.ExpirationDate);
        var after = await db.PersonalDayPassOperations.AsNoTracking().OrderBy(row => row.Id).ToListAsync();
        Assert.Equal(receipts.Select(row => (row.Id, row.PeriodStartsAtUtc, row.PeriodExpiresAtUtc, row.PaidThroughUtc)),
            after.Select(row => (row.Id, row.PeriodStartsAtUtc, row.PeriodExpiresAtUtc, row.PaidThroughUtc)));
    }

    /// <summary>The first pass and a legacy renewal contend before reading authority, preserving both paid durations.</summary>
    [Fact]
    public async Task FirstPassConcurrentLegacyRenewalPreservesBothDurations()
    {
        await using var f = await Fixture.CreateAsync();
        var expiry = Fixture.PaidAt.AddDays(30);
        var existing = await f.SeedExistingPaidLicenseAsync(expiry, 2);
        await using var writer = f.Db();
        await using var transaction = await writer.Database.BeginTransactionAsync();
        await writer.Database.ExecuteSqlRawAsync("SELECT pg_advisory_xact_lock(999831, 1)");
        var paidRequest = f.PostAsync(f.Request());
        await f.WaitForGlobalLockAsync();
        var renewalRequest = f.Client.PostAsJsonAsync($"/api/admin/licenses/{existing.LicenseKey}/renew", new
        {
            TransactionId = "first-pass-concurrent-renewal", DaysToAdd = 30
        });
        // The old path waits inside its UPDATE trigger after its stale read; the corrected path waits before reading.
        await f.WaitForGlobalLockAsync(2, includeLicenseUpdate: true);
        await transaction.CommitAsync();
        using var paidResponse = await paidRequest;
        using var renewalResponse = await renewalRequest;
        Assert.Equal(HttpStatusCode.OK, paidResponse.StatusCode);
        Assert.Equal(HttpStatusCode.OK, renewalResponse.StatusCode);
        await using var db = f.Db();
        var pass = await db.PersonalDayPasses.AsNoTracking().SingleAsync();
        var license = await db.Licenses.AsNoTracking().SingleAsync();
        Assert.Equal(expiry.AddDays(31), license.ExpirationDate);
        Assert.Equal(license.ExpirationDate, pass.PaidThroughUtc);
        Assert.Equal(existing.Id, license.Id);
        Assert.Equal(existing.LicenseKey, license.LicenseKey);
        Assert.Equal(1, await db.LicenseRenewals.CountAsync());
        Assert.Equal(1, await db.PersonalDayPassPayments.CountAsync());
    }

    /// <summary>Late expired evidence cannot replace seats or priority support belonging to the current paid interval.</summary>
    [Fact]
    public async Task LateExpiredPaymentPreservesCurrentSeatAndSupportInterval()
    {
        await using var f = await Fixture.CreateAsync();
        await f.SeedExistingPaidLicenseAsync(Fixture.PaidAt.AddDays(-5), 2);
        var currentRequest = f.Request() with { PrioritySupport = true, AmountMinor = 3420 };
        var current = await f.ReadResponseAsync(currentRequest);
        Assert.Equal(3, current.CurrentMaxSeats);
        Assert.True(current.CurrentPrioritySupport);
        var lateRequest = f.Extend(f.Request() with { PaidAtUtc = currentRequest.PaidAtUtc.AddDays(-3),
            PaymentId = "late-expired-one-seat", MaxSeats = 1, AmountMinor = 1000 }, current);
        var late = await f.ReadResponseAsync(lateRequest);
        Assert.True(late.PeriodExpiresAtUtc < currentRequest.PaidAtUtc);
        Assert.Equal(current.LicenseKey, late.LicenseKey);
        Assert.Equal(current.CurrentExpirationUtc, late.CurrentExpirationUtc);
        Assert.Equal(3, late.CurrentMaxSeats);
        Assert.True(late.CurrentPrioritySupport);
        Assert.False(late.PeriodPrioritySupport);
    }

    /// <summary>A monthly cycle can renew a key born as a pass, and a later day still queues after that paid horizon.</summary>
    [Fact]
    public async Task DayPassFirstThenSubscriptionRenewalAndDayRemainFifo()
    {
        await using var f = await Fixture.CreateAsync();
        var day = f.Request();
        var issued = await f.ReadResponseAsync(day);
        await f.ActivateAsync(issued.LicenseKey, "A6D3EED100000011");
        issued = await f.ReadResponseAsync(day);
        var subscription = f.Extend(f.Request() with { PaymentId = "monthly-after-initial-day", MaxSeats = 3,
            AmountMinor = 44_700, Offer = "subscription", DurationSeconds = 30 * 86_400,
            PaidAtUtc = day.PaidAtUtc.AddSeconds(1) }, issued);
        var appended = await f.ReadResponseAsync(subscription);
        Assert.Equal(issued.LicenseKey, appended.LicenseKey);
        Assert.Equal(issued.CurrentExpirationUtc, appended.PeriodStartsAtUtc);
        var renewedThrough = appended.PeriodExpiresAtUtc.AddDays(30);
        using var renewal = await f.Client.PostAsJsonAsync($"/api/admin/licenses/{issued.LicenseKey}/renew", new {
            TransactionId = "renew-day-born-key", Reference = "renew-day-born-key", TargetExpirationUtc = renewedThrough,
        });
        Assert.Equal(HttpStatusCode.OK, renewal.StatusCode);
        var current = await f.ReadResponseAsync(subscription);
        Assert.Equal(renewedThrough, current.CurrentExpirationUtc);
        var laterDay = f.Extend(f.Request() with { PaymentId = "day-after-monthly-renewal", MaxSeats = 2,
            AmountMinor = 2_000, PaidAtUtc = day.PaidAtUtc.AddSeconds(2) }, current);
        var final = await f.ReadResponseAsync(laterDay);
        Assert.Equal(issued.LicenseKey, final.LicenseKey);
        Assert.Equal(renewedThrough, final.PeriodStartsAtUtc);
        Assert.Equal(renewedThrough.AddDays(1), final.PeriodExpiresAtUtc);
        // The intervening legacy renewal must not pull the last daily seat change forward.
        await f.MaterializeSeatsAsync(appended.PeriodStartsAtUtc);
        await f.MaterializeSeatsAsync(renewedThrough.AddTicks(-1));
        await using var db = f.Db();
        Assert.Equal(3, (await db.Licenses.AsNoTracking().SingleAsync()).MaxSeats);
        await f.MaterializeSeatsAsync(renewedThrough);
        Assert.Equal(2, (await db.Licenses.AsNoTracking().SingleAsync()).MaxSeats);
    }

    /// <summary>A queued paid day commits before a renewal, whose locked reload must append without losing that day.</summary>
    [Fact]
    public async Task ConcurrentPaidDayThenRenewalPreservesBothDurations()
    {
        await using var f = await Fixture.CreateAsync();
        var first = f.Request();
        var issued = await f.ReadResponseAsync(first);
        await f.ActivateAsync(issued.LicenseKey, "A6D3EED100000012");
        issued = await f.ReadResponseAsync(first);
        var queuedDay = f.Extend(f.Request() with
        {
            PaymentId = "day-before-concurrent-renewal",
            PaidAtUtc = first.PaidAtUtc.AddSeconds(1)
        }, issued);
        await using var writer = f.Db();
        await using var transaction = await writer.Database.BeginTransactionAsync();
        await writer.Database.ExecuteSqlRawAsync("SELECT pg_advisory_xact_lock(999831, 1)");
        var paidRequest = f.PostAsync(queuedDay);
        await f.WaitForGlobalLockAsync();
        var renewalRequest = f.Client.PostAsJsonAsync($"/api/admin/licenses/{issued.LicenseKey}/renew", new
        {
            TransactionId = "renew-after-concurrent-day",
            Reference = "renew-after-concurrent-day",
            DaysToAdd = 30
        });
        await f.WaitForGlobalLockAsync(2);
        await transaction.CommitAsync();
        using var paidResponse = await paidRequest;
        using var renewalResponse = await renewalRequest;
        Assert.Equal(HttpStatusCode.OK, paidResponse.StatusCode);
        Assert.Equal(HttpStatusCode.OK, renewalResponse.StatusCode);
        await using var db = f.Db();
        var pass = await db.PersonalDayPasses.AsNoTracking().SingleAsync();
        var license = await db.Licenses.AsNoTracking().SingleAsync();
        Assert.Equal(pass.InitialPaidThroughUtc!.Value.AddDays(32), pass.PaidThroughUtc);
        Assert.Equal(pass.PaidThroughUtc, license.ExpirationDate);
        Assert.Equal(2, await db.PersonalDayPassPayments.CountAsync());
        Assert.Equal(1, await db.LicenseRenewals.CountAsync());
    }

    /// <summary>Forty simultaneous transport replays must create only one attributed key/payment/receipt.</summary>
    [Fact]
    public async Task ConcurrentReplayIssuesOneKeyAndPreservesExactPaidExpiry()
    {
        await using var f = await Fixture.CreateAsync();
        var request = f.Request();
        var calls = await Task.WhenAll(Enumerable.Range(0, 40).Select(_ => f.PostAsync(request)));
        foreach (var response in calls) { using (response) Assert.Equal(HttpStatusCode.OK, response.StatusCode); }
        var receipt = await f.ReadResponseAsync(request);
        Assert.Null(receipt.CurrentExpirationUtc);
        Assert.False(receipt.CurrentUsable);
        await using var db = f.Db();
        Assert.Equal(1, await db.PersonalDayPasses.CountAsync());
        Assert.Equal(1, await db.PersonalDayPassPayments.CountAsync());
        Assert.Equal(1, await db.PersonalDayPassOperations.CountAsync());
        var license = await db.Licenses.SingleAsync();
        Assert.Null(license.ValidityDays);
        Assert.Null(license.ActivationDate);
        Assert.Equal(3, license.MaxSeats);
        Assert.Equal("2.*", license.AllowedVersions);
        Assert.Equal("buyer@example.test", license.CustomerEmail);
        Assert.Equal("Synthetic buyer", license.CustomerName);
        Assert.Equal(LicenseProvisioningRequest.ProviderAdminApiProvenance, (await db.LicenseProvisioningRequests.SingleAsync()).AuthorityProvenance);
        Assert.Equal(request.CommercialSubjectId, (await db.RuntimeRecoveryCommercialOwnerships.SingleAsync()).OwnerSubjectId);
        Assert.False(db.Database.HasPendingModelChanges());
    }

    /// <summary>The first accepted software seat starts all already paid time and preserves later FIFO seat boundaries.</summary>
    [Fact]
    public async Task FirstActivationStartsDeferredPaidTimeAndQueuedSeatsOnTheSameKey()
    {
        await using var f = await Fixture.CreateAsync();
        var firstRequest = f.Request();
        var first = await f.ReadResponseAsync(firstRequest);
        Assert.True(first.CurrentPendingFirstActivation);
        Assert.Null(first.CurrentLedgerAnchorUtc);
        Assert.False(first.CurrentUsable);
        Assert.False(await f.HasAnyActivationAsync(first.LicenseKey));
        var queuedRequest = f.Extend(f.Request() with
        {
            PaymentId = "queued-before-first-activation",
            PaidAtUtc = firstRequest.PaidAtUtc.AddSeconds(1),
            MaxSeats = 5,
            AmountMinor = 5_000
        }, first);
        var queued = await f.ReadResponseAsync(queuedRequest);
        Assert.Equal(first.LicenseKey, queued.LicenseKey);
        Assert.Null(queued.CurrentExpirationUtc);
        Assert.True(queued.CurrentPendingFirstActivation);
        Assert.True((await f.ReadResponseAsync(firstRequest)).CurrentPendingFirstActivation);

        await using (var before = f.Db())
        {
            var pending = await before.Licenses.AsNoTracking().SingleAsync();
            Assert.Null(pending.ExpirationDate);
            Assert.Null(pending.ActivationDate);
            Assert.Equal(0, await before.LicenseSeats.CountAsync());
        }

        await Task.WhenAll(
            f.ActivateAsync(first.LicenseKey, "A6D3EED100000001"),
            f.ActivateAsync(first.LicenseKey, "A6D3EED100000001"));

        await using var db = f.Db();
        var pass = await db.PersonalDayPasses.AsNoTracking().SingleAsync();
        var license = await db.Licenses.AsNoTracking().SingleAsync();
        var seat = await db.LicenseSeats.AsNoTracking().SingleAsync();
        Assert.NotNull(pass.InitialPaidThroughUtc);
        Assert.Equal(first.LicenseKey, license.LicenseKey);
        Assert.Equal(pass.InitialPaidThroughUtc!.Value.AddDays(2), pass.PaidThroughUtc);
        Assert.Equal(pass.PaidThroughUtc, license.ExpirationDate);
        Assert.InRange((seat.FirstActivatedAt - pass.InitialPaidThroughUtc.Value).Duration(),
            TimeSpan.Zero, TimeSpan.FromMilliseconds(1));
        Assert.Equal(3, license.MaxSeats);
        var firstActivationExpiry = license.ExpirationDate;
        await f.ActivateAsync(first.LicenseKey, "A6D3EED100000001");
        Assert.Equal(firstActivationExpiry, (await db.Licenses.AsNoTracking().SingleAsync()).ExpirationDate);
        Assert.Equal(1, await db.LicenseHistories.CountAsync(history =>
            history.Action == "PERSONAL_PASS_FIRST_ACTIVATION_STARTED"));
        var activated = await f.ReadResponseAsync(firstRequest);
        Assert.False(activated.CurrentPendingFirstActivation);
        Assert.True(activated.CurrentUsable);
        Assert.Equal(pass.InitialPaidThroughUtc, activated.CurrentLedgerAnchorUtc);
        Assert.Equal(first.HistoricalPaidThroughUtc, activated.HistoricalPaidThroughUtc);
        Assert.Equal(first.HistoricalAuthorityVersion, activated.HistoricalAuthorityVersion);
        Assert.True(await f.HasAnyActivationAsync(first.LicenseKey));

        await f.MaterializeSeatsAsync(pass.InitialPaidThroughUtc.Value.AddDays(1));
        Assert.Equal(5, (await db.Licenses.AsNoTracking().SingleAsync()).MaxSeats);
        Assert.Equal(first.LicenseKey, (await db.Licenses.AsNoTracking().SingleAsync()).LicenseKey);
    }

    /// <summary>
    /// A false null expiry, released seat, changed paid type, or ended owner must deny deferred authority
    /// in both the real replay route and activation service. Historical receipts remain byte-equivalent.
    /// </summary>
    [Theory]
    [InlineData("false-null")]
    [InlineData("historical-seat")]
    [InlineData("changed-type")]
    [InlineData("ended-owner")]
    public async Task InvalidDeferredAuthorityNeverReopensPaidTime(string mutation)
    {
        await using var f = await Fixture.CreateAsync();
        var request = f.Request();
        var issued = await f.ReadResponseAsync(request);
        Assert.True(issued.CurrentPendingFirstActivation);
        await using var db = f.Db();
        var historical = JsonSerializer.Serialize(await db.PersonalDayPassOperations.AsNoTracking().SingleAsync());
        if (mutation == "false-null")
        {
            await db.Database.ExecuteSqlInterpolatedAsync($"UPDATE \"Licenses\" SET \"ExpirationDate\" = now() WHERE \"Id\" = {issued.LicenseId}");
            await db.Database.ExecuteSqlInterpolatedAsync($"UPDATE \"Licenses\" SET \"ExpirationDate\" = NULL WHERE \"Id\" = {issued.LicenseId}");
        }
        else if (mutation == "historical-seat")
        {
            db.LicenseSeats.Add(new LicenseSeat { LicenseId = issued.LicenseId, HardwareId = "A6D3EED100000099",
                IsActive = false, FirstActivatedAt = DateTime.UtcNow.AddDays(-1), UnlinkedAt = DateTime.UtcNow });
            await db.SaveChangesAsync();
        }
        else if (mutation == "changed-type")
        {
            var type = await db.LicenseTypes.SingleAsync();
            type.IsFree = true;
            await db.SaveChangesAsync();
        }
        else
        {
            var owner = await db.RuntimeRecoveryCommercialOwnerships.SingleAsync();
            owner.State = "REVOKED";
            owner.EndedAtUtc = DateTime.UtcNow;
            await db.SaveChangesAsync();
        }
        var replay = await f.ReadResponseAsync(request);
        Assert.False(replay.CurrentPendingFirstActivation);
        Assert.False(replay.CurrentUsable);
        Assert.Null(replay.CurrentExpirationUtc);
        Assert.Equal(mutation == "historical-seat", await f.HasAnyActivationAsync(issued.LicenseKey));
        Assert.Equal(issued.HistoricalAuthorityVersion, replay.HistoricalAuthorityVersion);
        Assert.Equal(historical, JsonSerializer.Serialize(await db.PersonalDayPassOperations.AsNoTracking().SingleAsync()));
        var license = await db.Licenses.SingleAsync();
        await Assert.ThrowsAsync<InvalidOperationException>(() => PersonalDayPassActivationService.StartPendingAsync(
            db, license, DateTime.UtcNow, "synthetic-negative-proof", CancellationToken.None));
        using var extension = await f.PostAsync(f.Extend(f.Request(), replay));
        Assert.Equal(HttpStatusCode.Conflict, extension.StatusCode);
        Assert.Equal(1, await db.PersonalDayPassPayments.CountAsync());
        Assert.Null((await db.PersonalDayPasses.AsNoTracking().SingleAsync()).InitialPaidThroughUtc);
    }

    /// <summary>A personal day pass queues behind an existing paid offer and keeps its key and current seats until the boundary.</summary>
    [Fact]
    public async Task ExistingMonthlyKeyIsReusedAndFutureSeatChangeDoesNotApplyEarly()
    {
        await using var f = await Fixture.CreateAsync();
        var existing = await f.SeedExistingPaidLicenseAsync(Fixture.PaidAt.AddDays(30), 2);
        var request = f.Request() with { MaxSeats = 5, AmountMinor = 5000 };
        var receipt = await f.ReadResponseAsync(request);
        Assert.Equal(existing.LicenseKey, receipt.LicenseKey);
        Assert.Equal(existing.Id, receipt.LicenseId);
        Assert.Equal(existing.LicenseTypeId, receipt.CurrentLicenseTypeId);
        Assert.Equal(2, receipt.CurrentMaxSeats);
        Assert.Equal(existing.ExpirationDate, receipt.PeriodStartsAtUtc);
        Assert.Equal(existing.ExpirationDate!.Value.AddDays(1), receipt.PeriodExpiresAtUtc);
        Assert.Equal(existing.ExpirationDate.Value.AddDays(1), receipt.CurrentExpirationUtc);
        await using var db = f.Db();
        var license = await db.Licenses.AsNoTracking().SingleAsync();
        Assert.Equal(2, license.MaxSeats);
        Assert.Equal(existing.LicenseTypeId, license.LicenseTypeId);
        Assert.Equal(5, (await db.PersonalDayPassPayments.AsNoTracking().SingleAsync()).MaxSeats);
        Assert.Equal(1, await f.MaterializeSeatsAsync(receipt.PeriodStartsAtUtc));
        var activated = await db.Licenses.AsNoTracking().SingleAsync();
        Assert.Equal(existing.LicenseKey, activated.LicenseKey);
        Assert.Equal(5, activated.MaxSeats);

        var current = await f.ReadResponseAsync(request);
        var monthly = f.Extend(f.Request() with { LicenseTypeId = current.CurrentLicenseTypeId,
            PaymentId = "monthly-after-day", MaxSeats = 4, AmountMinor = 59_600,
            Offer = "subscription", DurationSeconds = 30 * 86_400,
            PaidAtUtc = request.PaidAtUtc.AddSeconds(1) }, current);
        var extended = await f.ReadResponseAsync(monthly);
        Assert.Equal(existing.LicenseKey, extended.LicenseKey);
        Assert.Equal(receipt.PeriodExpiresAtUtc, extended.PeriodStartsAtUtc);
        Assert.Equal(receipt.PeriodExpiresAtUtc.AddDays(30), extended.PeriodExpiresAtUtc);
        Assert.Equal(5, extended.CurrentMaxSeats);
        Assert.Equal(1, await f.MaterializeSeatsAsync(extended.PeriodStartsAtUtc));
        Assert.Equal(4, (await db.Licenses.AsNoTracking().SingleAsync()).MaxSeats);
        Assert.Equal(existing.LicenseKey, (await db.Licenses.AsNoTracking().SingleAsync()).LicenseKey);
    }

    /// <summary>Reverse delivery and a second event for the same canonical payment cannot manufacture a day.</summary>
    [Fact]
    public async Task LatePaymentsPersistChronologicallyAndHistoricalReplayDoesNotRewriteAuthority()
    {
        await using var f = await Fixture.CreateAsync();
        var b = f.Request() with { PaidAtUtc = Fixture.PaidAt.AddDays(-3), PaymentId = "B" };
        var issued = await f.ReadResponseAsync(b);
        var a = f.Extend(f.Request() with { PaidAtUtc = b.PaidAtUtc.AddDays(-3), PaymentId = "A" }, issued);
        var late = await f.ReadResponseAsync(a);
        Assert.Equal(issued.LicenseKey, late.LicenseKey);
        Assert.Null(late.CurrentExpirationUtc);
        Assert.False(late.CurrentUsable);
        Assert.Equal(a.PaidAtUtc, late.PeriodStartsAtUtc);
        var replay = await f.ReadResponseAsync(b);
        Assert.True(replay.Idempotent);
        Assert.Equal(issued.HistoricalPaidThroughUtc, replay.HistoricalPaidThroughUtc);
        var duplicateEvent = await f.ReadResponseAsync(b with { OperationId = Guid.NewGuid() });
        Assert.True(duplicateEvent.Idempotent);
        await using var db = f.Db();
        Assert.Equal(2, await db.PersonalDayPassPayments.CountAsync());
    }

    /// <summary>Distinct simultaneous purchases resolve through CAS; a new observation adds the losing payment once.</summary>
    [Fact]
    public async Task DistinctPaymentsRaceWithoutLosingPaidTimeOrCreatingSecondKey()
    {
        await using var f = await Fixture.CreateAsync();
        var first = f.Request();
        var issued = await f.ReadResponseAsync(first);
        var a = f.Extend(f.Request() with { PaymentId = "A" }, issued);
        var b = f.Extend(f.Request() with { PaymentId = "B" }, issued);
        var results = await Task.WhenAll(f.PostAsync(a), f.PostAsync(b));
        Assert.Equal(1, results.Count(r => r.StatusCode == HttpStatusCode.OK));
        Assert.Equal(1, results.Count(r => r.StatusCode == HttpStatusCode.Conflict));
        var lost = results[0].StatusCode == HttpStatusCode.Conflict ? a : b;
        foreach (var result in results) result.Dispose();
        var observed = await f.ReadResponseAsync(first);
        var final = await f.ReadResponseAsync(f.Extend(lost with { OperationId = Guid.NewGuid() }, observed));
        Assert.Null(final.CurrentExpirationUtc);
        await f.ActivateAsync(final.LicenseKey, "A6D3EED100000013");
        await using var db = f.Db();
        Assert.Equal((await db.PersonalDayPasses.AsNoTracking().SingleAsync()).InitialPaidThroughUtc!.Value.AddDays(3),
            (await db.Licenses.AsNoTracking().SingleAsync()).ExpirationDate);
        Assert.Equal(issued.LicenseKey, final.LicenseKey);
    }

    /// <summary>Revocation and ABA invalidate new grants; replay reports history without undoing either transition.</summary>
    [Fact]
    public async Task RevocationAbaAndChangedPayloadNeverReactivateOrResetRights()
    {
        await using var f = await Fixture.CreateAsync();
        var first = f.Request();
        var issued = await f.ReadResponseAsync(first);
        await using var db = f.Db();
        await db.Database.ExecuteSqlInterpolatedAsync($"UPDATE \"Licenses\" SET \"IsActive\" = false, \"RevocationReason\" = 'security', \"RevokedAt\" = now() WHERE \"Id\" = {issued.LicenseId}");
        using var denied = await f.PostAsync(f.Extend(f.Request(), issued));
        Assert.Equal(HttpStatusCode.Conflict, denied.StatusCode);
        var replay = await f.ReadResponseAsync(first);
        Assert.False(replay.CurrentUsable);
        Assert.NotEqual(issued.CurrentAuthorityVersion, replay.CurrentAuthorityVersion);
        await db.Database.ExecuteSqlInterpolatedAsync($"UPDATE \"Licenses\" SET \"IsActive\" = true, \"RevocationReason\" = NULL, \"RevokedAt\" = NULL WHERE \"Id\" = {issued.LicenseId}");
        using var aba = await f.PostAsync(f.Extend(f.Request(), issued));
        Assert.Equal(HttpStatusCode.Conflict, aba.StatusCode);
        using var changed = await f.PostAsync(first with { PaymentId = "changed" });
        Assert.Equal(HttpStatusCode.Conflict, changed.StatusCode);
        using var differentMoney = await f.PostAsync(first with { OperationId = Guid.NewGuid(), PaidAtUtc = first.PaidAtUtc.AddSeconds(-1) });
        Assert.Equal(HttpStatusCode.Conflict, differentMoney.StatusCode);
        Assert.Equal(1, await db.PersonalDayPassPayments.CountAsync());
        Assert.Equal(3, (await db.Licenses.AsNoTracking().SingleAsync()).MaxSeats);
    }

    /// <summary>An ownership transfer cannot be bypassed by a stale snapshot or an old payment receipt.</summary>
    [Fact]
    public async Task OwnershipTransferStopsOldSubjectAndKeepsHistoricalReceiptSeparate()
    {
        await using var f = await Fixture.CreateAsync();
        var first = f.Request();
        var issued = await f.ReadResponseAsync(first);
        await using var db = f.Db();
        await using var transaction = await db.Database.BeginTransactionAsync();
        await db.Database.ExecuteSqlRawAsync("SELECT pg_advisory_xact_lock(999831, 1)");
        await db.Database.ExecuteSqlInterpolatedAsync($"SELECT \"Id\" FROM \"Licenses\" WHERE \"Id\" = {issued.LicenseId} FOR UPDATE");
        var previous = await db.RuntimeRecoveryCommercialOwnerships.SingleAsync();
        previous.State = "TRANSFERRED"; previous.EndedAtUtc = DateTime.UtcNow;
        var next = new RuntimeRecoveryCommercialSubject { ProductId = first.ProductId, Id = Guid.NewGuid(), CreatedAtUtc = DateTime.UtcNow };
        db.Add(next); await db.SaveChangesAsync();
        db.Add(new RuntimeRecoveryCommercialOwnership { Id = Guid.NewGuid(), ProductId = first.ProductId, LicenseId = issued.LicenseId,
            OwnerSubjectId = next.Id, PreviousOwnershipId = previous.Id, State = "ACTIVE", CreatedAtUtc = DateTime.UtcNow });
        await db.SaveChangesAsync(); await transaction.CommitAsync();
        using var denied = await f.PostAsync(f.Extend(f.Request(), issued));
        Assert.Equal(HttpStatusCode.Conflict, denied.StatusCode);
        Assert.False((await f.ReadResponseAsync(first)).CurrentUsable);
    }

    /// <summary>Observes an actual blocked payment before committing a competing revocation/ABA in the global lock order.</summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ConcurrentRevocationOrAbaWinsBeforeWaitingPayment(bool aba)
    {
        await using var f = await Fixture.CreateAsync();
        var issued = await f.ReadResponseAsync(f.Request());
        await using var writer = f.Db();
        await using var transaction = await writer.Database.BeginTransactionAsync();
        await writer.Database.ExecuteSqlRawAsync("SELECT pg_advisory_xact_lock(999831, 1)");
        var pending = f.PostAsync(f.Extend(f.Request(), issued));
        await f.WaitForGlobalLockAsync();
        await writer.Database.ExecuteSqlInterpolatedAsync($"UPDATE \"Licenses\" SET \"IsActive\" = false, \"RevocationReason\" = 'concurrent_security', \"RevokedAt\" = now() WHERE \"Id\" = {issued.LicenseId}");
        if (aba)
            await writer.Database.ExecuteSqlInterpolatedAsync($"UPDATE \"Licenses\" SET \"IsActive\" = true, \"RevocationReason\" = NULL, \"RevokedAt\" = NULL WHERE \"Id\" = {issued.LicenseId}");
        await transaction.CommitAsync();
        using var result = await pending;
        Assert.Equal(HttpStatusCode.Conflict, result.StatusCode);
        await using var observer = f.Db();
        Assert.Equal(1, await observer.PersonalDayPassPayments.CountAsync());
        Assert.Equal(issued.CurrentExpirationUtc, (await observer.Licenses.SingleAsync()).ExpirationDate);
    }

    /// <summary>A failure after license creation rolls back provenance, ownership and payment with it.</summary>
    [Fact]
    public async Task ReceiptFailureRollsBackEntireIssuanceAndRetrySucceeds()
    {
        await using var f = await Fixture.CreateAsync();
        await using var db = f.Db();
        await db.Database.ExecuteSqlRawAsync("""
            CREATE FUNCTION tkt991_fail_receipt() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic receipt failure'; END $$;
            CREATE TRIGGER tkt991_fail BEFORE INSERT ON "PersonalDayPassOperations" FOR EACH ROW EXECUTE FUNCTION tkt991_fail_receipt();
            """);
        var request = f.Request();
        // TestServer propagates unhandled server exceptions instead of synthesizing the socket-host 500.
        var failed = await Assert.ThrowsAsync<DbUpdateException>(() => f.PostAsync(request));
        Assert.IsType<PostgresException>(failed.InnerException);
        Assert.Equal(0, await db.Licenses.CountAsync());
        Assert.Equal(0, await db.PersonalDayPassPayments.CountAsync());
        Assert.Equal(0, await db.LicenseProvisioningRequests.CountAsync());
        await db.Database.ExecuteSqlRawAsync("DROP TRIGGER tkt991_fail ON \"PersonalDayPassOperations\"; DROP FUNCTION tkt991_fail_receipt();");
        Assert.False((await f.ReadResponseAsync(request)).Idempotent);
    }

    /// <summary>Exact Unicode identities remain distinct in PG; malformed price and owner attribution are refused.</summary>
    [Fact]
    public async Task DatabaseIdentityPriceAndNullConstraintsAreReal()
    {
        await using var f = await Fixture.CreateAsync();
        var request = f.Request() with { PaymentId = "pi_é😀" };
        var receipt = await f.ReadResponseAsync(request);
        var next = await f.ReadResponseAsync(f.Extend(f.Request() with { PaymentId = "pi_e\u0301😀" }, receipt));
        await f.ReadResponseAsync(f.Extend(f.Request() with { PaymentId = "PI_é😀" }, next));
        using var badPrice = await f.PostAsync(f.Request() with { AmountMinor = 200 });
        Assert.Equal(HttpStatusCode.BadRequest, badPrice.StatusCode);
        using var foreign = await f.PostAsync(request with { OperationId = Guid.NewGuid(), CommercialSubjectId = Guid.NewGuid() });
        Assert.Equal(HttpStatusCode.Conflict, foreign.StatusCode);
        using var falseEmail = await f.PostAsync(request with { OperationId = Guid.NewGuid(), CustomerEmail = "other@example.test" });
        Assert.Equal(HttpStatusCode.Conflict, falseEmail.StatusCode);
        await using var db = f.Db();
        Assert.Equal(3, await db.PersonalDayPassPayments.CountAsync());
        await Assert.ThrowsAsync<PostgresException>(() => db.Database.ExecuteSqlRawAsync("UPDATE \"PersonalDayPassPayments\" SET \"PaidAtUtc\" = NULL"));
        await Assert.ThrowsAsync<PostgresException>(() => db.Database.ExecuteSqlRawAsync("UPDATE \"PersonalDayPassOperations\" SET \"PeriodExpiresAtUtc\" = NULL"));
        await Assert.ThrowsAsync<PostgresException>(() => db.Database.ExecuteSqlRawAsync("UPDATE \"PersonalDayPassPayments\" SET \"AmountMinor\" = 200"));
        await Assert.ThrowsAsync<PostgresException>(() => db.Database.ExecuteSqlRawAsync("UPDATE \"PersonalDayPassOperations\" SET \"PeriodExpiresAtUtc\" = \"PeriodStartsAtUtc\" + interval '1 hour'"));
    }

    /// <summary>Public trial selection cannot create a pass; unsafe type settings and foreign product credentials fail closed.</summary>
    [Fact]
    public async Task PublicTrialAndUnsafeTypesCannotMintPaidTime()
    {
        await using var f = await Fixture.CreateAsync();
        using var trial = await f.Client.PostAsJsonAsync("/api/activation/trial", new { AppName = f.ProductName,
            HardwareId = "tkt991-new-hardware", TypeSlug = PersonalDayPassPolicy.TypeSlug });
        Assert.Contains("PAYMENT_REQUIRED", await trial.Content.ReadAsStringAsync());
        await using var db = f.Db();
        Assert.Equal(0, await db.Licenses.CountAsync());
        var type = await db.LicenseTypes.SingleAsync();
        type.IsRecurring = false; await db.SaveChangesAsync();
        using var unsafeType = await f.PostAsync(f.Request());
        Assert.Equal(HttpStatusCode.Conflict, unsafeType.StatusCode);
        type.IsRecurring = true; type.DisableNewActivations = true; await db.SaveChangesAsync();
        using var disabled = await f.PostAsync(f.Request());
        Assert.Equal(HttpStatusCode.Conflict, disabled.StatusCode);
        var other = new Product { Name = "foreign-" + Guid.NewGuid(), ApiSecret = "tkt991-foreign-product" };
        db.Add(other); await db.SaveChangesAsync();
        f.Client.DefaultRequestHeaders.Remove("X-Admin-Secret");
        f.Client.DefaultRequestHeaders.Add("X-Admin-Secret", other.ApiSecret);
        using var unauthorized = await f.PostAsync(f.Request());
        Assert.Equal(HttpStatusCode.Unauthorized, unauthorized.StatusCode);
    }

    /// <summary>TKT-001217: a customer with no licence at all may buy a paid subscription; it creates the authority.</summary>
    [Fact]
    public async Task FirstPaidSubscriptionWithoutAnyLicenseCreatesTheCommercialAuthority()
    {
        await using var f = await Fixture.CreateAsync();
        await using var empty = f.Db();
        Assert.Equal(0, await empty.Licenses.CountAsync());
        var monthly = f.Request() with { PaymentId = "first-paid-subscription", Offer = "subscription",
            DurationSeconds = 30 * 86_400, AmountMinor = 10_000, MaxSeats = 1 };

        var receipt = await f.ReadResponseAsync(monthly);

        await using var db = f.Db();
        var license = await db.Licenses.AsNoTracking().SingleAsync();
        Assert.Equal(receipt.LicenseKey, license.LicenseKey);
        Assert.Equal(monthly.LicenseTypeId, license.LicenseTypeId);
        Assert.Equal(monthly.CustomerEmail, license.CustomerEmail);
        Assert.Equal(1, license.MaxSeats);
        var owner = await db.RuntimeRecoveryCommercialOwnerships.AsNoTracking().SingleAsync();
        Assert.Equal(monthly.CommercialSubjectId, owner.OwnerSubjectId);
        Assert.Equal("ACTIVE", owner.State);
        Assert.Equal(license.Id, owner.LicenseId);
        Assert.Equal(monthly.PaidAtUtc.AddSeconds(monthly.DurationSeconds), receipt.PeriodExpiresAtUtc);
        // A free, anonymous or non-recurring type still cannot mint a brand-new paid licence.
        await using var toggles = f.Db();
        var type = await toggles.LicenseTypes.SingleAsync();
        type.IsFree = true;
        await toggles.SaveChangesAsync();
        using var freeType = await f.PostAsync(f.Request() with { PaymentId = "free-type-subscription",
            Offer = "subscription", DurationSeconds = 30 * 86_400, CommercialSubjectId = Guid.NewGuid() });
        Assert.Equal(HttpStatusCode.Conflict, freeType.StatusCode);
        type.IsFree = false;
        await toggles.SaveChangesAsync();
    }

    /// <summary>FREE-TRIAL may recover a paid key but cannot extend it, even if an administrator toggles recurring.</summary>
    [Fact]
    public async Task FreeTrialRecoveryPreservesPaidKeyAndExpiredTime()
    {
        await using var f = await Fixture.CreateAsync();
        var request = f.Request() with { PaidAtUtc = Fixture.PaidAt.AddDays(-3) };
        var paid = await f.ReadResponseAsync(request);
        await using var db = f.Db();
        var license = await db.Licenses.SingleAsync();
        license.HardwareId = "ABCDEF1234567890";
        var type = await db.LicenseTypes.SingleAsync();
        type.IsRecurring = true;
        db.Add(new LicenseType { ProductId = request.ProductId, Name = "Historical trial", Slug = "TRIAL", IsFree = true });
        await db.SaveChangesAsync();
        using var response = await f.Client.PostAsJsonAsync("/api/activation", new { AppName = f.ProductName,
            LicenseKey = "FREE-TRIAL", HardwareId = license.HardwareId, AppVersion = "2.2.999" });
        Assert.True(response.StatusCode == HttpStatusCode.OK, await response.Content.ReadAsStringAsync());
        var after = await db.Licenses.AsNoTracking().SingleAsync();
        Assert.Equal(paid.LicenseKey, after.LicenseKey);
        Assert.Equal(paid.CurrentExpirationUtc, after.ExpirationDate);
        Assert.Equal(1, await db.PersonalDayPassPayments.CountAsync());
    }

    /// <summary>Owns one generated database and TestServer; no production configuration or hosted outbound worker is used.</summary>
    private sealed class Fixture : IAsyncDisposable
    {
        /// <summary>Stable synthetic paid instant before this campaign; UTC milliseconds preserve exact assertions.</summary>
        public static readonly DateTime PaidAt = DateTimeOffset.FromUnixTimeMilliseconds(DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() - 10000).UtcDateTime;
        /// <summary>Loopback maintenance connection supplied only by the local disposable container runner.</summary>
        private readonly string maintenance;
        /// <summary>Generated database name, never a supplied existing database.</summary>
        private readonly string database;
        /// <summary>Isolated fixture connection shared by HTTP and observation contexts.</summary>
        private readonly string connection;
        /// <summary>In-process host owns HTTP lifetime.</summary>
        private readonly WebApplicationFactory<Program> host;
        /// <summary>Stable fixture account and product/type identifiers.</summary>
        private readonly Guid subjectId = Guid.NewGuid();
        /// <summary>Fixture-owned product UUID populated only after seed commit.</summary>
        private Guid productId;
        /// <summary>Fixture-owned reserved paid type UUID populated only after seed commit.</summary>
        private Guid typeId;
        /// <summary>Synthetic product name used by public activation routes.</summary>
        public string ProductName => database;
        /// <summary>Authenticated in-process HTTP client; disposed with the fixture.</summary>
        public HttpClient Client { get; }

        /// <summary>Removes all hosted services and replaces all DB registrations before starting the local host.</summary>
        private Fixture(string maintenance, string database, string connection)
        {
            this.maintenance = maintenance; this.database = database; this.connection = connection;
            host = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
            {
                builder.UseEnvironment("Production");
                builder.UseSetting("IsIntegrationTest", "true");
                builder.UseSetting("AdminSettings:ApiSecret", "tkt991-local-synthetic");
                builder.UseSetting("AdminSettings:AllowedIps", string.Empty);
                // Tests own every database and exclude background workers that could contact external services.
                builder.ConfigureServices(services =>
                {
                    services.RemoveAll<IHostedService>();
                    services.RemoveAll<IDataProtectionProvider>();
                    services.AddSingleton<IDataProtectionProvider>(new EphemeralDataProtectionProvider());
                    services.RemoveAll<DbContextOptions<LicenseDbContext>>();
                    services.RemoveAll<IDbContextOptionsConfiguration<LicenseDbContext>>();
                    services.RemoveAll<IDbContextFactory<LicenseDbContext>>();
                    services.RemoveAll<LicenseDbContext>();
                    services.AddDbContextFactory<LicenseDbContext>(options => options.UseNpgsql(connection));
                });
            });
            Client = host.CreateClient();
            Client.DefaultRequestHeaders.Add("X-Admin-Secret", "tkt991-local-synthetic");
        }

        /// <summary>Creates a fresh observer context so assertions never reuse tracked authority snapshots.</summary>
        public LicenseDbContext Db() => new(new DbContextOptionsBuilder<LicenseDbContext>().UseNpgsql(connection).Options);
        /// <summary>Invokes both exact controller reads with a physical fixture context and loopback-only request authority.</summary>
        public async Task<(IActionResult BySlug, IActionResult ById)> ReadExactTypesAsync(string slug, Guid requestedTypeId, string? requestedProduct = null)
        {
            using var scope = host.Services.CreateScope();
            await using var db = Db();
            var controller = ActivatorUtilities.CreateInstance<AdminController>(scope.ServiceProvider, db);
            var http = new DefaultHttpContext { RequestServices = scope.ServiceProvider };
            http.Connection.RemoteIpAddress = IPAddress.Loopback;
            http.Request.Headers["X-Admin-Secret"] = "tkt991-local-synthetic";
            controller.ControllerContext = new ControllerContext { HttpContext = http };
            var product = requestedProduct ?? ProductName;
            return (await controller.GetLicenseTypeBySlug(product, slug), await controller.GetLicenseTypeById(product, requestedTypeId));
        }
        /// <summary>Executes one deterministic worker iteration at a caller-controlled UTC boundary.</summary>
        public Task<int> MaterializeSeatsAsync(DateTime nowUtc) =>
            host.Services.GetRequiredService<PersonalDayPassSeatMaterializationService>().MaterializeAsync(nowUtc);
        /// <summary>Requires observed PG lock contention, so the race test cannot pass merely because a request was slow.</summary>
        public async Task WaitForGlobalLockAsync(int minimumWaiters = 1, bool includeLicenseUpdate = false)
        {
            Assert.InRange(minimumWaiters, 1, 8);
            await using var observer = new NpgsqlConnection(connection);
            await observer.OpenAsync();
            for (var attempt = 0; attempt < 150; attempt++)
            {
                await using var command = new NpgsqlCommand("""
                    SELECT count(*) FROM pg_stat_activity WHERE datname = current_database()
                    AND wait_event_type = 'Lock' AND (query LIKE '%pg_advisory_xact_lock(999831, 1)%'
                        OR (@includeUpdate AND query LIKE '%UPDATE%Licenses%'))
                    """, observer);
                command.Parameters.AddWithValue("includeUpdate", includeLicenseUpdate);
                if (Convert.ToInt64(await command.ExecuteScalarAsync()) >= minimumWaiters) return;
                await Task.Delay(20);
            }
            Assert.Fail($"Expected {minimumWaiters} operation(s) at the held global authority lock.");
        }
        /// <summary>Creates a new immutable synthetic payment with explicit seat/version terms.</summary>
        public AdminController.PersonalDayPassRequest Request() => new(Guid.NewGuid(), productId, subjectId, typeId,
            "stripe", "synthetic-account", "test", "pi_" + Guid.NewGuid(), PaidAt, 3000, "eur", 3, "2.*", "buyer@example.test", "Synthetic buyer");

        /// <summary>Seeds one existing personal commercial authority whose paid monthly horizon precedes the pass.</summary>
        public async Task<License> SeedExistingPaidLicenseAsync(DateTime expirationUtc, int maxSeats)
        {
            await using var db = Db();
            var type = await db.LicenseTypes.SingleAsync(candidate => candidate.Id == typeId);
            var subject = new RuntimeRecoveryCommercialSubject { ProductId = productId, Id = subjectId, CreatedAtUtc = DateTime.UtcNow };
            var license = new License { ProductId = productId, LicenseTypeId = type.Id,
                LicenseKey = Guid.NewGuid().ToString("D").ToUpperInvariant(), ExpirationDate = expirationUtc,
                ValidityDays = null, MaxSeats = maxSeats, AllowedVersions = "2.*",
                CustomerEmail = "buyer@example.test", CustomerName = "Synthetic buyer" };
            var owner = new RuntimeRecoveryCommercialOwnership { Id = Guid.NewGuid(), ProductId = productId,
                LicenseId = license.Id, OwnerSubjectId = subjectId, State = "ACTIVE", CreatedAtUtc = DateTime.UtcNow };
            db.AddRange(subject, license, owner);
            await db.SaveChangesAsync();
            return license;
        }
        /// <summary>Attaches an observed current snapshot; the caller controls whether to allocate a fresh operation UUID.</summary>
        public AdminController.PersonalDayPassRequest Extend(AdminController.PersonalDayPassRequest request, AdminController.PersonalDayPassResponse response) =>
            request with { ExpectedLicenseId = response.LicenseId, ExpectedOwnershipId = response.CurrentOwnershipId,
                ExpectedAuthorityVersion = response.CurrentAuthorityVersion };
        /// <summary>Sends only to TestServer, returning response ownership to the caller.</summary>
        public Task<HttpResponseMessage> PostAsync(AdminController.PersonalDayPassRequest request) => Client.PostAsJsonAsync("/api/admin/personal-day-passes/payments", request);
        /// <summary>Reads the independent exact licence endpoint, including inactive activation history.</summary>
        public async Task<bool> HasAnyActivationAsync(string licenseKey)
        {
            using var response = await Client.GetAsync($"/api/admin/licenses/{licenseKey}");
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            return json.RootElement.GetProperty("hasAnyActivation").GetBoolean();
        }
        /// <summary>Executes one accepted legacy software activation using exact synthetic identity.</summary>
        public async Task ActivateAsync(string licenseKey, string hardwareId)
        {
            using var activation = await Client.PostAsJsonAsync("/api/activation", new
            {
                AppName = ProductName,
                LicenseKey = licenseKey,
                HardwareId = hardwareId,
                AppVersion = "2.3.924",
                CustomerEmail = "buyer@example.test",
                CustomerName = "Synthetic buyer"
            });
            Assert.True(activation.StatusCode == HttpStatusCode.OK, await activation.Content.ReadAsStringAsync());
        }
        /// <summary>Requires successful local delivery before parsing the exact public response DTO.</summary>
        public async Task<AdminController.PersonalDayPassResponse> ReadResponseAsync(AdminController.PersonalDayPassRequest request)
        {
            using var response = await PostAsync(request);
            Assert.True(response.StatusCode == HttpStatusCode.OK, await response.Content.ReadAsStringAsync());
            return (await response.Content.ReadFromJsonAsync<AdminController.PersonalDayPassResponse>())!;
        }

        /// <summary>Creates and migrates only an owned generated database; a non-loopback target is always rejected.</summary>
        public static async Task<Fixture> CreateAsync()
        {
            var settings = new NpgsqlConnectionStringBuilder(Environment.GetEnvironmentVariable("SOFTLICENCE_RUNTIME_TEST_POSTGRES")
                ?? throw new InvalidOperationException("A synthetic loopback PostgreSQL runner is required."));
            if (settings.Host is not ("localhost" or "127.0.0.1" or "::1")) throw new InvalidOperationException("Loopback required.");
            var database = "tkt991_" + Guid.NewGuid().ToString("N");
            settings.Database = "postgres";
            var maintenance = settings.ConnectionString;
            await using (var admin = new NpgsqlConnection(maintenance))
            {
                await admin.OpenAsync();
                await using var command = new NpgsqlCommand($"CREATE DATABASE \"{database}\"", admin);
                await command.ExecuteNonQueryAsync();
            }
            settings.Database = database;
            var fixture = new Fixture(maintenance, database, settings.ConnectionString);
            try
            {
                await using var db = fixture.Db();
                await db.Database.MigrateAsync();
                var product = new Product { Name = database, ApiSecret = "tkt991-fixture-product" };
                // Signing material is generated in memory and encrypted with the fixture's ephemeral data protector.
                using var rsa = RSA.Create(2048);
                using var scope = fixture.host.Services.CreateScope();
                product.PrivateKeyXml = scope.ServiceProvider.GetRequiredService<EncryptionService>().Encrypt(rsa.ToXmlString(true));
                product.PublicKeyXml = rsa.ToXmlString(false);
                var type = new LicenseType { Product = product, Name = "AI Pro Edition", Slug = PersonalDayPassPolicy.TypeSlug,
                    DefaultDurationDays = 30, DefaultMaxSeats = 3, DefaultAllowedVersions = "2.*", IsRecurring = true };
                foreach (var pair in FixturePaidFeatures)
                    type.CustomParams.Add(new LicenseTypeCustomParam { Key = pair.Key, Name = pair.Key, Value = pair.Value });
                db.AddRange(product, type); await db.SaveChangesAsync();
                fixture.productId = product.Id; fixture.typeId = type.Id;
                return fixture;
            }
            catch { await fixture.DisposeAsync(); throw; }
        }

        /// <summary>Closes HTTP first, then drops exactly this generated database. No external or pre-existing database is removed.</summary>
        public async ValueTask DisposeAsync()
        {
            Client.Dispose(); await host.DisposeAsync();
            await using var admin = new NpgsqlConnection(maintenance);
            await admin.OpenAsync();
            await using var command = new NpgsqlCommand($"DROP DATABASE IF EXISTS \"{database}\" WITH (FORCE)", admin);
            await command.ExecuteNonQueryAsync();
        }
    }
}
