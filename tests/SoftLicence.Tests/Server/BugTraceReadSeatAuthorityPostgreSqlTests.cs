using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using SoftLicence.Server.Controllers;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>
/// TKT-003490 on PostgreSQL: the read and comment routes (customer ticket list, ticket comments, new
/// comment) accept a secondary PC that owns an active seat of the same multi-seat licence, exactly as
/// the report route does, and still refuse an unlinked seat, a seat of another licence, an unknown
/// identifier and a revoked licence. Before the fix only the licence's primary identifier was compared,
/// so the owner's own secondary PC was refused 538 times "Hardware ID mismatch" between 13/10 and 08/11.
/// </summary>
/// <remarks>
/// The seat predicate is an exact SQL equality on <c>LicenseSeats.HardwareId</c>; this is why the proof
/// runs on the production provider. The alias resolver is mocked to answer "no alias" so only the
/// direct seat path decides.
/// </remarks>
public sealed class BugTraceReadSeatAuthorityPostgreSqlTests
{
    private const string ProjectId = "9f3c8fea-8740-42af-be83-6f527c6d102a";
    private const string Email = "multiseat@example.invalid";
    private const string PrimaryHardwareId = "6F6B0AEE4E9B6AFE";
    private const string SecondaryHardwareId = "747494E7F4576E90";
    private const string UnlinkedHardwareId = "643BFC3D242B49BF";
    private const string ForeignHardwareId = "A223A7A74FDA4F01";
    private const string UnknownHardwareId = "0000000000000001";

    /// <summary>
    /// The three routes accept the primary identifier and an active secondary seat, refuse every other
    /// identifier with "Hardware ID mismatch", and refuse everything once the licence is revoked.
    /// </summary>
    [Fact]
    public async Task ReadAndCommentRoutes_AcceptActiveSameLicenceSeatOnly()
    {
        await using var provision = await PostgreSqlProvision.CreateAsync();
        var factory = new PostgreSqlContextFactory(
            new DbContextOptionsBuilder<LicenseDbContext>().UseNpgsql(provision.ConnectionString).Options);
        var licenseKey = await SeedAsync(factory);
        using var cache = new MemoryCache(new MemoryCacheOptions());
        var proxy = new FakeBugTraceProxyService();
        var controller = CreateController(factory, proxy, cache);

        foreach (var accepted in new[] { PrimaryHardwareId, SecondaryHardwareId })
        {
            Assert.IsType<OkObjectResult>(await ListTickets(controller, licenseKey, accepted));
            Assert.IsType<OkObjectResult>(await controller.GetTicketComments(
                "BT-00042", licenseKey, null, accepted, ProjectId, CancellationToken.None));
            Assert.IsType<OkObjectResult>(await controller.Comment(
                CommentRequest(licenseKey, accepted), CancellationToken.None));
        }

        foreach (var refused in new[] { UnlinkedHardwareId, ForeignHardwareId, UnknownHardwareId })
        {
            AssertError(await ListTickets(controller, licenseKey, refused), 403, "Hardware ID mismatch");
            AssertError(await controller.GetTicketComments(
                "BT-00042", licenseKey, null, refused, ProjectId, CancellationToken.None), 400, "Hardware ID mismatch");
            AssertError(await controller.Comment(
                CommentRequest(licenseKey, refused), CancellationToken.None), 400, "Hardware ID mismatch");
        }

        await using (var db = factory.CreateDbContext())
        {
            var license = await db.Licenses.SingleAsync(item => item.LicenseKey == licenseKey);
            license.IsActive = false;
            await db.SaveChangesAsync();
        }
        AssertError(await ListTickets(controller, licenseKey, SecondaryHardwareId), 403, "License is revoked");
        Assert.Equal(2, proxy.AddedTiaComments.Count);
    }

    /// <summary>Calls the customer ticket list route with one hardware identifier.</summary>
    /// <param name="controller">Controller under test.</param>
    /// <param name="licenseKey">Plain licence key.</param>
    /// <param name="hardwareId">Client hardware identifier.</param>
    private static Task<IActionResult> ListTickets(BugTraceController controller, string licenseKey, string hardwareId) =>
        controller.PostTickets(new BugTraceTicketsRequest
        {
            Email = Email,
            LicenseKey = licenseKey,
            HardwareId = hardwareId,
            ProjectId = ProjectId
        }, CancellationToken.None);

    /// <summary>Builds one valid comment on the ticket owned by the synthetic customer.</summary>
    /// <param name="licenseKey">Plain licence key.</param>
    /// <param name="hardwareId">Client hardware identifier.</param>
    private static BugTraceCommentRequest CommentRequest(string licenseKey, string hardwareId) => new()
    {
        LicenseKey = licenseKey,
        HardwareId = hardwareId,
        ProjectId = ProjectId,
        TicketNumber = "BT-00042",
        Content = "Synthetic comment"
    };

    /// <summary>Asserts an error result with its exact status code and error text.</summary>
    /// <param name="result">Controller result.</param>
    /// <param name="statusCode">Expected HTTP status code.</param>
    /// <param name="error">Expected error text contained in the body.</param>
    private static void AssertError(IActionResult result, int statusCode, string error)
    {
        var objectResult = Assert.IsAssignableFrom<ObjectResult>(result);
        Assert.Equal(statusCode, objectResult.StatusCode);
        Assert.Contains(error, System.Text.Json.JsonSerializer.Serialize(objectResult.Value), StringComparison.Ordinal);
    }

    /// <summary>
    /// Seeds a five-seat licence with a primary identifier, one active secondary seat and one unlinked
    /// seat, plus another customer's licence holding the foreign seat.
    /// </summary>
    /// <param name="factory">Factory bound to the isolated database.</param>
    /// <returns>The plain key of the multi-seat licence.</returns>
    private static async Task<string> SeedAsync(IDbContextFactory<LicenseDbContext> factory)
    {
        var product = new Product { Name = "TKT3490 synthetic", PrivateKeyXml = "synthetic", PublicKeyXml = "synthetic" };
        var type = new LicenseType { Product = product, Name = "Synthetic", Slug = "TKT3490" };
        var license = new License
        {
            Product = product, Type = type, LicenseKey = "TKT3490-MULTI-SEAT", CustomerEmail = Email,
            HardwareId = PrimaryHardwareId, MaxSeats = 5, IsActive = true
        };
        var foreign = new License
        {
            Product = product, Type = type, LicenseKey = "TKT3490-FOREIGN", CustomerEmail = "other@example.invalid",
            HardwareId = ForeignHardwareId, IsActive = true
        };
        await using var db = factory.CreateDbContext();
        db.AddRange(product, type, license, foreign);
        db.LicenseSeats.AddRange(
            new LicenseSeat { License = license, HardwareId = PrimaryHardwareId, IsActive = true },
            new LicenseSeat { License = license, HardwareId = SecondaryHardwareId, IsActive = true },
            new LicenseSeat { License = license, HardwareId = UnlinkedHardwareId, IsActive = false, UnlinkedAt = DateTime.UtcNow.AddDays(-28) },
            new LicenseSeat { License = foreign, HardwareId = ForeignHardwareId, IsActive = true });
        await db.SaveChangesAsync();
        return license.LicenseKey;
    }

    /// <summary>
    /// Creates a controller bound to the isolated database, with an alias resolver that always answers
    /// "no alias" and a valid request context for audit annotations.
    /// </summary>
    /// <param name="factory">PostgreSQL context factory.</param>
    /// <param name="proxy">Recording provider relay.</param>
    /// <param name="cache">Isolated rate-limit state.</param>
    private static BugTraceController CreateController(
        IDbContextFactory<LicenseDbContext> factory,
        IBugTraceProxyService proxy,
        IMemoryCache cache)
    {
        var aliases = new Mock<IHardwareAuthorityAliasResolver>();
        aliases
            .Setup(resolver => resolver.ResolveAsync(
                It.IsAny<LicenseDbContext>(), It.IsAny<Guid>(), It.IsAny<Guid>(), It.IsAny<string>(),
                It.IsAny<HardwareAuthorityResolutionIntent>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((LicenseDbContext _, Guid _, Guid _, string hardwareId, HardwareAuthorityResolutionIntent _, CancellationToken _) =>
                new HardwareAuthorityResolution(hardwareId, hardwareId, null, HardwareAuthorityResolutionStatus.NoAlias));
        var controller = new BugTraceController(
            proxy,
            Mock.Of<IBugTraceAutoReportService>(),
            factory,
            aliases.Object,
            cache,
            NullLogger<BugTraceController>.Instance);
        controller.ControllerContext = new ControllerContext { HttpContext = new DefaultHttpContext() };
        return controller;
    }

    /// <summary>Creates independent contexts for each controller authority read.</summary>
    private sealed class PostgreSqlContextFactory(DbContextOptions<LicenseDbContext> options)
        : IDbContextFactory<LicenseDbContext>
    {
        /// <inheritdoc />
        public LicenseDbContext CreateDbContext() => new(options);

        /// <inheritdoc />
        public Task<LicenseDbContext> CreateDbContextAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(CreateDbContext());
    }

    /// <summary>Owns one isolated migrated PostgreSQL database and drops it during disposal.</summary>
    private sealed class PostgreSqlProvision(string maintenanceConnectionString, string database, string connectionString)
        : IAsyncDisposable
    {
        /// <summary>Gets the isolated database connection string.</summary>
        public string ConnectionString { get; } = connectionString;

        /// <summary>Clones a uniquely named database from the shared current-schema model.</summary>
        public static async Task<PostgreSqlProvision> CreateAsync()
        {
            var clone = await PostgreSqlModelDatabase.CloneAsync("bugtrace_seats");
            return new PostgreSqlProvision(clone.MaintenanceConnectionString, clone.DatabaseName, clone.ConnectionString);
        }

        /// <summary>Drops the generated database even when an assertion fails.</summary>
        public async ValueTask DisposeAsync() =>
            await PostgreSqlModelDatabase.DropAsync(maintenanceConnectionString, database);
    }
}
