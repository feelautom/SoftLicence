using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using Xunit;
using PreparedBootstrapScenario = SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTestBase.PreparedBootstrapScenario;

namespace SoftLicence.Tests.Server;

/// <summary>
/// TKT-004085: with the assignment switch closed, the legitimate refusals of the seat-release controls and of the
/// PostgreSQL assignment trigger are named (<c>assignment_reconciliation_required</c>, <c>seat_assignment_busy</c>)
/// instead of the former 503 <c>authority_unavailable</c> or empty HTTP 500. The trigger cases use the real production
/// trigger and its exact messages, so a migration that rewrites a message breaks these tests.
/// </summary>
/// <param name="classDatabase">The xUnit-owned PostgreSQL clone fixture for this exact test class.</param>
public sealed class NamedAssignmentRefusalPostgreSqlTests(RuntimeEnrollmentPostgreSqlClassDatabase classDatabase)
    : RuntimeEnrollmentPostgreSqlTestBase(classDatabase)
{
    /// <summary>An ACTIVE right whose installation is no longer live is a named 409 with its bounded reason.</summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.NamedRefusal_SeatReleaseActiveRightWithoutRuntime_IsReconciliationRequired")]
    public async Task NamedRefusal_SeatReleaseActiveRightWithoutRuntime_IsReconciliationRequired()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        var right = await LeaveActiveRightWithoutRuntimeAsync(scenario);

        await using var db = CreateEnrollmentAssignmentMigrationContext(scenario.AdminConnectionString);
        await using var transaction = await SeatRuntimeReleaseAuthority.BeginAsync(db);
        var license = await db.Licenses.SingleAsync(row => row.Id == right.LicenseId);
        var seat = await db.LicenseSeats.SingleAsync(row => row.Id == right.LicenseSeatId);
        var refused = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            SeatRuntimeReleaseAuthority.PrepareAsync(db, license.ProductId, license, [seat], DateTime.UtcNow));

        Assert.Equal(AssignmentRefusals.ReconciliationRequiredCode, refused.ErrorCode);
        Assert.Equal(StatusCodes.Status409Conflict, refused.StatusCode);
        Assert.Equal("seat_release_assignment_without_runtime", refused.ReasonCode);
    }

    /// <summary>A live installation without any right is a named 409 with its bounded reason.</summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.NamedRefusal_SeatReleaseMissingRight_IsReconciliationRequired")]
    public async Task NamedRefusal_SeatReleaseMissingRight_IsReconciliationRequired()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await using var admin = CreateEnrollmentAssignmentMigrationContext(scenario.AdminConnectionString);
        var right = await admin.EnrollmentLicenseAssignments.AsNoTracking().SingleAsync();
        await admin.Database.ExecuteSqlInterpolatedAsync(
            $"DELETE FROM public.\"EnrollmentLicenseAssignments\" WHERE \"Id\" = {right.Id}");
        await SetAssignmentSwitchAsync(admin, AssignmentEnforcementSetting.Closed);

        await using var db = CreateEnrollmentAssignmentMigrationContext(scenario.AdminConnectionString);
        await using var transaction = await SeatRuntimeReleaseAuthority.BeginAsync(db);
        var license = await db.Licenses.SingleAsync(row => row.Id == right.LicenseId);
        var seat = await db.LicenseSeats.SingleAsync(row => row.Id == right.LicenseSeatId);
        var refused = await Assert.ThrowsAsync<DistributionOperationException>(() =>
            SeatRuntimeReleaseAuthority.PrepareAsync(db, license.ProductId, license, [seat], DateTime.UtcNow));

        Assert.Equal(AssignmentRefusals.ReconciliationRequiredCode, refused.ErrorCode);
        Assert.Equal(StatusCodes.Status409Conflict, refused.StatusCode);
        Assert.Equal("seat_release_assignment_missing", refused.ReasonCode);
    }

    /// <summary>
    /// The public deactivation and reset routes return the named 409 body (code, reason, English message, correlation)
    /// for that state, and leave the seat active; before TKT-004085 they answered 503 <c>authority_unavailable</c>.
    /// </summary>
    /// <param name="route"><c>client</c> for <c>/api/activation/deactivate</c>, <c>reset</c> for <c>/api/activation/reset-confirm</c>.</param>
    [Theory(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.NamedRefusal_PublicReleaseRoutes_ReturnReconciliationRequired")]
    [InlineData("client")]
    [InlineData("reset")]
    public async Task NamedRefusal_PublicReleaseRoutes_ReturnReconciliationRequired(string route)
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await ActivateCanonicalScenarioAsync(scenario, LegacyHardwareId);
        var right = await LeaveActiveRightWithoutRuntimeAsync(scenario);
        await using var db = await scenario.Factory.CreateDbContextAsync();
        var license = await db.Licenses.Include(row => row.Product).SingleAsync(row => row.Id == right.LicenseId);
        license.LicenseKey = license.LicenseKey.ToUpperInvariant();
        license.ResetCode = "123456";
        license.ResetCodeExpiry = DateTime.UtcNow.AddMinutes(10);
        await db.SaveChangesAsync();
        using var web = CreateAliasWebFactory(scenario, new RecordingLogger<HardwareAuthorityAliasResolver>())
            .WithWebHostBuilder(builder => builder.UseSetting("SOFTLICENCE_ASSIGNMENT_ENFORCEMENT", "closed"));
        using var client = web.CreateClient();

        using var response = route == "reset"
            ? await client.PostAsJsonAsync("/api/activation/reset-confirm", new { license.LicenseKey, AppName = license.Product!.Name, ResetCode = "123456" })
            : await client.PostAsJsonAsync("/api/activation/deactivate", new { license.LicenseKey, AppName = license.Product!.Name, HardwareId = LegacyHardwareId, Source = "settings_button" });

        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(AssignmentRefusals.ReconciliationRequiredCode, body.RootElement.GetProperty("error").GetString());
        Assert.Equal("seat_release_assignment_without_runtime", body.RootElement.GetProperty("reasonCode").GetString());
        Assert.Equal(AssignmentRefusals.ReconciliationRequiredMessage, body.RootElement.GetProperty("message").GetString());
        Assert.False(string.IsNullOrWhiteSpace(body.RootElement.GetProperty("correlationId").GetString()));
        Assert.True((await db.LicenseSeats.AsNoTracking().SingleAsync(row => row.Id == right.LicenseSeatId)).IsActive);
    }

    /// <summary>The real competing-claimant raise of the trigger (40001) is translated to the busy code.</summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.NamedRefusal_RealConcurrentClaimantRaise_IsBusy")]
    public async Task NamedRefusal_RealConcurrentClaimantRaise_IsBusy()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await using var db = CreateEnrollmentAssignmentMigrationContext(scenario.AdminConnectionString);
        await SetAssignmentSwitchAsync(db, AssignmentEnforcementSetting.Closed);

        await using var transaction = await db.Database.BeginTransactionAsync();
        await StageSecondClaimantAsync(db, scenario);
        var raised = await Assert.ThrowsAsync<PostgresException>(() => transaction.CommitAsync());

        Assert.True(AssignmentRefusals.TryTranslate(raised, out var refusal));
        Assert.Equal(AssignmentRefusals.BusyCode, refusal.ErrorCode);
        Assert.Equal("concurrent_seat_claimant", refusal.ReasonCode);
    }

    /// <summary>The real unresolved-graph raise of the trigger (23514) is translated with its reviewed reason.</summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.NamedRefusal_RealUnresolvedGraphRaise_IsReconciliationRequired")]
    public async Task NamedRefusal_RealUnresolvedGraphRaise_IsReconciliationRequired()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await using var db = CreateEnrollmentAssignmentMigrationContext(scenario.AdminConnectionString);
        await SetAssignmentSwitchAsync(db, AssignmentEnforcementSetting.Closed);

        var raised = await Assert.ThrowsAsync<PostgresException>(() => db.Database.ExecuteSqlInterpolatedAsync(
            $"UPDATE public.\"RuntimeEnrollments\" SET \"InstallationId\" = {Guid.NewGuid().ToString("D")} WHERE \"Id\" = {scenario.EnrollmentId}"));

        Assert.True(AssignmentRefusals.TryTranslate(raised, out var refusal));
        Assert.Equal(AssignmentRefusals.ReconciliationRequiredCode, refusal.ErrorCode);
        Assert.Equal("assignment_graph_binding_mismatch", refusal.ReasonCode);
    }

    /// <summary>A real check violation of another constraint (same SQLSTATE 23514) is never named.</summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.NamedRefusal_OtherRealCheckViolation_IsNotNamed")]
    public async Task NamedRefusal_OtherRealCheckViolation_IsNotNamed()
    {
        using var scenario = await CreatePreparedBootstrapScenarioAsync();
        await using var db = CreateEnrollmentAssignmentMigrationContext(scenario.AdminConnectionString);

        var raised = await Assert.ThrowsAsync<PostgresException>(() => db.Database.ExecuteSqlRawAsync(
            "UPDATE public.\"AssignmentEnforcementSettings\" SET \"Mode\" = 'bogus' WHERE \"Id\" = 1"));

        Assert.Equal(PostgresErrorCodes.CheckViolation, raised.SqlState);
        Assert.False(AssignmentRefusals.TryTranslate(raised, out _));
    }

    /// <summary>
    /// Builds the TKT-001428 inconsistent graph (ACTIVE right, installation INVALIDATED) with the switch closed. The
    /// trigger is bypassed (replica role) only to build this state, which the product never writes.
    /// </summary>
    /// <param name="scenario">The prepared Runtime scenario owning the single right.</param>
    /// <returns>The right that stays ACTIVE without a live installation.</returns>
    private static async Task<EnrollmentLicenseAssignment> LeaveActiveRightWithoutRuntimeAsync(PreparedBootstrapScenario scenario)
    {
        await using var admin = CreateEnrollmentAssignmentMigrationContext(scenario.AdminConnectionString);
        await SetAssignmentSwitchAsync(admin, AssignmentEnforcementSetting.Closed);
        await using (var seed = new NpgsqlConnection(scenario.AdminConnectionString))
        {
            await seed.OpenAsync();
            await using var transaction = await seed.BeginTransactionAsync();
            await using var command = new NpgsqlCommand("""
                SET LOCAL session_replication_role = replica;
                UPDATE public."RuntimeEnrollments"
                SET "State" = 'INVALIDATED', "InvalidatedAtUtc" = pg_catalog.clock_timestamp(),
                    "InvalidationReason" = 'tkt004085_probe'
                WHERE "Id" = @enrollment;
                """, seed, transaction);
            command.Parameters.AddWithValue("enrollment", scenario.EnrollmentId);
            await command.ExecuteNonQueryAsync();
            await transaction.CommitAsync();
        }
        var right = await admin.EnrollmentLicenseAssignments.AsNoTracking()
            .SingleAsync(row => row.EnrollmentId == scenario.EnrollmentId && row.State == "ACTIVE");
        return right;
    }

    /// <summary>
    /// Stages a second live binding and enrollment on the scenario seat (same construction as
    /// <c>AssignmentEnforcementSwitchPostgreSqlTests</c>), so the commit raises the competing-claimant refusal.
    /// </summary>
    /// <param name="db">Administrator context inside the caller's transaction.</param>
    /// <param name="scenario">The prepared Runtime scenario whose seat is claimed twice.</param>
    private static Task StageSecondClaimantAsync(LicenseDbContext db, PreparedBootstrapScenario scenario)
    {
        var secondBindingId = Guid.NewGuid();
        var secondEnrollmentId = Guid.NewGuid();
        return db.Database.ExecuteSqlInterpolatedAsync($"""
            INSERT INTO public."DistributionInstallationBindings"
            SELECT (jsonb_populate_record(NULL::public."DistributionInstallationBindings",
                to_jsonb(binding) || jsonb_build_object(
                    'Id', {secondBindingId.ToString("D")},
                    'GrantRef', {Guid.NewGuid().ToString("D")},
                    'GrantRefDigestSha256', {new string('b', 64)},
                    'HandoffDigestSha256', {new string('c', 64)},
                    'HardwareIdHash', {new string('d', 64)},
                    'InstallationId', {Guid.NewGuid().ToString("D")}))).*
            FROM public."DistributionInstallationBindings" binding
            WHERE binding."Id" = {scenario.Fixture.BindingId};

            INSERT INTO public."RuntimeEnrollments"
            SELECT (jsonb_populate_record(NULL::public."RuntimeEnrollments",
                to_jsonb(enrollment) || jsonb_build_object(
                    'Id', {secondEnrollmentId.ToString("D")},
                    'BindingId', {secondBindingId.ToString("D")},
                    'InstallationId', (SELECT "InstallationId"
                                       FROM public."DistributionInstallationBindings"
                                       WHERE "Id" = {secondBindingId}),
                    'HandoffDigestSha256', {new string('c', 64)},
                    'KeyThumbprint', {new string('e', 43)}))).*
            FROM public."RuntimeEnrollments" enrollment
            WHERE enrollment."Id" = {scenario.EnrollmentId};
            """);
    }
}
