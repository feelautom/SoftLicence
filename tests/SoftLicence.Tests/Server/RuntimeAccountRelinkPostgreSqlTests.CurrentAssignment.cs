using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>
/// TKT-003647 on a real PostgreSQL 17 database: the read-only current-assignment answer the Website uses to keep the
/// licence of an installed machine during a WebSetup update. It lives in this class to reuse the relink and seat
/// release scenarios, since the decisive case is a licence changed inside the application (account relink): the
/// answer must follow the ACTIVE assignment, not the historical binding licence.
/// </summary>
public sealed partial class RuntimeAccountRelinkPostgreSqlTests
{
    /// <summary>The only JSON members an <c>assigned</c> answer may carry (owner decision, 12/11/2026: UUID only, no name, type or key).</summary>
    private static readonly string[] AssignedMembers = ["schema", "outcome", "requestId", "licenseId", "eligible"];

    /// <summary>Serializer equivalent to the ASP.NET Core answer of the route (web defaults, camelCase).</summary>
    private static readonly JsonSerializerOptions WebJson = new(JsonSerializerDefaults.Web);

    /// <summary>
    /// A normally installed machine reads <c>assigned</c> with the licence of its ACTIVE assignment, eligible. The JSON
    /// carries exactly the five allowed members; apart from the two fixed protocol constants, its values contain none of
    /// the licence key (or any 8-character fragment of it), the customer name, the licence type name, slug or
    /// identifier, the product name or the hardware identifier, and the licence is a bare UUID. Nothing is
    /// written: business rows, relink ledger, hardware decisions and quotas are unchanged.
    /// </summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeAccountRelinkPostgreSqlTests.CurrentAssignment_Installed_AssignedEligible_UuidOnly_NoWrite")]
    public async Task CurrentAssignment_Installed_AssignedEligible_UuidOnly_NoWrite()
    {
        using var scenario = await ActivatedScenarioAsync();
        var licenseId = await InstallationLicenseIdAsync(scenario);
        var before = await CurrentAssignmentSnapshotAsync(scenario);

        var answer = await ResolveCurrentAssignmentAsync(scenario, await CurrentAssignmentRequestAsync(scenario));

        Assert.Equal(before, await CurrentAssignmentSnapshotAsync(scenario));
        Assert.Equal(RuntimeEnrollmentService.CurrentAssignmentResponseSchema, answer.Schema);
        Assert.Equal("assigned", answer.Outcome);
        Assert.Equal(licenseId.ToString("D"), answer.LicenseId);
        Assert.True(answer.Eligible);
        Assert.Null(answer.IneligibleReason);

        var json = JsonSerializer.Serialize(answer, WebJson);
        var members = JsonNode.Parse(json)!.AsObject();
        Assert.Equal(AssignedMembers.Order(StringComparer.Ordinal),
            members.Select(member => member.Key).Order(StringComparer.Ordinal));
        // schema and outcome are fixed protocol constants, already asserted equal above. They are excluded from the
        // substring search because a fixture name such as the product "Runtime" legitimately occurs inside the
        // constant "runtime-current-assignment-result-v1"; every other value is data and is searched.
        var data = string.Join("\n", members
            .Where(member => member.Key is not ("schema" or "outcome"))
            .Select(member => member.Value!.ToJsonString()));
        Assert.True(Guid.TryParseExact(answer.LicenseId, "D", out _));
        await using var db = await scenario.Factory.CreateDbContextAsync();
        var license = await db.Licenses.AsNoTracking().Include(row => row.Type).Include(row => row.Product)
            .SingleAsync(row => row.Id == licenseId);
        // Every textual identifier of the licence other than its UUID must stay inside SoftLicence.
        string[] forbidden =
        [
            license.LicenseKey, license.Type!.Name, license.Type.Slug, license.LicenseTypeId.ToString("D"),
            license.Product!.Name, license.CustomerName, LegacyHardwareId
        ];
        foreach (var value in forbidden.Where(value => !string.IsNullOrWhiteSpace(value)))
            Assert.DoesNotContain(value, data, StringComparison.OrdinalIgnoreCase);
        var compactKey = license.LicenseKey.Replace("-", string.Empty, StringComparison.Ordinal);
        for (var start = 0; start + 8 <= compactKey.Length; start++)
            Assert.DoesNotContain(compactKey.Substring(start, 8), data, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// The ticket case: the licence was changed inside the application (seat released, account relink to another
    /// licence of the same owner). The answer names the new licence of the ACTIVE assignment, not the historical
    /// binding licence the Website used to retain.
    /// </summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeAccountRelinkPostgreSqlTests.CurrentAssignment_AfterRelinkToOtherLicense_ReturnsNewLicenseNotBindingLicense")]
    public async Task CurrentAssignment_AfterRelinkToOtherLicense_ReturnsNewLicenseNotBindingLicense()
    {
        using var scenario = await ActivatedScenarioAsync();
        var bindingLicenseId = await InstallationLicenseIdAsync(scenario);
        var owner = Guid.NewGuid();
        await SetOwnerAsync(scenario, bindingLicenseId, owner);
        await ReleaseAsync(scenario, "client");
        var (otherLicenseId, _) = await AddLicenseWithSeatAsync(scenario, owner, OtherCanonicalHardwareId, seatActive: false);
        await RelinkAsync(scenario, await BuildAsync(scenario, otherLicenseId, owner));

        var answer = await ResolveCurrentAssignmentAsync(scenario, await CurrentAssignmentRequestAsync(scenario));

        Assert.Equal("assigned", answer.Outcome);
        Assert.Equal(otherLicenseId.ToString("D"), answer.LicenseId);
        Assert.NotEqual(bindingLicenseId.ToString("D"), answer.LicenseId);
        Assert.True(answer.Eligible);
    }

    /// <summary>
    /// An ACTIVE assignment whose key period is over, or whose licence counts more active seats than allowed, is
    /// <c>assigned</c> but not eligible, with the closed reason. Neither state ends the assignment in the database.
    /// </summary>
    [Theory(DisplayName = "SoftLicence.Tests.Server.RuntimeAccountRelinkPostgreSqlTests.CurrentAssignment_AssignedButUnusable_ReturnsReason")]
    [InlineData("expired", "license_expired")]
    [InlineData("capacity", "seat_capacity_exceeded")]
    public async Task CurrentAssignment_AssignedButUnusable_ReturnsReason(string mutation, string expectedReason)
    {
        using var scenario = await ActivatedScenarioAsync();
        var licenseId = await InstallationLicenseIdAsync(scenario);
        await using (var admin = AdminContext(scenario))
        {
            if (mutation == "expired")
                await admin.Database.ExecuteSqlInterpolatedAsync(
                    $"UPDATE \"Licenses\" SET \"ExpirationDate\" = now() - interval '1 day' WHERE \"Id\" = {licenseId}");
            else
            {
                // A second active seat on a one-seat licence: an over-capacity graph left by a legacy path.
                admin.LicenseSeats.Add(new LicenseSeat { LicenseId = licenseId, HardwareId = OtherCanonicalHardwareId, IsActive = true });
                await admin.SaveChangesAsync();
            }
        }

        var answer = await ResolveCurrentAssignmentAsync(scenario, await CurrentAssignmentRequestAsync(scenario));

        Assert.Equal("assigned", answer.Outcome);
        Assert.Equal(licenseId.ToString("D"), answer.LicenseId);
        Assert.False(answer.Eligible);
        Assert.Equal(expectedReason, answer.IneligibleReason);
    }

    /// <summary>
    /// An ACTIVE enrollment without ACTIVE assignment is <c>unassigned</c>: after a client sign-out, and after a licence
    /// revocation, whose database trigger ends the assignment (reason <c>license_revoked</c>). With a quarantine row it
    /// is <c>quarantined</c>. None of these answers names a licence.
    /// </summary>
    [Theory(DisplayName = "SoftLicence.Tests.Server.RuntimeAccountRelinkPostgreSqlTests.CurrentAssignment_NoActiveAssignment_UnassignedOrQuarantined")]
    [InlineData("released", "unassigned")]
    [InlineData("revoked", "unassigned")]
    [InlineData("quarantined", "quarantined")]
    public async Task CurrentAssignment_NoActiveAssignment_UnassignedOrQuarantined(string mutation, string expectedOutcome)
    {
        using var scenario = await ActivatedScenarioAsync();
        var licenseId = await InstallationLicenseIdAsync(scenario);
        if (mutation == "revoked")
        {
            await using var admin = AdminContext(scenario);
            await admin.Database.ExecuteSqlInterpolatedAsync(
                $"UPDATE \"Licenses\" SET \"IsActive\" = false, \"RevokedAt\" = now(), \"RevocationReason\" = 'tkt003647-synthetic' WHERE \"Id\" = {licenseId}");
        }
        else
        {
            await ReleaseAsync(scenario, "client");
            if (mutation == "quarantined")
            {
                await using var admin = AdminContext(scenario);
                admin.EnrollmentLicenseAssignmentQuarantines.Add(new EnrollmentLicenseAssignmentQuarantine
                {
                    EnrollmentId = scenario.EnrollmentId, BindingId = scenario.Fixture.BindingId,
                    Reason = "live_state_mismatch", ObservedAtUtc = DateTime.UtcNow
                });
                await admin.SaveChangesAsync();
            }
        }

        var answer = await ResolveCurrentAssignmentAsync(scenario, await CurrentAssignmentRequestAsync(scenario));

        Assert.Equal(expectedOutcome, answer.Outcome);
        Assert.Null(answer.LicenseId);
        Assert.Null(answer.Eligible);
        Assert.Null(answer.IneligibleReason);
    }

    /// <summary>
    /// Every request that does not designate the caller's own ACTIVE enrollment exactly gets the same <c>none</c>
    /// bytes as an unknown enrollment: other client, other product, other binding, other installation, other key
    /// thumbprint, the same thumbprint with one letter in another case (ordinal comparison), and an enrollment
    /// invalidated by a provider seat release.
    /// </summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeAccountRelinkPostgreSqlTests.CurrentAssignment_AnyMismatch_ReturnsIdenticalNone")]
    public async Task CurrentAssignment_AnyMismatch_ReturnsIdenticalNone()
    {
        using var scenario = await ActivatedScenarioAsync();
        var requestId = Guid.NewGuid();
        var clientId = await EnrollmentClientIdAsync(scenario);

        var unknown = await CurrentAssignmentRequestAsync(scenario, requestId);
        unknown.EnrollmentId = Guid.NewGuid().ToString("D");
        var expected = JsonSerializer.Serialize(
            await scenario.Runtime.ResolveCurrentAssignmentAsync(clientId, unknown), WebJson);
        Assert.Equal($"{{\"schema\":\"runtime-current-assignment-result-v1\",\"outcome\":\"none\",\"requestId\":\"{requestId:D}\"}}", expected);

        var thumbprint = (await CurrentAssignmentRequestAsync(scenario)).KeyThumbprint!;
        var letter = thumbprint.Select((character, index) => (character, index)).First(item => char.IsLetter(item.character));
        var caseFlipped = thumbprint[..letter.index]
            + (char.IsUpper(letter.character) ? char.ToLowerInvariant(letter.character) : char.ToUpperInvariant(letter.character))
            + thumbprint[(letter.index + 1)..];
        var cases = new List<(string Client, RuntimeCurrentAssignmentRequest Request)>();
        cases.Add(("another-distribution-client", await CurrentAssignmentRequestAsync(scenario, requestId)));
        foreach (var mutate in new Action<RuntimeCurrentAssignmentRequest>[]
                 {
                     request => request.ProductId = Guid.NewGuid().ToString("D"),
                     request => request.BindingId = Guid.NewGuid().ToString("D"),
                     request => request.InstallationId = Guid.NewGuid().ToString("D"),
                     request => request.KeyThumbprint = new string('A', 43),
                     request => request.KeyThumbprint = caseFlipped,
                 })
        {
            var request = await CurrentAssignmentRequestAsync(scenario, requestId);
            mutate(request);
            cases.Add((clientId, request));
        }
        foreach (var (client, request) in cases)
            Assert.Equal(expected, JsonSerializer.Serialize(
                await scenario.Runtime.ResolveCurrentAssignmentAsync(client, request), WebJson));

        await ReleaseAsync(scenario, "provider");
        Assert.Equal(expected, JsonSerializer.Serialize(await scenario.Runtime.ResolveCurrentAssignmentAsync(
            clientId, await CurrentAssignmentRequestAsync(scenario, requestId)), WebJson));
    }

    /// <summary>
    /// A malformed request is 400 <c>invalid_request</c> before any lookup: wrong schema, unknown member, a UUID not in
    /// canonical lowercase form, or a thumbprint of the wrong length.
    /// </summary>
    [Theory(DisplayName = "SoftLicence.Tests.Server.RuntimeAccountRelinkPostgreSqlTests.CurrentAssignment_MalformedRequest_Returns400")]
    [InlineData("schema")]
    [InlineData("unknown-member")]
    [InlineData("uppercase-uuid")]
    [InlineData("short-thumbprint")]
    public async Task CurrentAssignment_MalformedRequest_Returns400(string mutation)
    {
        using var scenario = await ActivatedScenarioAsync();
        var request = await CurrentAssignmentRequestAsync(scenario);
        switch (mutation)
        {
            case "schema": request.Schema = "runtime-current-assignment-request-v2"; break;
            case "unknown-member": request.ExtensionData = new() { ["licenseKey"] = JsonDocument.Parse("\"x\"").RootElement }; break;
            case "uppercase-uuid": request.EnrollmentId = request.EnrollmentId!.ToUpperInvariant(); break;
            case "short-thumbprint": request.KeyThumbprint = request.KeyThumbprint![..42]; break;
        }

        var refused = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            ResolveCurrentAssignmentAsync(scenario, request));

        Assert.Equal(StatusCodes.Status400BadRequest, refused.StatusCode);
        Assert.Equal("invalid_request", refused.ErrorCode);
    }

    /// <summary>
    /// A dangling assignment relation (its seat no longer exists) is 503 <c>authority_unavailable</c>, never a guessed
    /// <c>unassigned</c> that would let the Website offer a licence the hardware step then refuses.
    /// </summary>
    [Fact(DisplayName = "SoftLicence.Tests.Server.RuntimeAccountRelinkPostgreSqlTests.CurrentAssignment_MissingAssignmentSeat_Returns503")]
    public async Task CurrentAssignment_MissingAssignmentSeat_Returns503()
    {
        using var scenario = await ActivatedScenarioAsync();
        await using (var admin = new NpgsqlConnection(scenario.AdminConnectionString))
        {
            await admin.OpenAsync();
            // The foreign key forbids the corruption this test needs; drop it in this disposable database only.
            await using var dropConstraint = new NpgsqlCommand("""
                DO $broken_relation$
                DECLARE constraint_name name;
                BEGIN
                    SELECT conname INTO constraint_name FROM pg_catalog.pg_constraint
                    WHERE conrelid = 'public."EnrollmentLicenseAssignments"'::pg_catalog.regclass
                      AND conname LIKE 'FK_EnrollmentLicenseAssignments_LicenseSeats%';
                    EXECUTE pg_catalog.format(
                        'ALTER TABLE public."EnrollmentLicenseAssignments" DROP CONSTRAINT %I',
                        constraint_name);
                END;
                $broken_relation$;
                """, admin);
            await dropConstraint.ExecuteNonQueryAsync();
            await using var breakRelation = new NpgsqlCommand("""
                UPDATE public."EnrollmentLicenseAssignments"
                SET "LicenseSeatId" = @missing
                WHERE "EnrollmentId" = @enrollment AND "State" = 'ACTIVE';
                """, admin);
            breakRelation.Parameters.AddWithValue("missing", Guid.NewGuid());
            breakRelation.Parameters.AddWithValue("enrollment", scenario.EnrollmentId);
            await breakRelation.ExecuteNonQueryAsync();
        }

        var unavailable = await Assert.ThrowsAsync<RuntimeEnrollmentException>(async () =>
            await ResolveCurrentAssignmentAsync(scenario, await CurrentAssignmentRequestAsync(scenario)));

        Assert.Equal(StatusCodes.Status503ServiceUnavailable, unavailable.StatusCode);
        Assert.Equal("authority_unavailable", unavailable.ErrorCode);
        Assert.Equal("assignment_relation_missing", unavailable.DiagnosticCode);
    }

    /// <summary>
    /// Builds an exact current-assignment request for the scenario enrollment from its stored values, as the Website
    /// sends them from its reinstall request.
    /// </summary>
    /// <param name="scenario">Activated scenario.</param>
    /// <param name="requestId">Optional fixed correlation identifier, so two answers can be compared byte for byte.</param>
    private static async Task<RuntimeCurrentAssignmentRequest> CurrentAssignmentRequestAsync(
        PreparedBootstrapScenario scenario, Guid? requestId = null)
    {
        await using var db = await scenario.Factory.CreateDbContextAsync();
        var enrollment = await db.RuntimeEnrollments.AsNoTracking().SingleAsync(row => row.Id == scenario.EnrollmentId);
        return new RuntimeCurrentAssignmentRequest
        {
            Schema = RuntimeEnrollmentService.CurrentAssignmentRequestSchema,
            RequestId = (requestId ?? Guid.NewGuid()).ToString("D"),
            ProductId = enrollment.ProductId.ToString("D"),
            EnrollmentId = enrollment.Id.ToString("D"),
            BindingId = enrollment.BindingId.ToString("D"),
            InstallationId = enrollment.InstallationId,
            KeyThumbprint = enrollment.KeyThumbprint
        };
    }

    /// <summary>Calls the production service as the distribution client that owns the scenario enrollment.</summary>
    private static async Task<RuntimeCurrentAssignmentResponse> ResolveCurrentAssignmentAsync(
        PreparedBootstrapScenario scenario, RuntimeCurrentAssignmentRequest request) =>
        await scenario.Runtime.ResolveCurrentAssignmentAsync(await EnrollmentClientIdAsync(scenario), request);

    /// <summary>
    /// Extends the relink business snapshot with the rows a read must never touch either: hardware decisions,
    /// Runtime quotas, assignment quarantines and licence state.
    /// </summary>
    private static async Task<string> CurrentAssignmentSnapshotAsync(PreparedBootstrapScenario scenario)
    {
        await using var db = await scenario.Factory.CreateDbContextAsync();
        var decisions = await db.RuntimeDistributionHardwareDecisions.AsNoTracking().CountAsync();
        var quotas = await db.RuntimeEnrollmentQuotas.AsNoTracking().SumAsync(row => row.Count);
        var quarantines = await db.EnrollmentLicenseAssignmentQuarantines.AsNoTracking().CountAsync();
        var licenses = await db.Licenses.AsNoTracking().OrderBy(row => row.Id)
            .Select(row => row.Id + ":" + row.IsActive + ":" + row.RevokedAt + ":" + row.ExpirationDate + ":" + row.HardwareId)
            .ToListAsync();
        return string.Join("|", await SnapshotAsync(scenario), decisions, quotas, quarantines, string.Join(",", licenses));
    }
}
