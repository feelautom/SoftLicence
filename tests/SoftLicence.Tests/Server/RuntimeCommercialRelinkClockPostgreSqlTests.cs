using System.Diagnostics;
using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using SoftLicence.SDK;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>Exercises the privileged relink writer's time boundary under real PostgreSQL row contention.</summary>
public abstract partial class RuntimeEnrollmentPostgreSqlTestBase
{

    /// <summary>
    /// Confirms the writer is blocked by the owned seat transaction within three seconds. A missing
    /// lock wait fails the test instead of allowing a slow environment to simulate the intended race.
    /// </summary>
    /// <param name="observer">An open administrator connection owned by the caller.</param>
    /// <param name="writerPid">Backend executing the relink function.</param>
    /// <param name="blockerPid">Backend holding the target seat lock.</param>
    protected static async Task WaitForTkt1617SeatWaitAsync(NpgsqlConnection observer, int writerPid, int blockerPid)
    {
        var deadline = Stopwatch.StartNew();
        while (deadline.Elapsed < TimeSpan.FromSeconds(3))
        {
            await using var command = new NpgsqlCommand(
                "SELECT @blocker = ANY(pg_catalog.pg_blocking_pids(@writer));", observer);
            command.Parameters.AddWithValue("blocker", blockerPid);
            command.Parameters.AddWithValue("writer", writerPid);
            if (Assert.IsType<bool>(await command.ExecuteScalarAsync()))
                return;
            await Task.Delay(20);
        }
        Assert.Fail("Relink writer did not wait on the owned seat lock before the expiry deadline.");
    }
}

/// <summary>Runs the tests from RuntimeCommercialRelinkClockPostgreSqlTests as an independently schedulable PostgreSQL class.</summary>
/// <param name="classDatabase">The xUnit-owned PostgreSQL clone fixture for this exact test class.</param>
public sealed partial class RuntimeCommercialRelinkClockPostgreSqlTests(RuntimeEnrollmentPostgreSqlClassDatabase classDatabase)
    : RuntimeEnrollmentPostgreSqlTestBase(classDatabase)
{
    /// <summary>
    /// Holds the target seat lock until an initially valid authority expires. The production-role
    /// writer must refuse after the wait and leave assignment history unchanged. All timing is
    /// observed on the database clock; lock acquisition is confirmed before allowing expiry.
    /// </summary>
    /// <param name = "expireLicense">Expires the licence instead of the distribution entitlement.</param>
    [Theory(DisplayName = "SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTests.Tkt1617_RelinkWriter_AuthorityExpiresWhileWaitingForSeat_RefusesWithoutAssignment")]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Tkt1617_RelinkWriter_AuthorityExpiresWhileWaitingForSeat_RefusesWithoutAssignment(bool expireLicense)
    {
        var subject = Base64Url(SHA256.HashData("tkt-1617-clock-subject"u8.ToArray()));
        var hardware = Assert.IsType<string>(MachineIdentity.FromUuid(Tkt1617KnownSystemUuid).HardwareId);
        using var scenario = await CreatePreparedBootstrapScenarioAsync(initialHardwareId: hardware, initialSubjectRef: subject);
        await using (var release = await scenario.Factory.CreateDbContextAsync())
        {
            var enrollment = await release.RuntimeEnrollments.SingleAsync(row => row.Id == scenario.EnrollmentId);
            var oldSeat = await release.LicenseSeats.SingleAsync(row => row.Id == enrollment.LicenseSeatId);
            oldSeat.IsActive = false;
            oldSeat.UnlinkedAt = DateTime.UtcNow;
            await release.SaveChangesAsync();
        }

        var target = await CreateTkt1617TargetDistributionAsync(scenario, subject, hardware, hardware, 1, false, alreadyActivatedKnownSeat: true);
        Guid seatId;
        Guid entitlementId;
        string subjectDigest;
        int assignmentCount;
        await using (var read = await scenario.Factory.CreateDbContextAsync())
        {
            seatId = await read.LicenseSeats.Where(row => row.LicenseId == target.LicenseId && row.IsActive).Select(row => row.Id).SingleAsync();
            entitlementId = await read.DistributionEntitlements.Where(row => row.LicenseId == target.LicenseId).Select(row => row.Id).SingleAsync();
            subjectDigest = Assert.IsType<string>((await read.RuntimeEnrollments.SingleAsync(row => row.Id == scenario.EnrollmentId)).SubjectRefDigestSha256);
            assignmentCount = await read.EnrollmentLicenseAssignments.CountAsync();
        }

        await using var blocker = new NpgsqlConnection(scenario.AdminConnectionString);
        await blocker.OpenAsync();
        // Commit the expiry first: the waiter must see it as future when it enters the function.
        // The target licence is independent of the historical enrollment, so its update has no
        // assignment to refresh and does not introduce an additional test-only lock dependency.
        await using (var expiry = new NpgsqlCommand(expireLicense ? "UPDATE public.\"Licenses\" SET \"ExpirationDate\" = (pg_catalog.clock_timestamp() + interval '4 seconds') AT TIME ZONE 'UTC' WHERE \"Id\" = @id;" : "UPDATE public.\"DistributionEntitlements\" SET \"ExpiresAtUtc\" = pg_catalog.clock_timestamp() + interval '4 seconds' WHERE \"Id\" = @id;", blocker))
        {
            expiry.Parameters.AddWithValue("id", expireLicense ? target.LicenseId : entitlementId);
            Assert.Equal(1, await expiry.ExecuteNonQueryAsync());
        }

        await using var transaction = await blocker.BeginTransactionAsync();
        await using (var lockSeat = new NpgsqlCommand("SELECT \"Id\" FROM public.\"LicenseSeats\" WHERE \"Id\" = @id FOR UPDATE;", blocker, transaction))
        {
            lockSeat.Parameters.AddWithValue("id", seatId);
            Assert.Equal(seatId, await lockSeat.ExecuteScalarAsync());
        }

        var production = new NpgsqlConnectionStringBuilder(scenario.AdminConnectionString)
        {
            Username = "softlicence_app",
            Password = "runtime-production-role-test-only",
            Pooling = false
        }.ConnectionString;
        await using var writer = new NpgsqlConnection(production);
        await writer.OpenAsync();
        await using var relink = new NpgsqlCommand("""
            SELECT public.relink_runtime_commercial_assignment(
                @enrollment, @license, @seat, @subject, @client, @entitlement, NULL, NULL);
            """, writer)
        {
            CommandTimeout = 20
        };
        relink.Parameters.AddWithValue("enrollment", scenario.EnrollmentId);
        relink.Parameters.AddWithValue("license", target.LicenseId);
        relink.Parameters.AddWithValue("seat", seatId);
        relink.Parameters.AddWithValue("subject", subjectDigest);
        relink.Parameters.AddWithValue("client", target.ClientId);
        relink.Parameters.AddWithValue("entitlement", entitlementId);
        var pending = relink.ExecuteScalarAsync();
        var lockReleased = false;
        try
        {
            await using var observer = new NpgsqlConnection(scenario.AdminConnectionString);
            await observer.OpenAsync();
            await WaitForTkt1617SeatWaitAsync(observer, writer.ProcessID, blocker.ProcessID);
            // Waiting for the persisted database deadline avoids assuming client/server clock agreement.
            await using var waitExpiry = new NpgsqlCommand(expireLicense ? "SELECT pg_catalog.pg_sleep(GREATEST(0, EXTRACT(EPOCH FROM (\"ExpirationDate\" AT TIME ZONE 'UTC' - pg_catalog.clock_timestamp()))) + 0.1) FROM public.\"Licenses\" WHERE \"Id\" = @id;" : "SELECT pg_catalog.pg_sleep(GREATEST(0, EXTRACT(EPOCH FROM (\"ExpiresAtUtc\" - pg_catalog.clock_timestamp()))) + 0.1) FROM public.\"DistributionEntitlements\" WHERE \"Id\" = @id;", observer);
            waitExpiry.Parameters.AddWithValue("id", expireLicense ? target.LicenseId : entitlementId);
            await waitExpiry.ExecuteNonQueryAsync();
            Assert.False(pending.IsCompleted);
            await transaction.CommitAsync();
            lockReleased = true;
            var refusal = await Assert.ThrowsAsync<PostgresException>(async () => await pending);
            Assert.Equal(PostgresErrorCodes.CheckViolation, refusal.SqlState);
            Assert.Equal(expireLicense ? "runtime_commercial_relink_license_ineligible" : "runtime_commercial_relink_authority_ineligible", refusal.MessageText);
        }
        finally
        {
            // Release the owned lock even on an assertion failure, then observe the writer result
            // so disposal cannot strand a task or hide its original PostgreSQL exception.
            if (!lockReleased)
                await transaction.RollbackAsync();
            if (!pending.IsCompleted)
            {
                try
                {
                    await pending;
                }
                catch (PostgresException cleanupResult)
                {
                    Console.WriteLine("Relink task completed during cleanup with PostgreSQL SQLSTATE " + cleanupResult.SqlState);
                }
            }
        }

        await using var verify = await scenario.Factory.CreateDbContextAsync();
        Assert.Equal(assignmentCount, await verify.EnrollmentLicenseAssignments.CountAsync());
        Assert.False(await verify.EnrollmentLicenseAssignments.AnyAsync(row => row.EnrollmentId == scenario.EnrollmentId && row.State == "ACTIVE"));
        Assert.True((await verify.LicenseSeats.SingleAsync(row => row.Id == seatId)).IsActive);
    }
}
