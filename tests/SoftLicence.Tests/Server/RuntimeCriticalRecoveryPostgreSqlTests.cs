using System.Net;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using Npgsql;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

public sealed partial class RuntimeEnrollmentPostgreSqlTests
{
    [Fact]
    public async Task CriticalRecovery_BlocksBeforeCapabilityReplay_ResolvesGenerationAndRefetches()
    {
        var connections = await ProvisionIsolatedAsync();
        var factory = new TestDbFactory(connections.App);
        var fixture = await SeedAuthorityAsync(factory);
        var otherFixture = await SeedAuthorityAsync(factory);
        string hardwareId;
        await using (var seed = await factory.CreateDbContextAsync())
        {
            var binding = await seed.DistributionInstallationBindings.SingleAsync(row => row.Id == fixture.BindingId);
            var seat = await seed.LicenseSeats.SingleAsync(row => row.Id == binding.LicenseSeatId);
            hardwareId = seat.HardwareId.ToUpperInvariant();
            seat.HardwareId = hardwareId;
            binding.HardwareIdHash = Sha256(hardwareId);
            await seed.SaveChangesAsync();
        }

        using var activeSigning = CreateSigningKey(ActiveSigningPrivateKey);
        using var nextSigning = CreateSigningKey(NextSigningPrivateKey);
        using var enrollmentKey = RSA.Create(3072);
        using var ackKey = RSA.Create(2048);
        var options = RuntimeOptions(fixture.ProductId, activeSigning, nextSigning);
        await UpsertKeyRegistryAsync(connections.Admin, options);
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["CanaryAck:PrivateKeyPem"] = ackKey.ExportPkcs8PrivateKeyPem()
        }).Build();
        var authority = new RuntimeEnrollmentAuthorityService(factory, Options.Create(options));
        var registry = new RuntimeEnrollmentKeyRegistryService(factory, Options.Create(options));
        using var crypto = new RuntimeEnrollmentCryptoService(Options.Create(options));
        var service = new RuntimeEnrollmentService(
            factory,
            authority,
            registry,
            crypto,
            Options.Create(options),
            new CanaryAckService(factory, configuration, TimeProvider.System));

        var prepared = await service.PrepareAsync(
            "website-step1",
            Sha256("critical-recovery-prepare"),
            PrepareRequest(fixture, Guid.NewGuid().ToString("D"), enrollmentKey));
        var enrollmentId = Guid.Parse(prepared.Response.EnrollmentId);
        var confirmDigest = Sha256("critical-recovery-confirm");
        await service.ConfirmAsync(enrollmentId, confirmDigest, new RuntimeEnrollmentConfirmRequest
        {
            Schema = RuntimeEnrollmentService.ConfirmSchema,
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            EnrollmentId = enrollmentId.ToString("D"),
            Epoch = 1
        }, Proof(enrollmentKey, "confirm", enrollmentId, options.ConfirmAudience,
            prepared.Response.Challenge, confirmDigest), IPAddress.Loopback);

        await using (var mismatchedScope = await factory.CreateDbContextAsync())
        {
            mismatchedScope.RuntimeCriticalIncidents.Add(new SoftLicence.Server.Data.RuntimeCriticalIncident
            {
                EnrollmentId = enrollmentId,
                BindingId = otherFixture.BindingId,
                ProductId = otherFixture.ProductId,
                InstallationId = otherFixture.InstallationId,
                EventId = Guid.NewGuid().ToString("D"),
                Trigger = "RuntimeCheck_NativeDllSwapped",
                State = "OPEN",
                OpenedSecurityEpoch = 1,
                OpenedAuthorityEpoch = 0,
                OpenedAtUtc = DateTime.UtcNow
            });
            var mismatch = await Assert.ThrowsAsync<DbUpdateException>(() =>
                mismatchedScope.SaveChangesAsync());
            Assert.Equal(PostgresErrorCodes.ForeignKeyViolation,
                Assert.IsType<PostgresException>(mismatch.InnerException).SqlState);
        }
        await using (var mismatchedInstallation = await factory.CreateDbContextAsync())
        {
            mismatchedInstallation.RuntimeCriticalIncidents.Add(
                new SoftLicence.Server.Data.RuntimeCriticalIncident
                {
                    EnrollmentId = enrollmentId,
                    BindingId = fixture.BindingId,
                    ProductId = fixture.ProductId,
                    InstallationId = otherFixture.InstallationId,
                    EventId = Guid.NewGuid().ToString("D"),
                    Trigger = "RuntimeCheck_NativeDllSwapped",
                    State = "OPEN",
                    OpenedSecurityEpoch = 1,
                    OpenedAuthorityEpoch = 0,
                    OpenedAtUtc = DateTime.UtcNow
                });
            var mismatch = await Assert.ThrowsAsync<DbUpdateException>(() =>
                mismatchedInstallation.SaveChangesAsync());
            Assert.Equal(PostgresErrorCodes.ForeignKeyViolation,
                Assert.IsType<PostgresException>(mismatch.InnerException).SqlState);
        }
        await using (var mismatchedRecovery = await factory.CreateDbContextAsync())
        {
            mismatchedRecovery.RuntimeCriticalRecoveries.Add(
                new SoftLicence.Server.Data.RuntimeCriticalRecovery
                {
                    EnrollmentId = enrollmentId,
                    BindingId = fixture.BindingId,
                    ProductId = fixture.ProductId,
                    InstallationId = otherFixture.InstallationId,
                    RequestedEventId = Guid.NewGuid().ToString("D"),
                    OldSecurityEpoch = 1,
                    NewSecurityEpoch = 2,
                    ResolvedIncidentCount = 1,
                    AuthorityEpoch = 0,
                    RecoveredByClientId = "security-operator",
                    RecoveredByKeyId = "operator-key",
                    RecoveredAtUtc = DateTime.UtcNow
                });
            var mismatch = await Assert.ThrowsAsync<DbUpdateException>(() =>
                mismatchedRecovery.SaveChangesAsync());
            Assert.Equal(PostgresErrorCodes.ForeignKeyViolation,
                Assert.IsType<PostgresException>(mismatch.InnerException).SqlState);
        }

        var capabilityRequest = new RuntimeEnrollmentCapabilityRequest
        {
            Schema = RuntimeEnrollmentService.CapabilitySchema,
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            EnrollmentId = enrollmentId.ToString("D"),
            Epoch = 1,
            SecurityEpoch = 1,
            InstallationId = fixture.InstallationId,
            ReleaseVersion = fixture.Version,
            SessionId = Guid.NewGuid().ToString("D"),
            Audience = "https://broker.example.test",
            Scope = ["runtime.execute"],
            Binaries = CapabilityBinaries()
        };
        var capabilityDigest = Sha256("critical-recovery-capability");
        var frozenCapabilityProof = Proof(enrollmentKey, "capability", enrollmentId,
            capabilityRequest.Audience, "-", capabilityDigest);
        var issuedBeforeIncident = await service.CreateCapabilityAsync(
            enrollmentId, capabilityDigest, capabilityRequest, frozenCapabilityProof, IPAddress.Loopback);
        Assert.False(issuedBeforeIncident.Idempotent);

        var firstEvent = await OpenCriticalAsync("first");
        var secondEvent = await OpenCriticalAsync("second");

        var blockedReplay = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            service.CreateCapabilityAsync(
                enrollmentId, capabilityDigest, capabilityRequest, frozenCapabilityProof, IPAddress.Loopback));
        Assert.Equal(StatusCodes.Status423Locked, blockedReplay.StatusCode);
        Assert.Equal("critical_incident_unresolved", blockedReplay.ErrorCode);

        var recoveryRequest = new RuntimeCriticalRecoveryRequest
        {
            Schema = RuntimeEnrollmentService.CriticalRecoverySchema,
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            RequestId = Guid.NewGuid().ToString("D"),
            ProductId = fixture.ProductId.ToString("D"),
            EnrollmentId = enrollmentId.ToString("D"),
            BindingId = fixture.BindingId.ToString("D"),
            InstallationId = fixture.InstallationId,
            EventId = firstEvent,
            OldSecurityEpoch = 1,
            NewSecurityEpoch = 2
        };
        var recoveryDigest = Sha256("critical-recovery-exact-body");
        var recovered = await Task.WhenAll(
            service.RecoverCriticalAsync("security-operator", "operator-key", recoveryDigest, recoveryRequest),
            service.RecoverCriticalAsync("security-operator", "operator-key", recoveryDigest, recoveryRequest));
        Assert.Single(recovered, result => !result.Idempotent);
        Assert.Single(recovered, result => result.Idempotent);
        Assert.Single(recovered.Select(result => Convert.ToBase64String(result.ExactResponseBody)).Distinct());
        Assert.All(recovered, result => Assert.Equal(2, result.Response.NewSecurityEpoch));
        AssertRecoverySignature(recovered[0].Response, activeSigning);
        var previousTrustEntry = new RuntimeCapabilitySigningKeyOptions
        {
            KeyId = recovered[0].Response.KeyId,
            Role = "previous",
            PublicKeyPem = activeSigning.ExportSubjectPublicKeyInfoPem(),
            RetainUntilUtc = DateTimeOffset.UtcNow.AddHours(25)
        };
        Assert.Null(previousTrustEntry.PrivateKeyPem);
        using (var previousVerifier = RSA.Create())
        {
            previousVerifier.ImportFromPem(previousTrustEntry.PublicKeyPem);
            AssertRecoverySignature(recovered[0].Response, previousVerifier);
        }

        await using (var check = await factory.CreateDbContextAsync())
        {
            Assert.Equal(2, (await check.RuntimeEnrollments.SingleAsync(row => row.Id == enrollmentId)).SecurityEpoch);
            Assert.Equal(2, await check.RuntimeCriticalIncidents.CountAsync(row =>
                row.BindingId == fixture.BindingId && row.State == "RESOLVED"));
            Assert.False(await check.RuntimeCriticalIncidents.AnyAsync(row =>
                row.BindingId == fixture.BindingId && row.InstallationId == fixture.InstallationId && row.State == "OPEN"));
            var recovery = await check.RuntimeCriticalRecoveries.SingleAsync();
            Assert.Equal(2, recovery.ResolvedIncidentCount);
            Assert.Single(await check.RuntimeCriticalRecoveryReceipts.ToListAsync());
        }

        var stalePostRecoveryProof = Proof(enrollmentKey, "capability", enrollmentId,
            capabilityRequest.Audience, "-", capabilityDigest);
        var staleEpoch = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            service.CreateCapabilityAsync(
                enrollmentId, capabilityDigest, capabilityRequest,
                stalePostRecoveryProof, IPAddress.Loopback));
        Assert.Equal(StatusCodes.Status409Conflict, staleEpoch.StatusCode);
        Assert.Equal("security_epoch_mismatch", staleEpoch.ErrorCode);

        var clientRefetch = new RuntimeCriticalRecoveryClientRefetchRequest
        {
            Schema = RuntimeEnrollmentService.CriticalRecoveryClientRefetchSchema,
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            RequestId = Guid.NewGuid().ToString("D"),
            EnrollmentId = enrollmentId.ToString("D"),
            Epoch = 1,
            SecurityEpoch = 1
        };
        var clientRefetchDigest = Sha256("critical-recovery-client-refetch-body");
        var clientRefetchProof = Proof(
            enrollmentKey, "critical-recovery-refetch", enrollmentId,
            options.ConfirmAudience, "-", clientRefetchDigest);
        var clientReceipt = await service.RefetchCriticalRecoveryForClientAsync(
            enrollmentId, clientRefetchDigest, clientRefetch,
            clientRefetchProof, IPAddress.Loopback);
        Assert.Equal(1, clientReceipt.Response.OldSecurityEpoch);
        Assert.Equal(2, clientReceipt.Response.NewSecurityEpoch);
        Assert.Equal(firstEvent, clientReceipt.Response.EventId);
        AssertRecoverySignature(clientReceipt.Response, activeSigning);

        capabilityRequest.SecurityEpoch = 2;
        var postRecoveryProof = Proof(enrollmentKey, "capability", enrollmentId,
            capabilityRequest.Audience, "-", capabilityDigest);
        Assert.False((await service.CreateCapabilityAsync(
            enrollmentId, capabilityDigest, capabilityRequest, postRecoveryProof, IPAddress.Loopback)).Idempotent);

        var refetch = new RuntimeCriticalRecoveryRefetchRequest
        {
            Schema = RuntimeEnrollmentService.CriticalRecoveryRefetchSchema,
            ProtocolVersion = RuntimeEnrollmentService.ProtocolVersion,
            RequestId = Guid.NewGuid().ToString("D"),
            ProductId = fixture.ProductId.ToString("D"),
            RecoveryId = recovered[0].Response.RecoveryId,
            BindingId = fixture.BindingId.ToString("D"),
            InstallationId = fixture.InstallationId,
            EventId = firstEvent,
            NewSecurityEpoch = 2
        };
        var refetchDigest = Sha256("critical-recovery-refetch-body");
        var refreshed = await service.RefetchCriticalRecoveryAsync(
            "security-operator", "operator-key", refetchDigest, refetch);
        var refreshedReplay = await service.RefetchCriticalRecoveryAsync(
            "security-operator", "rotated-operator-key", refetchDigest, refetch);
        Assert.False(refreshed.Idempotent);
        Assert.True(refreshedReplay.Idempotent);
        Assert.Equal(refreshed.ExactResponseBody, refreshedReplay.ExactResponseBody);
        AssertRecoverySignature(refreshed.Response, activeSigning);

        await using (var mutation = await factory.CreateDbContextAsync())
        {
            var binding = await mutation.DistributionInstallationBindings
                .SingleAsync(row => row.Id == fixture.BindingId);
            var license = await mutation.Licenses.SingleAsync(row => row.Id == binding.LicenseId);
            license.IsActive = false;
            license.RevokedAt = DateTime.UtcNow;
            await mutation.SaveChangesAsync();
        }
        await AssertStoredReceiptsRejectedAsync("authority_ineligible");
        await using (var restore = await factory.CreateDbContextAsync())
        {
            var binding = await restore.DistributionInstallationBindings
                .SingleAsync(row => row.Id == fixture.BindingId);
            var license = await restore.Licenses.SingleAsync(row => row.Id == binding.LicenseId);
            license.IsActive = true;
            license.RevokedAt = null;
            await restore.SaveChangesAsync();
        }

        await using (var mutation = await factory.CreateDbContextAsync())
        {
            var binding = await mutation.DistributionInstallationBindings
                .SingleAsync(row => row.Id == fixture.BindingId);
            binding.State = "invalidated";
            binding.InvalidatedAtUtc = DateTime.UtcNow;
            binding.InvalidationReason = "recovery replay regression";
            await mutation.SaveChangesAsync();
        }
        await AssertStoredReceiptsRejectedAsync("binding_ineligible");
        await using (var restore = await factory.CreateDbContextAsync())
        {
            var binding = await restore.DistributionInstallationBindings
                .SingleAsync(row => row.Id == fixture.BindingId);
            binding.State = "active";
            binding.InvalidatedAtUtc = null;
            binding.InvalidationReason = null;
            await restore.SaveChangesAsync();
        }

        await using (var mutation = await factory.CreateDbContextAsync())
        {
            var enrollment = await mutation.RuntimeEnrollments.SingleAsync(row => row.Id == enrollmentId);
            enrollment.State = "INVALIDATED";
            enrollment.InvalidatedAtUtc = DateTime.UtcNow;
            enrollment.InvalidationReason = "recovery replay regression";
            await mutation.SaveChangesAsync();
        }
        await AssertStoredReceiptsRejectedAsync();
        await using (var restore = await factory.CreateDbContextAsync())
        {
            var enrollment = await restore.RuntimeEnrollments.SingleAsync(row => row.Id == enrollmentId);
            enrollment.State = "ACTIVE";
            enrollment.InvalidatedAtUtc = null;
            enrollment.InvalidationReason = null;
            await restore.SaveChangesAsync();
        }

        await using (var expire = await factory.CreateDbContextAsync())
        {
            var receipts = await expire.RuntimeCriticalRecoveryReceipts.ToListAsync();
            foreach (var receipt in receipts)
            {
                receipt.IssuedAtUtc = DateTime.UtcNow.AddHours(-26);
                receipt.ExpiresAtUtc = DateTime.UtcNow.AddHours(-2);
            }
            await expire.SaveChangesAsync();
            await expire.Database.ExecuteSqlRawAsync("""
                UPDATE public."RuntimeCriticalRecoveryReceipts"
                SET "ExactResponseBody" = NULL,
                    "DeliveryPurgedAtUtc" = clock_timestamp()
                WHERE "ExactResponseBody" IS NOT NULL
                  AND "ExpiresAtUtc" <= clock_timestamp();
                """);
        }
        await AssertStoredReceiptsRejectedAsync("recovery_receipt_expired");
        await using (var tombstones = await factory.CreateDbContextAsync())
        {
            Assert.Equal(2, await tombstones.RuntimeCriticalRecoveryReceipts.CountAsync());
            Assert.False(await tombstones.RuntimeCriticalRecoveryReceipts
                .AnyAsync(receipt => receipt.ExactResponseBody != null));
            Assert.Single(await tombstones.RuntimeCriticalRecoveries.ToListAsync());
            Assert.Equal(2, (await tombstones.RuntimeEnrollments
                .SingleAsync(row => row.Id == enrollmentId)).SecurityEpoch);
        }

        var postExpiryRefetch = new RuntimeCriticalRecoveryRefetchRequest
        {
            Schema = refetch.Schema,
            ProtocolVersion = refetch.ProtocolVersion,
            RequestId = Guid.NewGuid().ToString("D"),
            ProductId = refetch.ProductId,
            RecoveryId = refetch.RecoveryId,
            BindingId = refetch.BindingId,
            InstallationId = refetch.InstallationId,
            EventId = refetch.EventId,
            NewSecurityEpoch = refetch.NewSecurityEpoch
        };
        var postExpiryDelivery = await service.RefetchCriticalRecoveryAsync(
            "security-operator", "operator-key", Sha256("post-expiry-refetch"), postExpiryRefetch);
        Assert.False(postExpiryDelivery.Idempotent);
        Assert.NotEmpty(postExpiryDelivery.ExactResponseBody);
        AssertRecoverySignature(postExpiryDelivery.Response, activeSigning);

        var thirdEvent = await OpenCriticalAsync("third");
        var staleRefetchRequest = new RuntimeCriticalRecoveryRefetchRequest
        {
            Schema = refetch.Schema,
            ProtocolVersion = refetch.ProtocolVersion,
            RequestId = Guid.NewGuid().ToString("D"),
            ProductId = refetch.ProductId,
            RecoveryId = refetch.RecoveryId,
            BindingId = refetch.BindingId,
            InstallationId = refetch.InstallationId,
            EventId = refetch.EventId,
            NewSecurityEpoch = refetch.NewSecurityEpoch
        };
        var staleRefetch = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            service.RefetchCriticalRecoveryAsync(
                "security-operator", "operator-key", Sha256("new-refetch"), staleRefetchRequest));
        Assert.Equal("recovery_generation_conflict", staleRefetch.ErrorCode);

        var wrongGeneration = recoveryRequest;
        wrongGeneration.RequestId = Guid.NewGuid().ToString("D");
        wrongGeneration.EventId = thirdEvent;
        var generationConflict = await Assert.ThrowsAsync<RuntimeEnrollmentException>(() =>
            service.RecoverCriticalAsync(
                "security-operator", "operator-key", Sha256("wrong-generation"), wrongGeneration));
        Assert.Equal("recovery_binding_conflict", generationConflict.ErrorCode);

        await using var admin = new NpgsqlConnection(connections.Admin);
        await admin.OpenAsync();
        await using (var appRole = new NpgsqlConnection(connections.App))
        {
            await appRole.OpenAsync();
            Assert.True(await ScalarAsync<bool>(appRole, """
                SELECT pg_catalog.has_table_privilege(current_user,
                           'public."RuntimeCriticalIncidents"', 'SELECT,INSERT,UPDATE')
                   AND NOT pg_catalog.has_table_privilege(current_user,
                           'public."RuntimeCriticalIncidents"', 'DELETE,TRUNCATE')
                   AND pg_catalog.has_table_privilege(current_user,
                           'public."RuntimeCriticalRecoveries"', 'SELECT,INSERT,UPDATE')
                   AND NOT pg_catalog.has_table_privilege(current_user,
                           'public."RuntimeCriticalRecoveries"', 'DELETE,TRUNCATE')
                   AND pg_catalog.has_table_privilege(current_user,
                           'public."RuntimeCriticalRecoveryReceipts"', 'SELECT,INSERT,UPDATE')
                   AND NOT pg_catalog.has_table_privilege(current_user,
                           'public."RuntimeCriticalRecoveryReceipts"', 'DELETE,TRUNCATE')
                   AND pg_catalog.has_table_privilege(current_user,
                           'public."RuntimeEnrollmentAuthorityStates"', 'SELECT')
                   AND NOT pg_catalog.has_table_privilege(current_user,
                           'public."RuntimeEnrollmentAuthorityStates"', 'INSERT,UPDATE,DELETE,TRUNCATE')
                   AND pg_catalog.has_table_privilege(current_user,
                           'public."RuntimeEnrollmentKeyRegistries"', 'SELECT')
                   AND NOT pg_catalog.has_table_privilege(current_user,
                           'public."RuntimeEnrollmentKeyRegistries"', 'INSERT,UPDATE,DELETE,TRUNCATE');
                """));
        }
        await ExecuteAsync(admin, "SET enable_seqscan = off;");
        await using var explain = admin.CreateCommand();
        explain.CommandText = "EXPLAIN SELECT 1 FROM public.\"RuntimeCriticalIncidents\" WHERE \"BindingId\"=@binding AND \"InstallationId\"=@installation AND \"State\"='OPEN';";
        explain.Parameters.AddWithValue("binding", fixture.BindingId);
        explain.Parameters.AddWithValue("installation", fixture.InstallationId);
        var plan = string.Join('\n', await ReadRowsAsync(explain));
        Assert.Contains("IX_RuntimeCriticalIncidents_BindingId_InstallationId_State", plan, StringComparison.Ordinal);

        await ExecuteAsync(admin, "DELETE FROM public.\"RuntimeCanaryProofNonces\";");
        await using var durable = await factory.CreateDbContextAsync();
        Assert.Equal(3, await durable.RuntimeCriticalIncidents.CountAsync());

        async Task AssertStoredReceiptsRejectedAsync(string? expectedErrorCode = null)
        {
            var recoveryReplay = await CaptureAsync(() => service.RecoverCriticalAsync(
                "security-operator", "operator-key", recoveryDigest, recoveryRequest));
            var refetchReplay = await CaptureAsync(() => service.RefetchCriticalRecoveryAsync(
                "security-operator", "rotated-operator-key", refetchDigest, refetch));

            Assert.Null(recoveryReplay.Result);
            Assert.Null(refetchReplay.Result);
            var recoveryError = Assert.IsType<RuntimeEnrollmentException>(recoveryReplay.Error);
            var refetchError = Assert.IsType<RuntimeEnrollmentException>(refetchReplay.Error);
            Assert.False(recoveryError.StatusCode is >= 200 and < 300);
            Assert.False(refetchError.StatusCode is >= 200 and < 300);
            if (expectedErrorCode != null)
            {
                Assert.Equal(expectedErrorCode, recoveryError.ErrorCode);
                Assert.Equal(expectedErrorCode, refetchError.ErrorCode);
            }
        }

        async Task<string> OpenCriticalAsync(string suffix)
        {
            var canary = new CanaryPingRequest
            {
                Schema = CanaryAckService.Schema,
                EventId = Guid.NewGuid().ToString("D"),
                SentAtUtc = FormatUtc(DateTimeOffset.UtcNow),
                HardwareId = hardwareId,
                AppVersion = fixture.Version,
                Trigger = "RuntimeCheck_NativeDllSwapped",
                Severity = 3
            };
            var digest = Sha256("critical-canary-" + suffix);
            await service.ProcessCanaryAsync(enrollmentId, digest, canary,
                CanaryProof(enrollmentKey, enrollmentId, canary.EventId!, digest, options),
                IPAddress.Loopback);
            return canary.EventId!;
        }
    }

    private static void AssertRecoverySignature(RuntimeCriticalRecoveryResponse response, RSA key)
    {
        var signature = DecodeBase64Url(response.Signature);
        var payload = RuntimeEnrollmentCryptoService.BuildRecoverySignaturePayload(
            response with { Signature = string.Empty });
        Assert.True(key.VerifyData(
            Encoding.UTF8.GetBytes(payload),
            signature,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pss));
        Assert.False(key.VerifyData(
            Encoding.UTF8.GetBytes(RuntimeEnrollmentCryptoService.BuildRecoverySignaturePayload(
                response with { BindingId = Guid.NewGuid().ToString("D"), Signature = string.Empty })),
            signature,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pss));
        Assert.False(key.VerifyData(
            Encoding.UTF8.GetBytes(payload.Replace(
                RuntimeEnrollmentService.CriticalRecoveryResponseSchema,
                "runtime-enrollment-capability-v1",
                StringComparison.Ordinal)),
            signature,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pss));
    }

    private static async Task<IReadOnlyList<string>> ReadRowsAsync(NpgsqlCommand command)
    {
        var rows = new List<string>();
        await using var reader = await command.ExecuteReaderAsync();
        while (await reader.ReadAsync())
            rows.Add(reader.GetString(0));
        return rows;
    }
}
