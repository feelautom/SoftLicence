using Microsoft.EntityFrameworkCore;
using SoftLicence.SDK;
using SoftLicence.Server.Data;
using SoftLicence.Tests.Core;
using Xunit;
using SdkLicenseService = SoftLicence.SDK.LicenseService;

namespace SoftLicence.Tests.Server;

public sealed partial class PublicTrialTypeExposurePostgreSqlTests
{
    /// <summary>
    /// TKT-002466, audit stage A point 2: the recipe played through the real SDK client (<see cref="SoftLicenceClient"/>,
    /// <c>RequestTrialAsync</c> and <c>ActivateAsync</c>) against the in-process server, with a synthetic product and the
    /// two synthetic types of the audit recipe. Only the process-wide WMI reader is replaced, so the client sends the UUID,
    /// HWID and physical-machine evidence of a synthetic computer instead of the runner's own (a virtual machine).
    /// </summary>
    /// <remarks>Serialized with every class that replaces the machine-identity readers.</remarks>
    [Collection(MachineIdentityReadersCollection.Name)]
    public sealed class SdkRecipe
    {
        /// <summary>Opted-in recurring free type of the audit recipe.</summary>
        private const string FreeSlug = "GRATUIT-TEST";
        /// <summary>Closed recurring paid type of the audit recipe.</summary>
        private const string PaidRecipeSlug = "PAYANT-TEST";
        /// <summary>Closed paid type whose slug satisfies the AUTO-TRIAL interception.</summary>
        private const string PaidRecipeAutoTrialSlug = "PAYANT-TEST-FREE-TRIAL";

        /// <summary>
        /// 2.1 to 2.4: paid type refused in three spellings, AUTO-TRIAL key refused, open free type delivered and bound
        /// to the hardware. Renewal by the trial route exists only for the slug it still hard-codes (TKT-001889): an open
        /// recurring type with another slug is not renewed once expired (LICENSE_EXPIRED since TKT-002468, nothing written);
        /// the hard-coded Community slug is renewed while opted in, then refused without any write once closed.
        /// </summary>
        [Fact]
        [Trait(Harness.TestBenchTraits.Name, Harness.TestBenchTraits.ExclusiveSessions)]
        public async Task Tkt2466_SdkRecipe_RefusalsDeliveryAndRenewal()
        {
            await using var f = await Fixture.CreateAsync();
            await f.AddTypeAsync(FreeSlug, durationDays: 30, TrialParams, isFree: true, allowPublicTrial: true, isRecurring: true);
            await f.AddTypeAsync(HardCodedCommunitySlug, durationDays: 30, TrialParams, isFree: true, allowPublicTrial: true, isRecurring: true);
            await f.AddTypeAsync(PaidRecipeSlug, durationDays: 30, PaidParams, isRecurring: true);
            await f.AddTypeAsync(PaidRecipeAutoTrialSlug, durationDays: 30, PaidParams, isRecurring: true);
            var client = CreateClient(f);

            var machine = Machine.Create();
            using (UseSyntheticPhysicalComputer(machine))
            {
                foreach (var slug in new[] { PaidRecipeSlug, "payant-test", " PAYANT-TEST " })
                {
                    var refused = await client.RequestTrialAsync(f.ProductName, typeSlug: slug, appVersion: "1.0.0");
                    AssertTypedRefusal(refused, $"RequestTrialAsync « {slug} »");
                }
                AssertTypedRefusal(await client.ActivateAsync(PaidRecipeAutoTrialSlug, f.ProductName, appVersion: "1.0.0"), "ActivateAsync AUTO-TRIAL");
                await using (var empty = f.Db())
                {
                    Assert.False(await empty.Licenses.AnyAsync());
                    Assert.False(await empty.LicenseSeats.AnyAsync());
                }

                var delivered = await client.RequestTrialAsync(f.ProductName, typeSlug: FreeSlug, appVersion: "1.0.0");
                Assert.True(delivered.IsSuccess, delivered.ErrorMessage);
                var validation = SdkLicenseService.ValidateLicenseDetailed(delivered.LicenseFile!, f.PublicKeyXml, machine.HardwareId);
                Assert.True(validation.IsValid, validation.ErrorMessage);
                Assert.Equal(FreeSlug, validation.License!.TypeSlug);
                Assert.Equal(LicenseValidationErrorCode.HardwareIdMismatch,
                    SdkLicenseService.ValidateLicenseDetailed(delivered.LicenseFile!, f.PublicKeyXml, Machine.Create().HardwareId).ErrorCode);

                // Open recurring type, slug other than the hard-coded one: never renewed by the trial route; explicit
                // LICENSE_EXPIRED refusal since TKT-002468 (previously an accidental 503, run #459 evidence).
                await f.ExpireLicenseAsync(validation.License.Id);
                var beforeOpenExpired = await f.RightsSnapshotAsync();
                var notRenewed = await client.RequestTrialAsync(f.ProductName, typeSlug: FreeSlug, appVersion: "1.0.0");
                Assert.False(notRenewed.IsSuccess, "an open recurring type with another slug is not renewed by the trial route");
                Assert.Null(notRenewed.LicenseFile);
                Assert.True(notRenewed.ServerErrorCode == LicenceExpired, $"{notRenewed.ServerErrorCode} {notRenewed.ErrorMessage}");
                Assert.Equal(beforeOpenExpired, await f.RightsSnapshotAsync());
            }

            var communityMachine = Machine.Create();
            using (UseSyntheticPhysicalComputer(communityMachine))
            {
                var community = await client.RequestTrialAsync(f.ProductName, typeSlug: HardCodedCommunitySlug, appVersion: "1.0.0");
                Assert.True(community.IsSuccess, community.ErrorMessage);
                var communityId = SdkLicenseService.ValidateLicenseDetailed(community.LicenseFile!, f.PublicKeyXml, communityMachine.HardwareId).License!.Id;

                await f.ExpireLicenseAsync(communityId);
                var renewed = await client.RequestTrialAsync(f.ProductName, typeSlug: HardCodedCommunitySlug, appVersion: "1.0.0");
                Assert.True(renewed.IsSuccess, renewed.ErrorMessage);
                var renewedValidation = SdkLicenseService.ValidateLicenseDetailed(renewed.LicenseFile!, f.PublicKeyXml, communityMachine.HardwareId);
                Assert.True(renewedValidation.IsValid, renewedValidation.ErrorMessage);
                Assert.Equal(communityId, renewedValidation.License!.Id);
                Assert.InRange(renewedValidation.License.ExpirationDate!.Value, DateTime.UtcNow.AddDays(29), DateTime.UtcNow.AddDays(31));

                await f.SetOptInAsync(HardCodedCommunitySlug, allowPublicTrial: false);
                var expiredAt = await f.ExpireLicenseAsync(communityId);
                var beforeClosed = await f.RightsSnapshotAsync();
                var closed = await client.RequestTrialAsync(f.ProductName, typeSlug: HardCodedCommunitySlug, appVersion: "1.0.0");
                // Closed type: typed opt-in refusal before the held licence is even read (TKT-002468; previously an
                // accidental 503 authority_unavailable, run #457 evidence). Nothing is committed.
                AssertTypedRefusal(closed, "closed type: an expired licence must not be renewed nor delivered");
                Assert.Equal(beforeClosed, await f.RightsSnapshotAsync());

                await using var db = f.Db();
                Assert.Equal(expiredAt, (await db.Licenses.AsNoTracking().SingleAsync(l => l.Id == communityId)).ExpirationDate);
                Assert.Equal(1, await db.LicenseHistories.CountAsync(h => h.LicenseId == communityId && h.Action == HistoryActions.Renewed));
            }
        }

        /// <summary>
        /// 2.5: a paid licence issued by the administrator API and activated on the hardware, once expired, does not
        /// prevent a new free licence from the public route, and is itself left untouched (no extension, no renewal).
        /// </summary>
        [Fact]
        [Trait(Harness.TestBenchTraits.Name, Harness.TestBenchTraits.ExclusiveSessions)]
        public async Task Tkt2466_SdkRecipe_ExpiredPaidLicence_ThenFreeTrial_LeavesPaidIntact()
        {
            await using var f = await Fixture.CreateAsync();
            await f.AddTypeAsync(FreeSlug, durationDays: 30, TrialParams, isFree: true, allowPublicTrial: true, isRecurring: true);
            await f.AddTypeAsync(PaidRecipeSlug, durationDays: 30, PaidParams, isRecurring: true);
            var machine = Machine.Create();
            using var wmi = UseSyntheticPhysicalComputer(machine);
            var client = CreateClient(f);

            var key = await f.AdminCreateLicenseAsync(PaidRecipeSlug);
            var paid = await client.ActivateAsync(key, f.ProductName, appVersion: "1.0.0");
            Assert.True(paid.IsSuccess, paid.ErrorMessage);
            var paidId = SdkLicenseService.ValidateLicenseDetailed(paid.LicenseFile!, f.PublicKeyXml, machine.HardwareId).License!.Id;
            var expiredAt = await f.ExpireLicenseAsync(paidId);

            var free = await client.RequestTrialAsync(f.ProductName, typeSlug: FreeSlug, appVersion: "1.0.0");

            Assert.True(free.IsSuccess, free.ErrorMessage);
            var validation = SdkLicenseService.ValidateLicenseDetailed(free.LicenseFile!, f.PublicKeyXml, machine.HardwareId);
            Assert.True(validation.IsValid, validation.ErrorMessage);
            Assert.Equal(FreeSlug, validation.License!.TypeSlug);
            Assert.NotEqual(paidId, validation.License.Id);
            Assert.Equal("community", validation.License.Features["tier"]);
            await using var db = f.Db();
            var paidRow = await db.Licenses.AsNoTracking().SingleAsync(l => l.Id == paidId);
            Assert.Equal(expiredAt, paidRow.ExpirationDate);
            Assert.Equal(0, await db.LicenseHistories.CountAsync(h => h.LicenseId == paidId && h.Action == HistoryActions.Renewed));
            Assert.Equal(key, paidRow.LicenseKey);
        }

        /// <summary>Asserts the SDK maps the server refusal to a typed failure carrying the opt-in code and no file.</summary>
        /// <param name="result">SDK result.</param>
        /// <param name="label">Call label for the failure message.</param>
        private static void AssertTypedRefusal(ActivationResult result, string label)
        {
            Assert.False(result.IsSuccess, label);
            Assert.Null(result.LicenseFile);
            Assert.True(result.ServerErrorCode == PublicTrialNotAllowed, $"{label} : {result.ServerErrorCode} {result.ErrorMessage}");
        }

        /// <summary>SDK client wired to the in-process host; the client is owned by the fixture.</summary>
        /// <param name="f">Fixture owning the host.</param>
        private static SoftLicenceClient CreateClient(Fixture f) =>
            new(f.Client.BaseAddress!.ToString().TrimEnd('/'), f.PublicKeyXml, f.Client);

        /// <summary>Makes the SDK read the UUID and the physical-computer evidence of <paramref name="machine"/>.</summary>
        /// <param name="machine">Synthetic computer.</param>
        /// <returns>The restore handle of the replaced readers.</returns>
        private static IDisposable UseSyntheticPhysicalComputer(Machine machine)
        {
            var wmi = MachineIdentity.UseWmiQueryReaderForTests((className, properties) => className switch
            {
                "Win32_ComputerSystemProduct" => WmiQueryResult.Success(new IReadOnlyDictionary<string, string?>[]
                {
                    new Dictionary<string, string?> { ["UUID"] = machine.SystemUuid }
                }),
                "Win32_ComputerSystem" => WmiQueryResult.Success(new IReadOnlyDictionary<string, string?>[]
                {
                    new Dictionary<string, string?> { ["Manufacturer"] = "Dell Inc.", ["Model"] = "Precision 7680", ["HypervisorPresent"] = "False" }
                }),
                _ => WmiQueryResult.Success(new IReadOnlyDictionary<string, string?>[]
                {
                    properties.ToDictionary(property => property, property => (string?)(className + "." + property))
                })
            });
            var registry = MachineIdentity.UseRegistryValueReaderForTests((_, _, _) => MachineEvidenceValue.Unsupported());
            return new CompositeRestore(registry, wmi);
        }

        /// <summary>Restores both readers in reverse order.</summary>
        /// <param name="First">Restored first.</param>
        /// <param name="Second">Restored second.</param>
        private sealed record CompositeRestore(IDisposable First, IDisposable Second) : IDisposable
        {
            /// <inheritdoc />
            public void Dispose()
            {
                First.Dispose();
                Second.Dispose();
            }
        }
    }
}
