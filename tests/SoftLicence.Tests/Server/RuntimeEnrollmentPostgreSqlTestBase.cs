namespace SoftLicence.Tests.Server;

/// <summary>
/// Exposes the Runtime Enrollment PostgreSQL harness to independently schedulable test classes
/// without contributing inherited tests or mutable instance state.
/// </summary>
public abstract partial class RuntimeEnrollmentPostgreSqlTestBase
{
    /// <summary>Releases the historical alias seat and returns only its license identifier.</summary>
    /// <param name="scenario">Historical scenario to mutate.</param>
    /// <returns>The exact license identifier from the released historical graph.</returns>
    protected static async Task<Guid> ReleaseHistoricalAliasLicenseIdAsync(
        PreparedBootstrapScenario scenario) =>
        (await ReleaseHistoricalAliasSeatAsync(scenario)).LicenseId;
}
