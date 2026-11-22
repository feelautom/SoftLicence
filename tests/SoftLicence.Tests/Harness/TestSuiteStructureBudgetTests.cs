using System.Reflection;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SoftLicence.Server.Middlewares;
using Xunit;
using Xunit.Sdk;

namespace SoftLicence.Tests.Harness;

/// <summary>
/// Prevents the test suite from silently returning to oversized classes or adding direct
/// PostgreSQL migration replays without an explicit review of the established baseline.
/// </summary>
public sealed class TestSuiteStructureBudgetTests
{
    private const int MaximumCasesPerConcreteClass = 200;

    private static readonly IReadOnlyDictionary<string, int> ReviewedMigrationCallBaseline =
        new Dictionary<string, int>(StringComparer.Ordinal)
        {
            ["ApprovedBinariesPostgreSqlTests.cs"] = 1,
            ["BugTraceAutoReportPostgreSqlTests.cs"] = 1,
            ["CleanupServicePostgreSqlTests.cs"] = 3,
            ["CommercialOwnershipCommandPostgreSqlTests.cs"] = 1,
            ["EnrollmentAssignmentDualWritePostgreSqlTests.cs"] = 6,
            ["EnrollmentLicenseAssignmentPostgreSqlTests.cs"] = 7,
            ["LicenseDecisionHistoryCompatibilityPostgreSqlTests.cs"] = 1,
            ["LicenseRenewalIdempotencyPostgreSqlTests.cs"] = 1,
            ["PostgreSqlModelDatabase.cs"] = 1,
            // TKT-002466: one replay of the AllowPublicTrial migration over rows written at the previous boundary.
            ["PublicTrialMigrationPostgreSqlTests.cs"] = 1,
            ["RuntimeCommercialReattachmentPostgreSqlTests.cs"] = 3,
            ["RuntimeEnrollmentPostgreSqlTests.cs"] = 25,
            ["RuntimeEnrollmentSecurityLockPostgreSqlTests.cs"] = 6,
            ["RuntimeHardwareAuthorityMigrationPostgreSqlTests.cs"] = 5,
            ["RuntimeMigrationLineagePostgreSqlTests.cs"] = 3,
            ["RuntimeRecoveryCommercialOwnershipPostgreSqlTests.cs"] = 4,
            ["RuntimeRecoveryCommercialOwnershipRetentionPostgreSqlTests.cs"] = 3,
            ["RuntimeRememberedReleasePostgreSqlTests.cs"] = 2,
            ["RuntimeSeatRecoveryPostgreSqlTests.cs"] = 10,
            // TKT-002717: one replay of the TeamEligible migration over rows written at the previous boundary.
            ["TeamEligibleMigrationPostgreSqlTests.cs"] = 1,
            ["Tkt000557RepairScriptPostgreSqlTests.cs"] = 1,
            ["Tkt000672SourceCAuthorityPostgreSqlTests.cs"] = 1,
        };

    [Fact]
    public void EveryConcreteTestClassStaysWithinTheReviewedCaseBudget()
    {
        var assembly = typeof(TestSuiteStructureBudgetTests).Assembly;
        var oversized = assembly.GetTypes()
            .Where(type => type is { IsClass: true, IsAbstract: false })
            .Select(type => new { type.FullName, Cases = CountCases(type) })
            .Where(candidate => candidate.Cases > MaximumCasesPerConcreteClass)
            .OrderBy(candidate => candidate.FullName, StringComparer.Ordinal)
            .ToArray();

        Assert.True(
            oversized.Length == 0,
            "TEST STRUCTURE REFUSED: concrete xUnit classes may contain at most " +
            $"{MaximumCasesPerConcreteClass} discovered cases. Split the class so xUnit can schedule it independently. " +
            string.Join("; ", oversized.Select(candidate => $"{candidate.FullName}={candidate.Cases}")));
    }

    [Fact]
    public void PostgreSqlMigrationReplaySitesDoNotGrowWithoutExplicitReview()
    {
        var repositoryRoot = FindRepositoryRoot();
        var serverTests = Path.Combine(repositoryRoot, "tests", "SoftLicence.Tests", "Server");
        var violations = Directory.EnumerateFiles(serverTests, "*PostgreSql*.cs", SearchOption.TopDirectoryOnly)
            .Select(path => new
            {
                File = Path.GetFileName(path),
                Calls = CountEfMigrationReplayCalls(File.ReadAllText(path)),
            })
            .Where(candidate => candidate.Calls > 0)
            .Where(candidate =>
                !ReviewedMigrationCallBaseline.TryGetValue(candidate.File, out var reviewedCalls)
                || candidate.Calls > reviewedCalls)
            .OrderBy(candidate => candidate.File, StringComparer.Ordinal)
            .ToArray();

        Assert.True(
            violations.Length == 0,
            "TEST STRUCTURE REFUSED: a PostgreSQL test added a migration replay. Use PostgreSqlModelDatabase " +
            "and clone the migrated model, or update the reviewed baseline with a migration-specific justification. " +
            string.Join("; ", violations.Select(candidate => $"{candidate.File}={candidate.Calls}")));
    }

    [Fact]
    public void PostgreSqlMigrationReplayDetectionIgnoresBusinessHomonyms()
    {
        const string source = """
            await hardwareMigration.MigrateAsync();
            await database.Database.MigrateAsync();
            await database.GetService<IMigrator>().MigrateAsync();
            var migrator = database.GetService<IMigrator>();
            await migrator.MigrateAsync();
            """;

        Assert.Equal(3, CountEfMigrationReplayCalls(source));
    }

    [Fact]
    public async Task IntegrationAuditPersistenceCannotOutliveItsPostgreSqlFixture()
    {
        var persistenceStarted = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var allowPersistenceToFinish = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);

        var scheduled = AuditPersistenceScheduler.ScheduleAsync(
            waitForCompletion: true,
            async () =>
            {
                persistenceStarted.SetResult();
                await allowPersistenceToFinish.Task;
            });

        await persistenceStarted.Task.WaitAsync(TimeSpan.FromSeconds(1));
        Assert.True(
            !scheduled.IsCompleted,
            "TEST BENCH REFUSED (TKT-001959, DOC-1310): integration audit persistence must finish " +
            "before an isolated PostgreSQL fixture can be disposed.");

        allowPersistenceToFinish.SetResult();
        await scheduled.WaitAsync(TimeSpan.FromSeconds(1));
    }

    [Fact]
    public async Task ProductionAuditPersistenceRemainsDetached()
    {
        var persistenceStarted = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var allowPersistenceToFinish = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);

        var scheduled = AuditPersistenceScheduler.ScheduleAsync(
            waitForCompletion: false,
            async () =>
            {
                persistenceStarted.SetResult();
                await allowPersistenceToFinish.Task;
            });

        Assert.True(
            scheduled.IsCompletedSuccessfully,
            "Production audit persistence must retain its non-blocking scheduling contract.");
        await persistenceStarted.Task.WaitAsync(TimeSpan.FromSeconds(1));
        allowPersistenceToFinish.SetResult();
    }

    /// <summary>
    /// Counts only EF Core migration invocations, excluding unrelated domain methods that happen
    /// to use the same <c>Migrate</c> or <c>MigrateAsync</c> name.
    /// </summary>
    private static int CountEfMigrationReplayCalls(string source)
    {
        var root = CSharpSyntaxTree.ParseText(source).GetRoot();
        var migratorVariables = root.DescendantNodes()
            .OfType<VariableDeclaratorSyntax>()
            .Where(IsMigratorDeclaration)
            .Select(variable => variable.Identifier.ValueText)
            .ToHashSet(StringComparer.Ordinal);

        return root.DescendantNodes()
            .OfType<InvocationExpressionSyntax>()
            .Count(invocation => IsEfMigrationInvocation(invocation, migratorVariables));
    }

    /// <summary>Recognizes variables whose declared type or initializer proves they are EF migrators.</summary>
    private static bool IsMigratorDeclaration(VariableDeclaratorSyntax variable)
    {
        if (variable.Parent?.Parent is VariableDeclarationSyntax declaration
            && declaration.Type.ToString().EndsWith("IMigrator", StringComparison.Ordinal))
        {
            return true;
        }

        return variable.Initializer?.Value.DescendantNodesAndSelf()
            .OfType<GenericNameSyntax>()
            .Any(IsGetServiceOfMigrator) == true;
    }

    /// <summary>Recognizes EF Database extensions and calls through a proven IMigrator receiver.</summary>
    private static bool IsEfMigrationInvocation(
        InvocationExpressionSyntax invocation,
        IReadOnlySet<string> migratorVariables)
    {
        if (invocation.Expression is not MemberAccessExpressionSyntax member
            || member.Name.Identifier.ValueText is not ("Migrate" or "MigrateAsync"))
        {
            return false;
        }

        return member.Expression switch
        {
            MemberAccessExpressionSyntax receiver
                when receiver.Name.Identifier.ValueText == "Database" => true,
            InvocationExpressionSyntax receiver
                when receiver.Expression is MemberAccessExpressionSyntax service
                     && service.Name is GenericNameSyntax generic
                     && IsGetServiceOfMigrator(generic) => true,
            IdentifierNameSyntax receiver => migratorVariables.Contains(receiver.Identifier.ValueText),
            _ => false,
        };
    }

    /// <summary>Recognizes the exact generic service lookup for EF Core's IMigrator.</summary>
    private static bool IsGetServiceOfMigrator(GenericNameSyntax generic) =>
        generic.Identifier.ValueText == "GetService"
        && generic.TypeArgumentList.Arguments.Count == 1
        && generic.TypeArgumentList.Arguments[0].ToString().EndsWith("IMigrator", StringComparison.Ordinal);

    /// <summary>Counts the concrete xUnit cases that discovery can schedule for one runtime class.</summary>
    private static int CountCases(Type type) => type
        .GetMethods(BindingFlags.Instance | BindingFlags.Public)
        .Sum(CountCases);

    /// <summary>Expands data attributes so theory rows count as separate discovered cases.</summary>
    private static int CountCases(MethodInfo method)
    {
        var fact = method.GetCustomAttribute<FactAttribute>(inherit: true);
        if (fact is null)
            return 0;
        if (fact is not TheoryAttribute)
            return 1;

        var dataAttributes = method.GetCustomAttributes<DataAttribute>(inherit: true).ToArray();
        return dataAttributes.Length == 0
            ? 1
            : dataAttributes.Sum(attribute => attribute.GetData(method)?.Count() ?? 1);
    }

    /// <summary>Finds the owning worktree without relying on a caller-controlled current directory.</summary>
    private static string FindRepositoryRoot()
    {
        foreach (var start in new[] { AppContext.BaseDirectory, Directory.GetCurrentDirectory() })
        {
            var directory = new DirectoryInfo(start);
            while (directory is not null)
            {
                var marker = Path.Combine(directory.FullName, "tests", "SoftLicence.Tests", "SoftLicence.Tests.csproj");
                if (File.Exists(marker))
                    return directory.FullName;
                directory = directory.Parent;
            }
        }

        throw new InvalidOperationException("TEST STRUCTURE REFUSED: the SoftLicence repository root was not found.");
    }
}
