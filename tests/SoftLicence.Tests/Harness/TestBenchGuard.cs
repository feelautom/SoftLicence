using System.Net;
using System.Net.Sockets;
using Npgsql;

namespace SoftLicence.Tests.Harness;

/// <summary>What the guard needs to know about a test run before it starts.</summary>
/// <param name="ReadVariable">Reads one environment variable; null when it is not set.</param>
/// <param name="SelectedTestClasses">Full names of the classes owning the selected test cases.</param>
/// <param name="NeedsExclusiveSessions">
/// True when a selected test carries the <see cref="TestBenchTraits.ExclusiveSessions"/> trait.
/// </param>
internal sealed record TestBenchRequest(
    Func<string, string?> ReadVariable,
    IReadOnlyCollection<string> SelectedTestClasses,
    bool NeedsExclusiveSessions);

/// <summary>
/// xUnit trait declaring a bench requirement on one test. The Runtime Enrollment PostgreSQL
/// tests share one harness but run in independently schedulable classes, some of which use
/// purpose-built pooled harnesses (Source C, capability compatibility). The requirement remains
/// per test, not per class.
/// </summary>
internal static class TestBenchTraits
{
    internal const string Name = "TestBench";

    /// <summary>
    /// The test clones or drops a database and fails with PostgreSQL 55006, or refuses its own
    /// cleanup, when an idle pooled session of the test process is still attached to it.
    /// </summary>
    internal const string ExclusiveSessions = "ExclusiveSessions";
}

/// <summary>Facts read from the live PostgreSQL server by the bench probe.</summary>
/// <param name="ServerIdentity">
/// Opaque value that differs between two PostgreSQL instances: the cluster system identifier
/// when the role may read it, followed by the postmaster start time in microseconds. Compared
/// exactly, never parsed.
/// </param>
internal sealed record TestBenchServerFacts(
    int ServerVersionNumber,
    bool IsSuperuser,
    long OtherClientSessions,
    long UserTables,
    int MaxLocksPerTransaction,
    bool AutovacuumEnabled,
    string ServerIdentity);

/// <summary>Side-effect boundary of the guard, replaced by a fake in its own tests.</summary>
internal interface ITestBenchProbe
{
    /// <summary>Connects with the given builder and reads the server facts, or throws.</summary>
    TestBenchServerFacts InspectServer(NpgsqlConnectionStringBuilder connection);

    bool DirectoryExists(string path);
}

/// <summary>
/// Refuses a test run whose bench settings are known to make it fail late (TKT-001775). A full
/// suite once ran 55 minutes before reporting a connection string without <c>Pooling=false</c>.
/// Connection strings are always read through <see cref="NpgsqlConnectionStringBuilder"/>, never
/// by text search, so key casing, spacing, aliases and repeated keys follow Npgsql's own rules.
/// A connection string is a secret: no message ever contains one, nor any text produced by the
/// driver or the server, which is neither bounded nor guaranteed free of connection details.
/// No connection is ever opened to a host that is not loopback.
/// </summary>
internal static class TestBenchGuard
{
    internal const string RuntimeVariable = "SOFTLICENCE_RUNTIME_TEST_POSTGRES";
    internal const string SourceCBootstrapVariable = "SOFTLICENCE_RUNTIME_TEST_POSTGRES_BOOTSTRAP";
    internal const string BugTraceVariable = "SOFTLICENCE_BUGTRACE_TEST_POSTGRES";
    internal const string ContainerVariable = "SOFTLICENCE_RUNTIME_TEST_POSTGRES_CONTAINER";
    internal const string ConsumerRepositoryVariable = "SOFTLICENCE_RUNTIME_CONSUMER_REPOSITORY";
    internal const string CompatibilityEvidenceVariable = "SOFTLICENCE_RUNTIME_COMPAT_EVIDENCE";

    /// <summary>Set to <see cref="FullSuiteProfile"/> by scripts/Test-FullSuite.ps1 only.</summary>
    internal const string ProfileVariable = "SOFTLICENCE_TEST_SUITE";
    internal const string FullSuiteProfile = "full";

    internal const int RequiredPostgreSqlMajor = 17;
    internal const int RequiredMaxLocksPerTransaction = 1024;
    internal const string Launcher = "scripts/Test-FullSuite.ps1";
    internal const string Guide = "documentation DOC-1310";

    /// <summary>Classes that read the runtime connection without "PostgreSql" in their name.</summary>
    private static readonly string[] OtherPostgreSqlClasses =
    [
        "AdminLicenseExtensionTests",
        "RuntimeEnrollmentCompatibilityTests",
    ];

    /// <summary>Returns every violated prerequisite; an empty list lets the run start.</summary>
    internal static IReadOnlyList<string> Evaluate(TestBenchRequest request, ITestBenchProbe probe)
    {
        var violations = new List<string>();
        var profile = request.ReadVariable(ProfileVariable);
        // The profile is a machine code written by the launcher: exact value, no case folding.
        var fullSuite = string.Equals(profile, FullSuiteProfile, StringComparison.Ordinal);
        if (!string.IsNullOrEmpty(profile) && !fullSuite)
            violations.Add($"{ProfileVariable} holds an unknown value. Only '{FullSuiteProfile}' is defined, and only {Launcher} sets it.");

        var simpleNames = request.SelectedTestClasses.Select(SimpleName).ToHashSet(StringComparer.Ordinal);
        var needsPostgreSql = simpleNames.Any(IsPostgreSqlClass);

        NpgsqlConnectionStringBuilder? runtimeConnection = null;
        TestBenchServerFacts? runtimeFacts = null;
        var runtime = request.ReadVariable(RuntimeVariable);
        if (string.IsNullOrWhiteSpace(runtime))
        {
            if (fullSuite || needsPostgreSql)
                violations.Add($"{RuntimeVariable} is not set, and this selection contains PostgreSQL tests. "
                    + $"Run the complete suite with {Launcher}, or a targeted launcher from scripts/, which start a disposable PostgreSQL {RequiredPostgreSqlMajor} container.");
        }
        else if ((runtimeConnection = TryParse(RuntimeVariable, runtime, violations)) is not null)
        {
            // Counted before the host check: a connection is opened only when the string itself
            // raised no objection, in particular about its host.
            var before = violations.Count;
            RequireLoopback(RuntimeVariable, runtimeConnection, violations);
            if ((fullSuite || request.NeedsExclusiveSessions) && runtimeConnection.Pooling)
                violations.Add($"{RuntimeVariable} must contain Pooling=false. "
                    + "The selection contains tests that clone or drop databases; an idle pooled session makes PostgreSQL answer 55006 and the suite only reports it at the end.");
            var sourceC = !string.IsNullOrWhiteSpace(request.ReadVariable(SourceCBootstrapVariable));
            if (fullSuite && sourceC)
                violations.Add($"{SourceCBootstrapVariable} is set: that is the Source C harness (scripts/Invoke-Tkt000672SourceCAuthority.ps1), which cannot be combined with the full-suite profile.");
            if ((fullSuite || needsPostgreSql) && violations.Count == before)
                runtimeFacts = InspectServer(RuntimeVariable, runtimeConnection, probe, violations);
            if (runtimeFacts is not null)
                RequireRuntimeServer(runtimeFacts, fullSuite, violations);
        }

        if (fullSuite)
            RequireFullSuiteInputs(request, runtimeConnection, runtimeFacts, probe, violations);
        return violations;
    }

    /// <summary>Builds the single failure message shown instead of the test run.</summary>
    internal static string Format(IReadOnlyList<string> violations) =>
        "TEST BENCH REFUSED (TKT-001775): no test was started because the bench settings are wrong."
        + Environment.NewLine
        + string.Join(Environment.NewLine, violations.Select(violation => " - " + violation))
        + Environment.NewLine
        + $"Fix the settings above, or run {Launcher} through file-lourde. Procedure: {Guide}.";

    /// <summary>Opens the bounded probe connection; reports a failure without any provider text.</summary>
    private static TestBenchServerFacts? InspectServer(
        string variable, NpgsqlConnectionStringBuilder connection, ITestBenchProbe probe, List<string> violations)
    {
        try
        {
            return probe.InspectServer(connection);
        }
        catch (Exception exception) when (exception is NpgsqlException or TimeoutException or InvalidOperationException or SocketException)
        {
            violations.Add($"{variable} does not reach a PostgreSQL server within 5 seconds ({DescribeFailure(exception)}). "
                + "Check that the disposable container is running and that the port, user and password are current.");
            return null;
        }
    }

    /// <summary>
    /// SQLSTATE values the guard is willing to explain, each with a fixed phrase. A server may
    /// answer any five-character code, so the code itself is never printed: an unknown one is
    /// simply not explained. Compared exactly, as machine codes.
    /// </summary>
    private static readonly Dictionary<string, string> KnownFailures = new(StringComparer.Ordinal)
    {
        ["28P01"] = "the password was refused",
        ["28000"] = "the login was refused",
        ["3D000"] = "the database does not exist",
        ["57P03"] = "the server is still starting",
        ["53300"] = "the server has no connection left",
    };

    /// <summary>
    /// Names a connection failure with closed vocabularies only: the exception type, a fixed
    /// phrase for a few known SQLSTATE values, or the socket error name (an enumeration). No
    /// text chosen by the driver or the server is ever used, the SQLSTATE included.
    /// </summary>
    private static string DescribeFailure(Exception exception)
    {
        var description = exception.GetType().Name;
        for (var current = exception; current is not null; current = current.InnerException)
        {
            if (current is PostgresException { SqlState: { } state } && KnownFailures.TryGetValue(state, out var phrase))
                return $"{description}, {phrase}";
            if (current is SocketException socket && Enum.IsDefined(socket.SocketErrorCode))
                return $"{description}, socket error {socket.SocketErrorCode}";
        }

        return description;
    }

    private static void RequireRuntimeServer(TestBenchServerFacts facts, bool fullSuite, List<string> violations)
    {
        var major = facts.ServerVersionNumber / 10000;
        if (major != RequiredPostgreSqlMajor)
            violations.Add($"The server is PostgreSQL {major}; the tests require PostgreSQL {RequiredPostgreSqlMajor} (image postgres:{RequiredPostgreSqlMajor}).");
        if (!fullSuite)
            return;
        if (!facts.IsSuperuser)
            violations.Add($"{RuntimeVariable} must log in as a superuser of the disposable server: the suite creates roles and creates or drops databases.");
        if (facts.OtherClientSessions != 0)
            violations.Add($"{facts.OtherClientSessions} other client session(s) are connected to the server. Close them (psql, IDE, another test run): the suite requires a server it owns alone.");
        if (facts.UserTables != 0)
            violations.Add($"The target database already holds {facts.UserTables} table(s). The suite requires a fresh database on a fresh container.");
        if (facts.MaxLocksPerTransaction < RequiredMaxLocksPerTransaction)
            violations.Add($"max_locks_per_transaction is {facts.MaxLocksPerTransaction}; start PostgreSQL with -c max_locks_per_transaction={RequiredMaxLocksPerTransaction}.");
        if (facts.AutovacuumEnabled)
            violations.Add("autovacuum is on; start PostgreSQL with -c autovacuum=off so no background worker holds a database being dropped.");
    }

    private static void RequireFullSuiteInputs(
        TestBenchRequest request,
        NpgsqlConnectionStringBuilder? runtimeConnection,
        TestBenchServerFacts? runtimeFacts,
        ITestBenchProbe probe,
        List<string> violations)
    {
        var bugTrace = request.ReadVariable(BugTraceVariable);
        if (string.IsNullOrWhiteSpace(bugTrace))
        {
            violations.Add($"{BugTraceVariable} is not set (BugTraceAutoReportPostgreSqlTests needs its own database).");
        }
        else if (TryParse(BugTraceVariable, bugTrace, violations) is { } bugTraceConnection)
        {
            // Counted before the host check: a string that is refused is never connected to.
            var before = violations.Count;
            RequireLoopback(BugTraceVariable, bugTraceConnection, violations);
            if (bugTraceConnection.Pooling)
                violations.Add($"{BugTraceVariable} must contain Pooling=false.");
            // Database names are compared exactly: PostgreSQL keeps the case of quoted names.
            if (runtimeConnection is not null
                && string.Equals(runtimeConnection.Database, bugTraceConnection.Database, StringComparison.Ordinal))
                violations.Add($"{BugTraceVariable} and {RuntimeVariable} must name two different databases.");

            if (violations.Count == before
                && InspectServer(BugTraceVariable, bugTraceConnection, probe, violations) is { } bugTraceFacts)
                RequireBugTraceDatabase(bugTraceFacts, runtimeFacts, violations);
        }

        if (string.IsNullOrWhiteSpace(request.ReadVariable(ContainerVariable)))
            violations.Add($"{ContainerVariable} is not set (the real psql wrapper tests run psql inside the disposable container).");
        RequireDirectory(request, ConsumerRepositoryVariable, "the read-only Desktop repository used by the compatibility tests", probe, violations);
        RequireDirectory(request, CompatibilityEvidenceVariable, "the output directory of the compatibility evidence", probe, violations);
    }

    /// <summary>A wrong port or password on the second connection must not surface an hour later.</summary>
    private static void RequireBugTraceDatabase(
        TestBenchServerFacts facts, TestBenchServerFacts? runtimeFacts, List<string> violations)
    {
        var major = facts.ServerVersionNumber / 10000;
        if (major != RequiredPostgreSqlMajor)
            violations.Add($"{BugTraceVariable} reaches PostgreSQL {major}; the tests require PostgreSQL {RequiredPostgreSqlMajor}.");
        if (!facts.IsSuperuser)
            violations.Add($"{BugTraceVariable} must log in as a superuser of the disposable server.");
        if (facts.UserTables != 0)
            violations.Add($"The BugTrace database already holds {facts.UserTables} table(s). The suite requires a fresh database.");
        // The identity is an opaque server value: exact comparison. Hosts and ports cannot tell
        // two instances apart (localhost, 127.0.0.1 and ::1 may be three different servers).
        if (runtimeFacts is not null && !string.Equals(facts.ServerIdentity, runtimeFacts.ServerIdentity, StringComparison.Ordinal))
            violations.Add($"{BugTraceVariable} and {RuntimeVariable} reach two different PostgreSQL servers; both must target the same disposable container.");
    }

    private static void RequireDirectory(
        TestBenchRequest request, string variable, string meaning, ITestBenchProbe probe, List<string> violations)
    {
        var path = request.ReadVariable(variable);
        if (string.IsNullOrWhiteSpace(path))
            violations.Add($"{variable} is not set ({meaning}).");
        else if (!probe.DirectoryExists(path))
            violations.Add($"{variable} names a directory that does not exist ({meaning}).");
    }

    private static NpgsqlConnectionStringBuilder? TryParse(string variable, string value, List<string> violations)
    {
        try
        {
            return new NpgsqlConnectionStringBuilder(value);
        }
        catch (Exception exception) when (exception is ArgumentException or FormatException or KeyNotFoundException)
        {
            // Never repeat the value or the parser message: both may contain the password.
            violations.Add($"{variable} is not a valid Npgsql connection string ({exception.GetType().Name}). "
                + "Expected the form Host=127.0.0.1;Port=<port>;Username=postgres;Password=<password>;Database=<database>;Pooling=false.");
            return null;
        }
    }

    /// <summary>
    /// The tests create fixed-password roles and drop databases: only a local disposable server
    /// is acceptable. Host names are case-insensitive; addresses are compared as addresses.
    /// </summary>
    private static void RequireLoopback(string variable, NpgsqlConnectionStringBuilder connection, List<string> violations)
    {
        var host = connection.Host;
        var local = !string.IsNullOrWhiteSpace(host)
            && !host.Contains(',')
            && (string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase)
                || (IPAddress.TryParse(host, out var address) && IPAddress.IsLoopback(address)));
        if (!local)
            violations.Add($"{variable} must target one loopback host (127.0.0.1, ::1 or localhost). "
                + "The tests create roles and drop databases and must never reach a shared or production server.");
    }

    private static bool IsPostgreSqlClass(string simpleName) =>
        simpleName.Contains("PostgreSql", StringComparison.Ordinal)
        || OtherPostgreSqlClasses.Contains(simpleName, StringComparer.Ordinal);

    /// <summary>Type names are compiler identifiers: exact, case-sensitive comparison.</summary>
    private static string SimpleName(string fullName)
    {
        var nested = fullName.Split('+')[0];
        var separator = nested.LastIndexOf('.');
        return separator < 0 ? nested : nested[(separator + 1)..];
    }
}

/// <summary>Reads the live server facts with a short, unpooled connection.</summary>
internal sealed class NpgsqlTestBenchProbe : ITestBenchProbe
{
    public TestBenchServerFacts InspectServer(NpgsqlConnectionStringBuilder connection)
    {
        var bounded = new NpgsqlConnectionStringBuilder(connection.ConnectionString)
        {
            Pooling = false,
            Timeout = 5,
            CommandTimeout = 5,
        };
        using var session = new NpgsqlConnection(bounded.ConnectionString);
        session.Open();
        using var command = new NpgsqlCommand("""
            SELECT current_setting('server_version_num')::int,
                   (SELECT rolsuper FROM pg_catalog.pg_roles WHERE rolname = current_user),
                   (SELECT count(*) FROM pg_catalog.pg_stat_activity
                    WHERE backend_type = 'client backend' AND pid <> pg_catalog.pg_backend_pid()),
                   (SELECT count(*) FROM pg_catalog.pg_tables
                    WHERE schemaname NOT IN ('pg_catalog', 'information_schema')),
                   current_setting('max_locks_per_transaction')::int,
                   current_setting('autovacuum') = 'on',
                   (extract(epoch FROM pg_catalog.pg_postmaster_start_time()) * 1000000)::bigint::text;
            """, session);
        TestBenchServerFacts facts;
        using (var reader = command.ExecuteReader())
        {
            if (!reader.Read())
                throw new InvalidOperationException("The server returned no bench facts.");
            facts = new TestBenchServerFacts(
                reader.GetInt32(0),
                !reader.IsDBNull(1) && reader.GetBoolean(1),
                reader.GetInt64(2),
                reader.GetInt64(3),
                reader.GetInt32(4),
                reader.GetBoolean(5),
                reader.GetString(6));
        }

        return facts with { ServerIdentity = ReadSystemIdentifier(session) + ":" + facts.ServerIdentity };
    }

    /// <summary>
    /// The system identifier is unique to a cluster and readable by PUBLIC by default. A role
    /// that was denied it (a deliberately unprivileged harness) keeps the start time alone
    /// instead of failing the probe: the identity is only compared under the full-suite
    /// profile, whose role is a superuser.
    /// </summary>
    private static string ReadSystemIdentifier(NpgsqlConnection session)
    {
        try
        {
            using var command = new NpgsqlCommand(
                "SELECT system_identifier::text FROM pg_catalog.pg_control_system();", session);
            return command.ExecuteScalar() as string ?? string.Empty;
        }
        catch (PostgresException)
        {
            return string.Empty;
        }
    }

    public bool DirectoryExists(string path) => Directory.Exists(path);
}
