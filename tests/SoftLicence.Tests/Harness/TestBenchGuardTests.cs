using System.Net.Sockets;
using System.Reflection;
using Npgsql;
using Xunit;
using Xunit.Abstractions;
using Xunit.Sdk;

namespace SoftLicence.Tests.Harness;

/// <summary>
/// TKT-001775: the bench guard refuses a run whose settings are wrong and never refuses a
/// correct one. No PostgreSQL server is used here: the live facts come from a fake probe.
/// </summary>
public sealed class TestBenchGuardTests
{
    private const string Secret = "s3cret-Value-NeverPrinted";
    private const string Loopback = "Host=127.0.0.1;Port=5544;Username=postgres;Password=" + Secret + ";Database=sl_runtime";
    private const string Unpooled = Loopback + ";Pooling=false";
    private const string BugTraceUnpooled =
        "Host=127.0.0.1;Port=5544;Username=postgres;Password=" + Secret + ";Database=sl_bugtrace;Pooling=false";
    private const string ExclusiveClass = "SoftLicence.Tests.Server.RuntimeEnrollmentCorePostgreSqlTests";
    private const string ExclusiveMethod = "AssignmentDualWrite_ProductionRole_CannotWriteLedgerDirectly";
    private const string OrdinaryPostgreSqlClass = "SoftLicence.Tests.Server.LicenseBillingPostgreSqlTests";
    private const string UnitClass = "SoftLicence.Tests.Core.HardwareIdTests";

    [Fact]
    public void UnitTestsWithoutAnySettingAreNotRefused()
    {
        var probe = new FakeProbe();
        Assert.Empty(Evaluate(new(), probe, UnitClass));
        Assert.Equal(0, probe.InspectCalls);
    }

    [Theory]
    [InlineData(ExclusiveClass)]
    [InlineData(OrdinaryPostgreSqlClass)]
    [InlineData("SoftLicence.Tests.Server.AdminLicenseExtensionTests")]
    [InlineData("SoftLicence.Tests.Server.RuntimeEnrollmentCompatibilityTests")]
    [InlineData("SoftLicence.Tests.Server.PortalDeactivationPostgreSqlTests+Nested")]
    public void PostgreSqlTestsWithoutTheRuntimeVariableAreRefused(string testClass)
    {
        var violation = Assert.Single(Evaluate(new(), new FakeProbe(), testClass, UnitClass));
        Assert.Contains(TestBenchGuard.RuntimeVariable + " is not set", violation, StringComparison.Ordinal);
        Assert.Contains(TestBenchGuard.Launcher, violation, StringComparison.Ordinal);
    }

    [Theory]
    // The reference incident: no Pooling key at all, Npgsql then pools by default.
    [InlineData(Loopback)]
    [InlineData(Loopback + ";Pooling=true")]
    [InlineData(Loopback + ";POOLING = True")]
    // A text search for "Pooling=false" would accept these; the parser does not.
    [InlineData(Loopback + ";Pooling=false;Pooling=true")]
    [InlineData(Loopback + ";Application Name='Pooling=false'")]
    public void ExclusiveSessionTestsRequireAnUnpooledConnection(string connection)
    {
        var violations = EvaluateExclusive(Runtime(connection), new FakeProbe(), ExclusiveClass);
        var violation = Assert.Single(violations);
        Assert.Contains("must contain Pooling=false", violation, StringComparison.Ordinal);
        Assert.Contains("55006", violation, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(Loopback + ";Pooling=false")]
    [InlineData(Loopback + ";pooling = FALSE")]
    [InlineData(Loopback + ";POOLING=False;")]
    [InlineData(Loopback + ";Pooling=true;Pooling=false")]
    [InlineData("Pooling=false;" + Loopback)]
    public void AnUnpooledConnectionIsAcceptedWhateverItsSpelling(string connection) =>
        Assert.Empty(EvaluateExclusive(Runtime(connection), new FakeProbe(), ExclusiveClass));

    [Fact]
    public void TargetedPostgreSqlTestsThatDoNotCloneDatabasesMayKeepPooling() =>
        Assert.Empty(Evaluate(Runtime(Loopback), new FakeProbe(), OrdinaryPostgreSqlClass));

    [Theory]
    [InlineData("db.internal.example")]
    [InlineData("192.0.2.1")]
    [InlineData("198.51.100.30")]
    [InlineData("127.0.0.1,192.0.2.1")]
    [InlineData("localhost.example")]
    public void AServerThatIsNotLocalIsRefusedBeforeAnyConnection(string host)
    {
        var probe = new FakeProbe();
        var connection = $"Host={host};Username=postgres;Password={Secret};Database=sl_runtime;Pooling=false";
        var violation = Assert.Single(EvaluateExclusive(Runtime(connection), probe, ExclusiveClass));
        Assert.Contains("loopback", violation, StringComparison.Ordinal);
        Assert.Equal(0, probe.InspectCalls);
    }

    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("localhost")]
    [InlineData("LOCALHOST")]
    [InlineData("::1")]
    public void LoopbackHostsAreAccepted(string host)
    {
        var connection = $"Host={host};Username=postgres;Password={Secret};Database=sl_runtime;Pooling=false";
        Assert.Empty(EvaluateExclusive(Runtime(connection), new FakeProbe(), ExclusiveClass));
    }

    [Fact]
    public void AMissingHostIsRefused()
    {
        var connection = $"Username=postgres;Password={Secret};Database=sl_runtime;Pooling=false";
        Assert.Contains("loopback", Assert.Single(EvaluateExclusive(Runtime(connection), new FakeProbe(), ExclusiveClass)), StringComparison.Ordinal);
    }

    [Fact]
    public void AnUnparsableConnectionStringIsRefusedWithoutBeingRepeated()
    {
        var probe = new FakeProbe();
        var violations = Evaluate(Runtime(Loopback + ";NotAnNpgsqlKey=1"), probe, ExclusiveClass);
        var violation = Assert.Single(violations);
        Assert.Contains("not a valid Npgsql connection string", violation, StringComparison.Ordinal);
        Assert.DoesNotContain(Secret, TestBenchGuard.Format(violations), StringComparison.Ordinal);
        Assert.Equal(0, probe.InspectCalls);
    }

    [Fact]
    public void AnotherPostgreSqlMajorIsRefused()
    {
        var probe = new FakeProbe { Facts = GoodFacts with { ServerVersionNumber = 160004 } };
        var violation = Assert.Single(Evaluate(Runtime(Unpooled), probe, OrdinaryPostgreSqlClass));
        Assert.Contains("PostgreSQL 16", violation, StringComparison.Ordinal);
        Assert.Contains("PostgreSQL 17", violation, StringComparison.Ordinal);
    }

    [Fact]
    public void AnUnreachableServerIsRefusedWithoutThePassword()
    {
        var probe = new FakeProbe { Failure = new NpgsqlException("Failed to connect to 127.0.0.1:5544") };
        var violations = Evaluate(Runtime(Unpooled), probe, OrdinaryPostgreSqlClass);
        Assert.Contains("does not reach a PostgreSQL server", Assert.Single(violations), StringComparison.Ordinal);
        Assert.DoesNotContain(Secret, TestBenchGuard.Format(violations), StringComparison.Ordinal);
    }

    [Fact]
    public void AConnectionFailureIsNamedWithoutAnyProviderText()
    {
        // A provider message is neither bounded nor guaranteed free of connection details.
        var leaking = $"password authentication failed; connection string was Host=127.0.0.1;Password={Secret}";
        var refused = new FakeProbe { Failure = new PostgresException(leaking, "FATAL", "FATAL", "28P01") };
        var refusedMessage = TestBenchGuard.Format(Evaluate(Runtime(Unpooled), refused, OrdinaryPostgreSqlClass));
        Assert.Contains("(PostgresException, the password was refused)", refusedMessage, StringComparison.Ordinal);
        Assert.DoesNotContain("28P01", refusedMessage, StringComparison.Ordinal);
        Assert.DoesNotContain(Secret, refusedMessage, StringComparison.Ordinal);
        Assert.DoesNotContain("password authentication failed", refusedMessage, StringComparison.Ordinal);

        var closed = new FakeProbe
        {
            Failure = new NpgsqlException(leaking, new SocketException((int)SocketError.ConnectionRefused)),
        };
        var closedMessage = TestBenchGuard.Format(Evaluate(Runtime(Unpooled), closed, OrdinaryPostgreSqlClass));
        Assert.Contains("(NpgsqlException, socket error ConnectionRefused)", closedMessage, StringComparison.Ordinal);
        Assert.DoesNotContain(Secret, closedMessage, StringComparison.Ordinal);

        var odd = new FakeProbe { Failure = new PostgresException(leaking, "FATAL", "FATAL", Secret) };
        var oddMessage = TestBenchGuard.Format(Evaluate(Runtime(Unpooled), odd, OrdinaryPostgreSqlClass));
        Assert.Contains("(PostgresException)", oddMessage, StringComparison.Ordinal);
        Assert.DoesNotContain(Secret, oddMessage, StringComparison.Ordinal);
    }

    [Theory]
    // PostgreSQL lets a server answer any five-character SQLSTATE: the code is data chosen by
    // the other side and could carry a short secret. It is never printed.
    [InlineData("S3CR7")]
    [InlineData("PW123")]
    [InlineData("12345")]
    [InlineData("28p01")]
    [InlineData("28P01 ")]
    public void AnUnknownSqlStateIsNeverPrinted(string sqlState)
    {
        var probe = new FakeProbe { Failure = new PostgresException("refused", "FATAL", "FATAL", sqlState) };
        var message = TestBenchGuard.Format(Evaluate(Runtime(Unpooled), probe, OrdinaryPostgreSqlClass));
        Assert.Contains("(PostgresException)", message, StringComparison.Ordinal);
        Assert.DoesNotContain(sqlState.Trim(), message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("28P01", "the password was refused")]
    [InlineData("28000", "the login was refused")]
    [InlineData("3D000", "the database does not exist")]
    [InlineData("57P03", "the server is still starting")]
    [InlineData("53300", "the server has no connection left")]
    public void AKnownSqlStateIsExplainedByAFixedPhrase(string sqlState, string phrase)
    {
        var probe = new FakeProbe { Failure = new PostgresException("anything", "FATAL", "FATAL", sqlState) };
        var message = TestBenchGuard.Format(Evaluate(Runtime(Unpooled), probe, OrdinaryPostgreSqlClass));
        Assert.Contains($"(PostgresException, {phrase})", message, StringComparison.Ordinal);
        Assert.DoesNotContain(sqlState, message, StringComparison.Ordinal);
    }

    [Fact]
    public void TheProbeReceivesTheParsedConnectionOfTheRuntimeVariable()
    {
        var probe = new FakeProbe();
        Assert.Empty(Evaluate(Runtime(Unpooled), probe, OrdinaryPostgreSqlClass));
        Assert.Equal(1, probe.InspectCalls);
        Assert.Equal("sl_runtime", probe.LastConnection!.Database);
        Assert.Equal(5544, probe.LastConnection.Port);
    }

    [Fact]
    public void TheSourceCHarnessKeepsItsUnprivilegedPooledConnection()
    {
        // Its independently scheduled tests carry no exclusive-session trait.
        var settings = Runtime(Loopback);
        settings[TestBenchGuard.SourceCBootstrapVariable] = Unpooled;
        var probe = new FakeProbe { Facts = GoodFacts with { IsSuperuser = false } };
        Assert.Empty(Evaluate(settings, probe, ExclusiveClass));
    }

    [Fact]
    public void TheCompatibilityHarnessKeepsItsPooledConnectionOnTheSameClass()
    {
        // tests/Compatibility/Run-RuntimeCapabilityCompatibility.ps1: pooled, database runtime_compat.
        var connection = "Host=127.0.0.1;Port=25991;Database=runtime_compat;Username=postgres;Password=" + Secret;
        Assert.Empty(Evaluate(Runtime(connection), new FakeProbe(), ExclusiveClass));
    }

    [Fact]
    public void TheRemainingTestFromTheReferenceIncidentCarriesTheExclusiveSessionsTrait()
    {
        var baseType = typeof(SoftLicence.Tests.Server.RuntimeEnrollmentPostgreSqlTestBase);
        var declared = Assert.Single(baseType.Assembly.GetTypes()
            .Where(type => type != baseType && baseType.IsAssignableFrom(type))
            .Select(type => type.GetMethod(ExclusiveMethod, BindingFlags.Instance | BindingFlags.Public | BindingFlags.DeclaredOnly)),
            candidate => candidate is not null);
        Assert.Contains(declared!.GetCustomAttributesData(), attribute =>
            attribute.AttributeType == typeof(TraitAttribute)
            && (string?)attribute.ConstructorArguments[0].Value == TestBenchTraits.Name
            && (string?)attribute.ConstructorArguments[1].Value == TestBenchTraits.ExclusiveSessions);
    }

    [Fact]
    public void TheFullSuiteProfileRequiresBothConnectionsOnTheSameServer()
    {
        // Same port on IPv4 and IPv6 loopback can be two instances: only the server tells.
        var settings = FullSuite();
        settings[TestBenchGuard.BugTraceVariable] = BugTraceUnpooled.Replace("Host=127.0.0.1", "Host=::1", StringComparison.Ordinal);
        var probe = FullSuiteProbe();
        probe.FactsByDatabase["sl_bugtrace"] = GoodFacts with { ServerIdentity = "1791799999999999" };
        Assert.Contains("two different PostgreSQL servers",
            Assert.Single(EvaluateExclusive(settings, probe, ExclusiveClass)), StringComparison.Ordinal);

        // Another port that reaches the same instance is accepted.
        var samePortless = FullSuite();
        samePortless[TestBenchGuard.BugTraceVariable] = BugTraceUnpooled.Replace("Port=5544", "Port=5432", StringComparison.Ordinal);
        Assert.Empty(EvaluateExclusive(samePortless, FullSuiteProbe(), ExclusiveClass));
    }

    [Theory]
    [InlineData("192.0.2.1")]
    [InlineData("softlicence.example")]
    public void TheFullSuiteProfileNeverConnectsToARemoteBugTraceHost(string host)
    {
        var settings = FullSuite();
        settings[TestBenchGuard.BugTraceVariable] = BugTraceUnpooled.Replace("Host=127.0.0.1", "Host=" + host, StringComparison.Ordinal);
        var probe = FullSuiteProbe();
        var violation = Assert.Single(EvaluateExclusive(settings, probe, ExclusiveClass));
        Assert.Contains(TestBenchGuard.BugTraceVariable + " must target one loopback host", violation, StringComparison.Ordinal);
        Assert.Equal(new[] { "sl_runtime" }, probe.InspectedDatabases);
    }

    [Fact]
    public void ARefusedRunIsReportedOnTheFirstTestWithoutCreatingAnythingOfIt()
    {
        var assembly = new TestAssembly(Reflector.Wrap(typeof(TestBenchGuardTests).Assembly), null, null);
        var collection = new TestCollection(assembly, Reflector.Wrap(typeof(RefusalSampleCollection)), "refusal sample");
        var testClass = new TestClass(collection, Reflector.Wrap(typeof(RefusalSample)));
        var method = new TestMethod(testClass, Reflector.Wrap(
            typeof(RefusalSample).GetMethod(nameof(RefusalSample.Row), BindingFlags.Instance | BindingFlags.NonPublic)!));
        var sink = new RecordingSink();
        // One row of a theory: its unique ID differs from the ID of the method alone.
        var testCase = new XunitTestCase(sink, TestMethodDisplay.ClassAndMethod, TestMethodDisplayOptions.None, method, [true, "refusal"]);
        var methodOnly = new XunitTestCase(sink, TestMethodDisplay.ClassAndMethod, TestMethodDisplayOptions.None, method);
        Assert.NotEqual(methodOnly.UniqueID, testCase.UniqueID);

        TestBenchRefusal.Report(testCase, "TEST BENCH REFUSED: sample", sink);

        Assert.Equal(
            new[]
            {
                typeof(TestAssemblyStarting), typeof(TestCollectionStarting), typeof(TestClassStarting),
                typeof(TestMethodStarting), typeof(TestCaseStarting), typeof(TestStarting), typeof(TestFailed),
                typeof(TestFinished), typeof(TestCaseFinished), typeof(TestMethodFinished), typeof(TestClassFinished),
                typeof(TestCollectionFinished), typeof(TestAssemblyFinished),
            },
            sink.Messages.Select(message => message.GetType()).ToArray());
        var failed = Assert.Single(sink.Messages.OfType<TestFailed>());
        Assert.Equal("TEST BENCH REFUSED: sample", Assert.Single(failed.Messages));
        Assert.Same(testCase, failed.TestCase);
        Assert.Equal(testCase.UniqueID, failed.TestCase.UniqueID);
        Assert.Equal(testCase.DisplayName, failed.Test.DisplayName);
        var finished = Assert.Single(sink.Messages.OfType<TestAssemblyFinished>());
        Assert.Equal(1, finished.TestsRun);
        Assert.Equal(1, finished.TestsFailed);
        Assert.Equal(0, finished.TestsSkipped);
        // Neither the class, nor its class fixture, nor its collection fixture was built.
        Assert.Equal(0, RefusalSample.Created);
        Assert.Equal(0, RefusalSampleFixture.Created);
    }

    /// <summary>Stands for a test class whose fixtures would touch the refused bench.</summary>
    private sealed class RefusalSample : IClassFixture<RefusalSampleFixture>
    {
        public static int Created;

        public RefusalSample(RefusalSampleFixture fixture)
        {
            _ = fixture;
            Created++;
        }

        internal void Row(bool flag, string label)
        {
            _ = flag;
            _ = label;
        }
    }

    private sealed class RefusalSampleFixture
    {
        public static int Created;

        public RefusalSampleFixture() => Created++;
    }

    private sealed class RefusalSampleCollection : ICollectionFixture<RefusalSampleFixture>;

    private sealed class RecordingSink : LongLivedMarshalByRefObject, IMessageSink
    {
        public List<IMessageSinkMessage> Messages { get; } = [];

        public bool OnMessage(IMessageSinkMessage message)
        {
            Messages.Add(message);
            return true;
        }
    }

    [Fact]
    public void TheFullSuiteProfileProbesTheBugTraceDatabaseToo()
    {
        var unreachable = FullSuiteProbe();
        unreachable.FailureByDatabase["sl_bugtrace"] = new NpgsqlException("28P01: password authentication failed");
        var violations = EvaluateExclusive(FullSuite(), unreachable, ExclusiveClass);
        Assert.Contains(TestBenchGuard.BugTraceVariable + " does not reach", Assert.Single(violations), StringComparison.Ordinal);
        Assert.DoesNotContain(Secret, TestBenchGuard.Format(violations), StringComparison.Ordinal);

        var used = FullSuiteProbe();
        used.FactsByDatabase["sl_bugtrace"] = GoodFacts with { UserTables = 12 };
        Assert.Contains("BugTrace database already holds 12 table(s)",
            Assert.Single(EvaluateExclusive(FullSuite(), used, ExclusiveClass)), StringComparison.Ordinal);

        var accepted = FullSuiteProbe();
        Assert.Empty(EvaluateExclusive(FullSuite(), accepted, ExclusiveClass));
        Assert.Equal(new[] { "sl_runtime", "sl_bugtrace" }, accepted.InspectedDatabases);
    }

    [Fact]
    public void TheFullSuiteProfileAcceptsACompleteBench() =>
        Assert.Empty(EvaluateExclusive(FullSuite(), FullSuiteProbe(), ExclusiveClass, UnitClass));

    [Fact]
    public void TheFullSuiteProfileRequiresTheRuntimeVariableEvenForUnitTests()
    {
        var settings = FullSuite();
        settings.Remove(TestBenchGuard.RuntimeVariable);
        Assert.Contains(Evaluate(settings, FullSuiteProbe(), UnitClass),
            violation => violation.Contains(TestBenchGuard.RuntimeVariable + " is not set", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData(TestBenchGuard.BugTraceVariable, "is not set")]
    [InlineData(TestBenchGuard.ContainerVariable, "is not set")]
    [InlineData(TestBenchGuard.ConsumerRepositoryVariable, "is not set")]
    [InlineData(TestBenchGuard.CompatibilityEvidenceVariable, "is not set")]
    public void TheFullSuiteProfileRequiresEveryInput(string variable, string expected)
    {
        var settings = FullSuite();
        settings.Remove(variable);
        var violation = Assert.Single(EvaluateExclusive(settings, FullSuiteProbe(), ExclusiveClass));
        Assert.Contains(variable + " " + expected, violation, StringComparison.Ordinal);
    }

    [Fact]
    public void TheFullSuiteProfileRequiresExistingDirectories()
    {
        var probe = FullSuiteProbe();
        probe.Directories.Clear();
        var violations = EvaluateExclusive(FullSuite(), probe, ExclusiveClass);
        Assert.Equal(2, violations.Count);
        Assert.All(violations, violation => Assert.Contains("does not exist", violation, StringComparison.Ordinal));
    }

    [Fact]
    public void TheFullSuiteProfileRequiresTwoDistinctUnpooledDatabases()
    {
        var sameDatabase = FullSuite();
        sameDatabase[TestBenchGuard.BugTraceVariable] = Unpooled;
        Assert.Contains("two different databases", Assert.Single(EvaluateExclusive(sameDatabase, FullSuiteProbe(), ExclusiveClass)), StringComparison.Ordinal);

        var pooled = FullSuite();
        pooled[TestBenchGuard.BugTraceVariable] = BugTraceUnpooled.Replace(";Pooling=false", string.Empty, StringComparison.Ordinal);
        Assert.Contains(TestBenchGuard.BugTraceVariable + " must contain Pooling=false",
            Assert.Single(EvaluateExclusive(pooled, FullSuiteProbe(), ExclusiveClass)), StringComparison.Ordinal);

        // Database names differing only by case are two databases for PostgreSQL.
        var otherCase = FullSuite();
        otherCase[TestBenchGuard.BugTraceVariable] = Unpooled.Replace("sl_runtime", "SL_RUNTIME", StringComparison.Ordinal);
        Assert.Empty(EvaluateExclusive(otherCase, FullSuiteProbe(), ExclusiveClass));
    }

    [Fact]
    public void TheFullSuiteProfileRequiresAnUnpooledRuntimeConnectionEvenForUnitTests()
    {
        var settings = FullSuite();
        settings[TestBenchGuard.RuntimeVariable] = Loopback;
        Assert.Contains("must contain Pooling=false", Assert.Single(Evaluate(settings, FullSuiteProbe(), UnitClass)), StringComparison.Ordinal);
    }

    [Fact]
    public void TheFullSuiteProfileChecksTheLiveServer()
    {
        var probe = FullSuiteProbe();
        probe.Facts = GoodFacts with { IsSuperuser = false, OtherClientSessions = 1, UserTables = 3, MaxLocksPerTransaction = 64, AutovacuumEnabled = true };
        probe.FactsByDatabase["sl_bugtrace"] = GoodFacts;
        var violations = EvaluateExclusive(FullSuite(), probe, ExclusiveClass);
        Assert.Equal(5, violations.Count);
        Assert.Contains(violations, violation => violation.Contains("superuser", StringComparison.Ordinal));
        Assert.Contains(violations, violation => violation.Contains("1 other client session(s)", StringComparison.Ordinal));
        Assert.Contains(violations, violation => violation.Contains("already holds 3 table(s)", StringComparison.Ordinal));
        Assert.Contains(violations, violation => violation.Contains("max_locks_per_transaction is 64", StringComparison.Ordinal));
        Assert.Contains(violations, violation => violation.Contains("autovacuum is on", StringComparison.Ordinal));
    }

    [Fact]
    public void TheFullSuiteProfileRefusesTheSourceCHarnessVariable()
    {
        var settings = FullSuite();
        settings[TestBenchGuard.SourceCBootstrapVariable] = Unpooled;
        Assert.Contains(TestBenchGuard.SourceCBootstrapVariable + " is set",
            Assert.Single(EvaluateExclusive(settings, FullSuiteProbe(), ExclusiveClass)), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("FULL")]
    [InlineData("Full")]
    [InlineData(" full")]
    [InlineData("complete")]
    public void AnUnknownProfileIsRefusedInsteadOfBeingGuessed(string profile)
    {
        var settings = new Dictionary<string, string?> { [TestBenchGuard.ProfileVariable] = profile };
        Assert.Contains("unknown value", Assert.Single(Evaluate(settings, new FakeProbe(), UnitClass)), StringComparison.Ordinal);
    }

    [Fact]
    public void TheMessageSaysWhatToDoAndWhereTheProcedureIs()
    {
        var message = TestBenchGuard.Format(EvaluateExclusive(Runtime(Loopback), new FakeProbe(), ExclusiveClass));
        Assert.StartsWith("TEST BENCH REFUSED", message, StringComparison.Ordinal);
        Assert.Contains("no test was started", message, StringComparison.Ordinal);
        Assert.Contains(TestBenchGuard.Launcher, message, StringComparison.Ordinal);
        Assert.Contains("DOC-1310", message, StringComparison.Ordinal);
        Assert.DoesNotContain(Secret, message, StringComparison.Ordinal);
    }

    [Fact]
    public void TheAssemblyRunsEveryTestThroughTheGuardedFramework()
    {
        var attribute = typeof(TestBenchGuardTests).Assembly.GetCustomAttribute<TestFrameworkAttribute>();
        Assert.NotNull(attribute);
        var data = typeof(TestBenchGuardTests).Assembly.GetCustomAttributesData()
            .Single(candidate => candidate.AttributeType == typeof(TestFrameworkAttribute));
        Assert.Equal(typeof(GuardedTestFramework).FullName, (string?)data.ConstructorArguments[0].Value);
        Assert.Equal(typeof(GuardedTestFramework).Assembly.GetName().Name, (string?)data.ConstructorArguments[1].Value);
    }

    private static readonly TestBenchServerFacts GoodFacts =
        new(170002, IsSuperuser: true, OtherClientSessions: 0, UserTables: 0, MaxLocksPerTransaction: 1024, AutovacuumEnabled: false, ServerIdentity: "1791790000000000");

    private static IReadOnlyList<string> Evaluate(
        Dictionary<string, string?> settings, FakeProbe probe, params string[] testClasses) =>
        TestBenchGuard.Evaluate(
            new TestBenchRequest(name => settings.TryGetValue(name, out var value) ? value : null, testClasses, NeedsExclusiveSessions: false),
            probe);

    /// <summary>Same selection, with at least one test carrying the ExclusiveSessions trait.</summary>
    private static IReadOnlyList<string> EvaluateExclusive(
        Dictionary<string, string?> settings, FakeProbe probe, params string[] testClasses) =>
        TestBenchGuard.Evaluate(
            new TestBenchRequest(name => settings.TryGetValue(name, out var value) ? value : null, testClasses, NeedsExclusiveSessions: true),
            probe);

    private static Dictionary<string, string?> Runtime(string connection) =>
        new() { [TestBenchGuard.RuntimeVariable] = connection };

    private static Dictionary<string, string?> FullSuite() => new()
    {
        [TestBenchGuard.ProfileVariable] = TestBenchGuard.FullSuiteProfile,
        [TestBenchGuard.RuntimeVariable] = Unpooled,
        [TestBenchGuard.BugTraceVariable] = BugTraceUnpooled,
        [TestBenchGuard.ContainerVariable] = "softlicence-fullsuite-pg-0123456789ab",
        [TestBenchGuard.ConsumerRepositoryVariable] = @"D:\consumer",
        [TestBenchGuard.CompatibilityEvidenceVariable] = @"D:\evidence",
    };

    private static FakeProbe FullSuiteProbe()
    {
        var probe = new FakeProbe();
        probe.Directories.Add(@"D:\consumer");
        probe.Directories.Add(@"D:\evidence");
        return probe;
    }

    private sealed class FakeProbe : ITestBenchProbe
    {
        public TestBenchServerFacts Facts { get; set; } = GoodFacts;
        public Exception? Failure { get; init; }
        public HashSet<string> Directories { get; } = new(StringComparer.Ordinal);
        public int InspectCalls { get; private set; }
        public NpgsqlConnectionStringBuilder? LastConnection { get; private set; }

        public Dictionary<string, TestBenchServerFacts> FactsByDatabase { get; } = new(StringComparer.Ordinal);
        public Dictionary<string, Exception> FailureByDatabase { get; } = new(StringComparer.Ordinal);
        public List<string> InspectedDatabases { get; } = [];

        public TestBenchServerFacts InspectServer(NpgsqlConnectionStringBuilder connection)
        {
            InspectCalls++;
            LastConnection ??= connection;
            var database = connection.Database ?? string.Empty;
            InspectedDatabases.Add(database);
            if (FailureByDatabase.TryGetValue(database, out var failure))
                throw failure;
            if (Failure is not null)
                throw Failure;
            return FactsByDatabase.TryGetValue(database, out var facts) ? facts : Facts;
        }

        public bool DirectoryExists(string path) => Directories.Contains(path);
    }
}
