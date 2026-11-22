using System.Reflection;
using Xunit.Abstractions;
using Xunit.Sdk;

[assembly: Xunit.TestFramework("SoftLicence.Tests.Harness.GuardedTestFramework", "SoftLicence.Tests")]

namespace SoftLicence.Tests.Harness;

/// <summary>
/// xUnit entry point of this assembly. It evaluates <see cref="TestBenchGuard"/> once, before
/// any selected test case runs, and replaces the whole run by one failed result carrying the
/// guard message when the bench settings are wrong. Discovery is not affected.
/// </summary>
public sealed class GuardedTestFramework : XunitTestFramework
{
    public GuardedTestFramework(IMessageSink messageSink)
        : base(messageSink)
    {
    }

    protected override ITestFrameworkExecutor CreateExecutor(AssemblyName assemblyName) =>
        new GuardedTestFrameworkExecutor(assemblyName, SourceInformationProvider, DiagnosticMessageSink);
}

internal sealed class GuardedTestFrameworkExecutor : XunitTestFrameworkExecutor
{
    public GuardedTestFrameworkExecutor(
        AssemblyName assemblyName,
        ISourceInformationProvider sourceInformationProvider,
        IMessageSink diagnosticMessageSink)
        : base(assemblyName, sourceInformationProvider, diagnosticMessageSink)
    {
    }

    protected override void RunTestCases(
        IEnumerable<IXunitTestCase> testCases,
        IMessageSink executionMessageSink,
        ITestFrameworkExecutionOptions executionOptions)
    {
        var selected = testCases.ToList();
        if (selected.Count != 0)
        {
            var request = new TestBenchRequest(
                Environment.GetEnvironmentVariable,
                selected.Select(testCase => testCase.TestMethod.TestClass.Class.Name).Distinct(StringComparer.Ordinal).ToList(),
                selected.Any(RequiresExclusiveSessions));
            var violations = TestBenchGuard.Evaluate(request, new NpgsqlTestBenchProbe());
            if (violations.Count != 0)
            {
                var message = TestBenchGuard.Format(violations);
                Console.Error.WriteLine(message);
                // The normal runners are not used at all: they would build the collection and
                // class fixtures of the first test, and several of those open the refused
                // connection, create roles or migrate a database.
                TestBenchRefusal.Report(selected[0], message, executionMessageSink);
                return;
            }
        }

        base.RunTestCases(selected, executionMessageSink, executionOptions);
    }

    /// <summary>Trait names and values are code identifiers: exact, case-sensitive comparison.</summary>
    private static bool RequiresExclusiveSessions(IXunitTestCase testCase) =>
        testCase.Traits.TryGetValue(TestBenchTraits.Name, out var values)
        && values.Contains(TestBenchTraits.ExclusiveSessions, StringComparer.Ordinal);
}

/// <summary>
/// Reports a refused run as one failed result of the first selected test case, by sending the
/// xUnit execution messages directly. Nothing of the test is created or executed: no test class,
/// no constructor, no class fixture, no collection fixture. The reported case is the discovered
/// one, so its unique ID matches what the runner expects; a result reported under another ID
/// (as a substitute error case would be for one row of a theory) is silently dropped.
/// </summary>
internal static class TestBenchRefusal
{
    internal static void Report(ITestCase testCase, string message, IMessageSink sink)
    {
        ITestCase[] cases = [testCase];
        var method = testCase.TestMethod;
        var testClass = method.TestClass;
        var collection = testClass.TestCollection;
        var assembly = collection.TestAssembly;
        var test = new XunitTest((IXunitTestCase)testCase, testCase.DisplayName);

        // IMessageSink.OnMessage returns false to ask for cancellation. The sequence is still
        // closed symmetrically: a runner left with a started assembly would wait for ever.
        sink.OnMessage(new TestAssemblyStarting(cases, assembly, DateTime.Now, "SoftLicence test bench guard", "xUnit.net (guarded)"));
        sink.OnMessage(new TestCollectionStarting(cases, collection));
        sink.OnMessage(new TestClassStarting(cases, testClass));
        sink.OnMessage(new TestMethodStarting(cases, method));
        sink.OnMessage(new TestCaseStarting(testCase));
        sink.OnMessage(new TestStarting(test));
        sink.OnMessage(new TestFailed(
            test,
            0m,
            string.Empty,
            [typeof(InvalidOperationException).FullName!],
            [message],
            [string.Empty],
            [-1]));
        sink.OnMessage(new TestFinished(test, 0m, string.Empty));
        sink.OnMessage(new TestCaseFinished(testCase, 0m, 1, 1, 0));
        sink.OnMessage(new TestMethodFinished(cases, method, 0m, 1, 1, 0));
        sink.OnMessage(new TestClassFinished(cases, testClass, 0m, 1, 1, 0));
        sink.OnMessage(new TestCollectionFinished(cases, collection, 0m, 1, 1, 0));
        sink.OnMessage(new TestAssemblyFinished(cases, assembly, 0m, 1, 1, 0));
    }
}
