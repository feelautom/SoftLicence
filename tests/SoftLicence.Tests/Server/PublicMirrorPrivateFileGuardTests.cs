using System.Text.Json;
using System.Text.RegularExpressions;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>
/// TKT-004182 permanent guard: no test that the public GitHub workflow runs may name a file that
/// <c>scripts/Sync-PublicRepo.ps1</c> leaves out of the public mirror.
/// </summary>
/// <remarks>
/// <para>
/// The public workflow <c>.github/workflows/publish.yml</c> runs this test project in the public mirror with a VSTest
/// filter. A test that reads a private file (for example <c>deploy.ps1</c>) without being filtered out passes here and
/// fails there, right after the mirror is pushed: it broke the SDK 1.1.15 and 2.0.0 publications and would have broken
/// 3.0.0.
/// </para>
/// <para>
/// Why a static check and not a replay of the public workflow in the private CI: the mirror is built by
/// <c>Sync-PublicRepo.ps1</c>, which depends on <c>robocopy</c> and Windows paths and cannot run on the private Linux CI
/// runner; replaying it would mean porting the publication tool itself. This guard reads the three sources of
/// truth instead of copying them (review 2532): the test filter from <c>publish.yml</c>, the exclusion list from
/// <c>scripts/publish-manifest.json</c> and the republished scripts from <c>Sync-PublicRepo.ps1</c>. Any form of one of
/// them that it cannot interpret makes it fail explicitly rather than guess.
/// </para>
/// <para>
/// Limits, stated so nobody over-trusts it: it sees literals written in the test method body, not paths computed at
/// run time or hidden in shared helpers; a path split into separate <c>Path.Combine</c> segments is caught for the
/// excluded directory names and file names, not for <c>docs/</c> sub-paths. The full public-workflow replay done before
/// each SDK publication (DOC-40, TKT-004138) remains the final proof. The class carries <c>PrivateRepository</c>
/// itself because it reads <c>scripts/</c> files, which the mirror does not contain.
/// </para>
/// </remarks>
[Trait("Category", "PrivateRepository")]
public sealed class PublicMirrorPrivateFileGuardTests
{
    /// <summary>
    /// Scripts that <c>Sync-PublicRepo.ps1</c> is expected to copy back into the mirror although <c>scripts/</c> is
    /// excluded. Changing what the public workflow can load must be a conscious change of this list:
    /// <see cref="TheRepublishedScriptsAreExactlyTheExpectedOnes"/> compares it with the synchronizer's real list.
    /// </summary>
    private static readonly string[] ExpectedRepublishedScripts = ["SdkSigning.ps1", "Test-TrackedSecrets.ps1"];

    /// <summary>
    /// Excluded entries that are build or tool output regenerated in every checkout (or globs), never source files a
    /// test reads from the repository; flagging them would only produce false positives.
    /// </summary>
    private static readonly HashSet<string> GeneratedEntries = new(StringComparer.Ordinal)
    {
        "bin/", "obj/", "out/", "TestResults/", "artifacts/", ".vs/", ".vscode/", ".git/", "softlicence.db",
    };

    /// <summary>
    /// Fails, listing each offender as <c>file: test -&gt; literal</c>, when a test run by the public workflow names a
    /// file or directory excluded from the public mirror. The fix is to add <c>[Trait("Category", "PrivateRepository")]</c>
    /// to that test (or to stop reading the private file).
    /// </summary>
    [Fact]
    public void EveryPublicSuiteTest_NamesNoFileExcludedFromThePublicMirror()
    {
        var root = FindRepositoryRoot();
        var filter = ReadPublicWorkflowFilter(root);
        var rules = LoadExclusionRules(root);
        var violations = new List<string>();
        foreach (var file in EnumerateTestSources(root))
        {
            foreach (var test in FindTests(File.ReadAllText(file), filter))
            {
                if (!test.RunsInPublicSuite)
                    continue;
                foreach (var literal in test.Literals)
                {
                    if (rules.IsExcluded(literal, test.Body))
                        violations.Add($"{Path.GetRelativePath(root, file)}: {test.Name} -> \"{literal}\"");
                }
            }
        }

        Assert.True(violations.Count == 0,
            "Tests run by the public publish.yml read files excluded from the public mirror; add "
            + "[Trait(\"Category\", \"PrivateRepository\")] to them:" + Environment.NewLine
            + string.Join(Environment.NewLine, violations));
    }

    /// <summary>
    /// The guard must actually see a violation: a synthetic public test reading <c>deploy.ps1</c> is flagged, the
    /// same test marked <c>PrivateRepository</c> is not, a test whose fully qualified name contains <c>PostgreSql</c>
    /// is out of the public filter, and a republished script is allowed. Protects the guard against silently matching
    /// nothing after a refactoring.
    /// </summary>
    [Fact]
    public void TheGuardFlagsAnUnmarkedReadOfAPrivateFileOnly()
    {
        var root = FindRepositoryRoot();
        var rules = LoadExclusionRules(root);
        var filter = ParsePublicFilter("FullyQualifiedName!~PostgreSql&Category!=PrivateRepository&Category!=RequiresPostgreSql");
        const string source = """
            namespace Sample.Tests;

            public sealed class SampleTests
            {
                [Fact]
                public void Unmarked() { var deploy = ReadProjectFile("deploy.ps1"); }

                [Fact]
                [Trait("Category", "PrivateRepository")]
                public void Marked() { var deploy = ReadProjectFile("deploy.ps1"); }

                [Fact]
                public void PublicScript() { var s = ReadProjectFile("scripts/SdkSigning.ps1"); }
            }

            public sealed class SamplePostgreSqlTests
            {
                [Fact]
                public void InPostgreSqlClass() { var deploy = ReadProjectFile("deploy.ps1"); }
            }
            """;

        var flagged = FindTests(source, filter)
            .Where(test => test.RunsInPublicSuite && test.Literals.Any(literal => rules.IsExcluded(literal, test.Body)))
            .Select(test => test.Name)
            .ToList();

        Assert.Equal(["Unmarked"], flagged);
    }

    /// <summary>
    /// Review 2532, filter drift: the filter is read from <c>publish.yml</c>, never copied. The supported grammar is a
    /// conjunction of <c>FullyQualifiedName!~value</c> and <c>Category!=value</c>; every other shape is refused with an
    /// explicit message, so a workflow change the guard cannot follow fails here instead of being misread.
    /// </summary>
    [Theory]
    [InlineData("FullyQualifiedName!~PostgreSql|Category!=PrivateRepository")]
    [InlineData("(FullyQualifiedName!~PostgreSql)&Category!=PrivateRepository")]
    [InlineData("FullyQualifiedName~PostgreSql")]
    [InlineData("Category=PrivateRepository")]
    [InlineData("Name!~PostgreSql")]
    [InlineData("TestCategory!=PrivateRepository")]
    [InlineData("FullyQualifiedName!~")]
    [InlineData("")]
    public void ThePublicFilterParser_RefusesEveryUnsupportedForm(string expression)
    {
        var refusal = Assert.Throws<InvalidOperationException>(() => ParsePublicFilter(expression));
        Assert.StartsWith("PUBLIC_FILTER_UNSUPPORTED", refusal.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// The real filter of <c>publish.yml</c> parses into exactly its clauses, and a changed value in the workflow text
    /// changes what the guard excludes (the guard follows the workflow instead of a copy).
    /// </summary>
    [Fact]
    public void ThePublicFilter_IsReadFromTheWorkflowAndFollowsItsChanges()
    {
        var filter = ReadPublicWorkflowFilter(FindRepositoryRoot());
        Assert.Contains("PostgreSql", filter.ExcludedNameParts);
        Assert.Contains("PrivateRepository", filter.ExcludedCategories);

        const string changedWorkflow = """
            - name: Run tests
              run: dotnet test tests/SoftLicence.Tests/ --no-restore --filter "Category!=OnlyThisOne"
            """;
        var changed = ExtractPublicFilter(changedWorkflow);
        Assert.Empty(changed.ExcludedNameParts);
        Assert.Equal(["OnlyThisOne"], changed.ExcludedCategories);
        Assert.Throws<InvalidOperationException>(() => ExtractPublicFilter("- run: dotnet build src/SoftLicence.sln"));
    }

    /// <summary>
    /// Review 2532, republished scripts: the real list of <c>Sync-PublicRepo.ps1</c> (its <c>$publicScriptNames</c>
    /// assignment, not its comments) must be exactly <see cref="ExpectedRepublishedScripts"/>.
    /// </summary>
    [Fact]
    public void TheRepublishedScriptsAreExactlyTheExpectedOnes()
    {
        var synchronizer = File.ReadAllText(Path.Combine(FindRepositoryRoot(), "scripts", "Sync-PublicRepo.ps1"));
        Assert.Equal(
            ExpectedRepublishedScripts.Order(StringComparer.Ordinal),
            ExtractRepublishedScripts(synchronizer).Order(StringComparer.Ordinal));
    }

    /// <summary>
    /// The extraction reads the assignment only: removing a script from the list while the comment still names it, or
    /// adding one, changes the extracted set (the previous text search stayed green in both cases).
    /// </summary>
    [Fact]
    public void RepublishedScriptExtraction_IgnoresCommentsAndSeesAdditionsAndRemovals()
    {
        const string comments = """
            #   Test-TrackedSecrets.ps1 : tracked-secret guard run by every workflow execution.
            #   SdkSigning.ps1          : SDK signature and identity guard loaded before the NuGet push
            """;
        var removed = ExtractRepublishedScripts(comments + "\n$publicScriptNames = @(\"Test-TrackedSecrets.ps1\")\n");
        var added = ExtractRepublishedScripts(comments
            + "\n$publicScriptNames = @(\"Test-TrackedSecrets.ps1\", \"SdkSigning.ps1\", \"Extra.ps1\")\n");

        Assert.Equal(["Test-TrackedSecrets.ps1"], removed);
        Assert.Equal(["Test-TrackedSecrets.ps1", "SdkSigning.ps1", "Extra.ps1"], added);
        Assert.Throws<InvalidOperationException>(() => ExtractRepublishedScripts(comments));
        Assert.Throws<InvalidOperationException>(() =>
            ExtractRepublishedScripts("$publicScriptNames = @(\"A.ps1\")\n$publicScriptNames = @(\"B.ps1\")\n"));
        Assert.Throws<InvalidOperationException>(() => ExtractRepublishedScripts("$publicScriptNames = @($names)\n"));
    }

    /// <summary>
    /// What the public workflow filter excludes: fully qualified name fragments (<c>FullyQualifiedName!~</c>) and trait
    /// categories (<c>Category!=</c>). VSTest compares both case-insensitively, and so does the guard.
    /// </summary>
    private sealed record PublicFilter(IReadOnlyList<string> ExcludedNameParts, IReadOnlyList<string> ExcludedCategories);

    /// <summary>Reads and parses the test filter of <c>.github/workflows/publish.yml</c>.</summary>
    private static PublicFilter ReadPublicWorkflowFilter(string root) =>
        ExtractPublicFilter(File.ReadAllText(Path.Combine(root, ".github", "workflows", "publish.yml")));

    /// <summary>
    /// Finds the single <c>dotnet test ... --filter "..."</c> command of a workflow text and parses its expression.
    /// Refuses (<see cref="InvalidOperationException"/>, code <c>PUBLIC_FILTER_UNSUPPORTED</c>) when there is not
    /// exactly one such command or its filter is not a double-quoted value.
    /// </summary>
    private static PublicFilter ExtractPublicFilter(string workflow)
    {
        var commands = Regex.Matches(workflow, @"dotnet\s+test\b[^\r\n]*").Select(match => match.Value).ToList();
        if (commands.Count != 1)
            throw new InvalidOperationException($"PUBLIC_FILTER_UNSUPPORTED: expected exactly one dotnet test command, found {commands.Count}.");
        var filter = Regex.Match(commands[0], @"--filter\s+""([^""]*)""");
        if (!filter.Success)
            throw new InvalidOperationException("PUBLIC_FILTER_UNSUPPORTED: the dotnet test command has no double-quoted --filter value.");
        return ParsePublicFilter(filter.Groups[1].Value);
    }

    /// <summary>
    /// Parses a VSTest filter limited to a conjunction (<c>&amp;</c>) of <c>FullyQualifiedName!~value</c> and
    /// <c>Category!=value</c> clauses. Any other operator, property, grouping, disjunction or empty value throws
    /// <see cref="InvalidOperationException"/> starting with <c>PUBLIC_FILTER_UNSUPPORTED</c>: interpreting it wrongly
    /// would let the guard approve a test the public workflow actually runs.
    /// </summary>
    private static PublicFilter ParsePublicFilter(string expression)
    {
        if (string.IsNullOrWhiteSpace(expression) || expression.IndexOfAny(['|', '(', ')']) >= 0)
            throw new InvalidOperationException($"PUBLIC_FILTER_UNSUPPORTED: '{expression}' (only '&' of supported clauses).");
        var nameParts = new List<string>();
        var categories = new List<string>();
        foreach (var clause in expression.Split('&'))
        {
            var match = Regex.Match(clause.Trim(), @"^(FullyQualifiedName!~|Category!=)(\S.*)$");
            if (!match.Success)
                throw new InvalidOperationException($"PUBLIC_FILTER_UNSUPPORTED: clause '{clause}'.");
            (match.Groups[1].Value == "Category!=" ? categories : nameParts).Add(match.Groups[2].Value.Trim());
        }
        return new PublicFilter(nameParts, categories);
    }

    /// <summary>
    /// Extracts the scripts <c>Sync-PublicRepo.ps1</c> copies back into the mirror from its single
    /// <c>$publicScriptNames = @("a", "b")</c> assignment. Comments are ignored. Refuses (no assignment, several
    /// assignments, or an element that is not a double-quoted literal) rather than guessing.
    /// </summary>
    private static IReadOnlyList<string> ExtractRepublishedScripts(string synchronizer)
    {
        var assignments = Regex.Matches(synchronizer, @"^\s*\$publicScriptNames\s*=\s*@\((?<items>[^)\r\n]*)\)\s*$", RegexOptions.Multiline);
        if (assignments.Count != 1)
            throw new InvalidOperationException($"REPUBLISHED_SCRIPTS_UNSUPPORTED: expected one $publicScriptNames assignment, found {assignments.Count}.");
        var names = new List<string>();
        foreach (var item in assignments[0].Groups["items"].Value.Split(','))
        {
            var literal = Regex.Match(item.Trim(), @"^""([^""]+)""$");
            if (!literal.Success)
                throw new InvalidOperationException($"REPUBLISHED_SCRIPTS_UNSUPPORTED: element '{item.Trim()}' is not a double-quoted name.");
            names.Add(literal.Groups[1].Value);
        }
        return names;
    }

    /// <summary>
    /// Builds the exclusion rules from <c>scripts/publish-manifest.json</c>: its <c>Blacklist</c> minus generated
    /// entries, globs and entries that a <c>Substitutions</c> rule recreates under the same name in the mirror, plus the
    /// republished scripts read from <c>Sync-PublicRepo.ps1</c>.
    /// </summary>
    private static ExclusionRules LoadExclusionRules(string root)
    {
        using var manifest = JsonDocument.Parse(File.ReadAllText(Path.Combine(root, "scripts", "publish-manifest.json")));
        var substitutionTargets = manifest.RootElement.GetProperty("Substitutions").EnumerateObject()
            .Select(pair => pair.Value.GetString()!.Replace('\\', '/'))
            .ToHashSet(StringComparer.Ordinal);
        var directories = new List<string>();
        var files = new List<string>();
        foreach (var element in manifest.RootElement.GetProperty("Blacklist").EnumerateArray())
        {
            var entry = element.GetString()!.Replace('\\', '/');
            if (entry.Contains('*', StringComparison.Ordinal) || GeneratedEntries.Contains(entry))
                continue;
            if (substitutionTargets.Any(target => target.EndsWith("/" + entry, StringComparison.Ordinal) || target == entry))
                continue;
            if (entry.EndsWith('/'))
                directories.Add(entry.TrimEnd('/'));
            else
                files.Add(entry);
        }

        var republished = ExtractRepublishedScripts(File.ReadAllText(Path.Combine(root, "scripts", "Sync-PublicRepo.ps1")));
        return new ExclusionRules(root, directories, files, republished);
    }

    /// <summary>
    /// Decides whether one string literal of a public test names something the mirror does not contain.
    /// </summary>
    /// <param name="Root">Private repository root, used to check whether a <c>docs/</c> path exists in <c>docs-public/</c>.</param>
    /// <param name="Directories">Excluded directory names, without trailing slash (for example <c>scripts</c>).</param>
    /// <param name="Files">Excluded file names (for example <c>deploy.ps1</c>).</param>
    /// <param name="Republished">Script names published despite the <c>scripts</c> exclusion.</param>
    private sealed record ExclusionRules(
        string Root,
        IReadOnlyList<string> Directories,
        IReadOnlyList<string> Files,
        IReadOnlyList<string> Republished)
    {
        /// <summary>
        /// True when <paramref name="literal"/> names an excluded file or a path under an excluded directory, or a
        /// <c>docs/</c> path that <c>docs-public/</c> (which replaces <c>docs/</c> in the mirror) does not provide.
        /// A bare directory segment (as in <c>Path.Combine(root, "scripts", "x.ps1")</c>) counts unless the test body
        /// only reaches a republished script. Comparison is ordinal: the synchronizer copies exact names and paths are
        /// case-sensitive on the Linux runners.
        /// </summary>
        public bool IsExcluded(string literal, string testBody)
        {
            var path = literal.Replace('\\', '/').Trim();
            if (path.Length == 0)
                return false;
            var fileName = path[(path.LastIndexOf('/') + 1)..];
            if (Files.Any(file => path == file || fileName == file))
                return true;

            foreach (var directory in Directories)
            {
                if (path == directory)
                    return !Republished.Any(script => testBody.Contains($"\"{script}\"", StringComparison.Ordinal));
                if (path.StartsWith(directory + "/", StringComparison.Ordinal))
                    return !(directory == "scripts" && Republished.Contains(path[(directory.Length + 1)..]));
            }

            if (path.StartsWith("docs/", StringComparison.Ordinal) && path.Length > "docs/".Length)
                return !Path.Exists(Path.Combine(Root, "docs-public", path["docs/".Length..]));
            return false;
        }
    }

    /// <summary>
    /// One <c>[Fact]</c> or <c>[Theory]</c> found in a source file: its name, its body text (attributes through the
    /// closing brace), its string literals, and whether the public filter would run it.
    /// </summary>
    private sealed record TestMethod(string Name, string Body, IReadOnlyList<string> Literals, bool RunsInPublicSuite);

    /// <summary>
    /// Finds every test method of <paramref name="text"/> with a small C# scanner that skips comments and string
    /// literals while matching braces, and applies <paramref name="filter"/>: a test is out of the public suite when its
    /// fully qualified name (namespace, class, method) contains an excluded fragment, or when the method or its class
    /// carries an excluded category. Both comparisons ignore case, as VSTest does.
    /// </summary>
    private static IEnumerable<TestMethod> FindTests(string text, PublicFilter filter)
    {
        var namespaceName = Regex.Match(text, @"^\s*namespace\s+([\w.]+)", RegexOptions.Multiline).Groups[1].Value;
        foreach (Match attribute in Regex.Matches(text, @"\[(Fact|Theory)\b"))
        {
            var bodyStart = text.IndexOf('{', attribute.Index);
            var arrow = text.IndexOf("=>", attribute.Index, StringComparison.Ordinal);
            var end = arrow >= 0 && (bodyStart < 0 || arrow < bodyStart)
                ? text.IndexOf(';', arrow) + 1
                : MatchingBrace(text, bodyStart) + 1;
            if (end <= attribute.Index)
                continue;
            var body = text[attribute.Index..end];
            var name = Regex.Match(body, @"\b(?:void|Task)\s+(\w+)\s*\(").Groups[1].Value;
            var classMatch = Regex.Matches(text[..attribute.Index], @"\bclass\s+(\w+)").LastOrDefault();
            var className = classMatch?.Groups[1].Value ?? string.Empty;
            var classHeader = classMatch is null ? string.Empty : ClassAttributes(text, classMatch.Index);
            var fullyQualifiedName = $"{namespaceName}.{className}.{name}";
            var categories = Categories(body).Concat(Categories(classHeader));
            var excluded = filter.ExcludedNameParts.Any(part => fullyQualifiedName.Contains(part, StringComparison.OrdinalIgnoreCase))
                || categories.Any(category => filter.ExcludedCategories.Contains(category, StringComparer.OrdinalIgnoreCase));
            yield return new TestMethod(name, body, StringLiterals(body), !excluded);
        }
    }

    /// <summary>Returns the values of the <c>[Trait("Category", "...")]</c> attributes found in a text.</summary>
    private static IEnumerable<string> Categories(string text) =>
        Regex.Matches(text, @"Trait\(\s*""Category""\s*,\s*""([^""]+)""\s*\)").Select(match => match.Groups[1].Value);

    /// <summary>
    /// Returns the attribute block written just before a class declaration: the text between the previous statement or
    /// block end (<c>;</c>, <c>}</c> or <c>{</c>) and the <c>class</c> keyword.
    /// </summary>
    private static string ClassAttributes(string text, int classIndex)
    {
        var start = text.LastIndexOfAny([';', '}', '{'], Math.Max(0, classIndex - 1));
        return text[(start + 1)..classIndex];
    }

    /// <summary>
    /// Returns the index of the brace closing the one at <paramref name="open"/>, skipping comments, characters and
    /// string literals (regular, verbatim, interpolated, raw) so that braces inside them never count; -1 if unmatched.
    /// </summary>
    private static int MatchingBrace(string text, int open)
    {
        if (open < 0)
            return -1;
        var depth = 0;
        for (var index = open; index < text.Length; index++)
        {
            var skipped = SkipNonCode(text, index);
            if (skipped != index)
            {
                index = skipped - 1;
                continue;
            }
            if (text[index] == '{')
                depth++;
            else if (text[index] == '}' && --depth == 0)
                return index;
        }
        return -1;
    }

    /// <summary>
    /// Extracts the values of the regular and verbatim string literals of a code fragment (interpolated literals give
    /// their constant text). Raw literals are skipped: test bodies do not use them for paths.
    /// </summary>
    private static IReadOnlyList<string> StringLiterals(string code)
    {
        var literals = new List<string>();
        foreach (Match literal in Regex.Matches(code, @"(?<!\w)(\$?@|@?\$?)""((?:[^""\\\r\n]|\\.|"""")*)"""))
            literals.Add(literal.Groups[2].Value.Replace(@"\\", @"\", StringComparison.Ordinal));
        return literals;
    }

    /// <summary>
    /// When <paramref name="index"/> starts a comment, character or string literal, returns the index just after it;
    /// otherwise returns <paramref name="index"/> unchanged.
    /// </summary>
    private static int SkipNonCode(string text, int index)
    {
        if (text.AsSpan(index).StartsWith("//"))
            return NextOrEnd(text, text.IndexOf('\n', index));
        if (text.AsSpan(index).StartsWith("/*"))
            return NextOrEnd(text, text.IndexOf("*/", index + 2, StringComparison.Ordinal), 2);
        if (text.AsSpan(index).StartsWith("\"\"\""))
            return NextOrEnd(text, text.IndexOf("\"\"\"", index + 3, StringComparison.Ordinal), 3);
        if (text[index] == '\'')
        {
            var close = index + 1;
            while (close < text.Length && text[close] != '\'')
                close += text[close] == '\\' ? 2 : 1;
            return Math.Min(close + 1, text.Length);
        }
        if (text[index] != '"')
            return index;
        var verbatim = index > 0 && (text[index - 1] == '@' || (index > 1 && text[index - 2] == '@'));
        var position = index + 1;
        while (position < text.Length)
        {
            if (verbatim && text[position] == '"' && position + 1 < text.Length && text[position + 1] == '"')
                position += 2;
            else if (!verbatim && text[position] == '\\')
                position += 2;
            else if (text[position] == '"')
                return position + 1;
            else
                position++;
        }
        return text.Length;
    }

    /// <summary>Returns the index after a found delimiter, or the end of the text when the delimiter is missing.</summary>
    private static int NextOrEnd(string text, int found, int length = 1) =>
        found < 0 ? text.Length : found + length;

    /// <summary>
    /// Lists the C# test sources of the test project, without build output and without this file: its self-tests hold
    /// synthetic C# sources in raw string literals, which the scanner would otherwise read as real tests.
    /// </summary>
    private static IEnumerable<string> EnumerateTestSources(string root) =>
        Directory.EnumerateFiles(Path.Combine(root, "tests", "SoftLicence.Tests"), "*.cs", SearchOption.AllDirectories)
            .Where(path =>
            {
                var relative = Path.GetRelativePath(root, path).Replace('\\', '/');
                return !relative.Contains("/bin/", StringComparison.Ordinal)
                    && !relative.Contains("/obj/", StringComparison.Ordinal)
                    && !string.Equals(Path.GetFileName(path), $"{nameof(PublicMirrorPrivateFileGuardTests)}.cs", StringComparison.Ordinal);
            });

    /// <summary>Walks up from the test binaries to the directory holding <c>src/SoftLicence.sln</c>.</summary>
    private static string FindRepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory != null && !File.Exists(Path.Combine(directory.FullName, "src", "SoftLicence.sln")))
            directory = directory.Parent;
        Assert.NotNull(directory);
        return directory!.FullName;
    }
}
