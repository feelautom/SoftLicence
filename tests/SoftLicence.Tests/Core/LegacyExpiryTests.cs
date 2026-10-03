using System.Globalization;
using System.Text.RegularExpressions;
using Xunit;

namespace SoftLicence.Tests.Core;

/// <summary>
/// Enforces Franck's rule (30/09/2026): every piece of code kept for the old system carries
/// <c>LEGACY-EXPIRY(TKT-xxxxxx, yyyy-mm-dd)</c> and must be gone after that date. The day after an expiry this test
/// fails until the tagged code, and its tag, are removed as described in the ticket.
/// </summary>
public class LegacyExpiryTests
{
    private static readonly Regex Tag = new(
        @"LEGACY-EXPIRY\((?<ticket>[^,)]*),\s*(?<date>[^)]*)\)", RegexOptions.CultureInvariant);

    private static readonly Regex Ticket = new(@"^TKT-\d{6}$", RegexOptions.CultureInvariant);

    [Fact]
    public void NoLegacyExpiryTagIsPastItsDate()
    {
        var today = DateOnly.FromDateTime(DateTime.UtcNow);
        var expired = Tags().Where(tag => tag.Date < today)
            .Select(tag => $"{tag.Location}: {tag.Ticket} expired on {tag.Date:yyyy-MM-dd}")
            .ToList();

        Assert.True(expired.Count == 0,
            "Legacy code past its removal date must be deleted (see the ticket):" + Environment.NewLine
            + string.Join(Environment.NewLine, expired));
    }

    [Fact]
    public void EveryLegacyExpiryTagNamesATicketAndAValidDate()
    {
        var malformed = Tags().Where(tag => !tag.Valid).Select(tag => tag.Location).ToList();

        Assert.True(malformed.Count == 0,
            "LEGACY-EXPIRY must be written LEGACY-EXPIRY(TKT-000000, yyyy-mm-dd):" + Environment.NewLine
            + string.Join(Environment.NewLine, malformed));
    }

    private static IEnumerable<(string Location, string Ticket, DateOnly Date, bool Valid)> Tags()
    {
        var source = Path.Combine(FindRepositoryRoot(), "src");
        foreach (var file in Directory.EnumerateFiles(source, "*.cs", SearchOption.AllDirectories))
        {
            var separator = Path.DirectorySeparatorChar;
            if (file.Contains($"{separator}bin{separator}", StringComparison.Ordinal)
                || file.Contains($"{separator}obj{separator}", StringComparison.Ordinal))
                continue;
            var lines = File.ReadAllLines(file);
            for (var index = 0; index < lines.Length; index++)
            {
                foreach (Match match in Tag.Matches(lines[index]))
                {
                    var ticket = match.Groups["ticket"].Value.Trim();
                    var dateText = match.Groups["date"].Value.Trim();
                    var parsed = DateOnly.TryParseExact(dateText, "yyyy-MM-dd", CultureInfo.InvariantCulture,
                        DateTimeStyles.None, out var date);
                    yield return ($"{Path.GetRelativePath(source, file)}:{index + 1}", ticket,
                        parsed ? date : DateOnly.MinValue, parsed && Ticket.IsMatch(ticket));
                }
            }
        }
    }

    private static string FindRepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory.FullName, "src", "SoftLicence.sln")))
                return directory.FullName;
            directory = directory.Parent;
        }

        throw new DirectoryNotFoundException("Could not locate the SoftLicence repository root.");
    }
}
