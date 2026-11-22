using System.Reflection;
using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using Xunit;

namespace SoftLicence.Tests.Server;

/// <summary>
/// TKT-004112 guard: every endpoint label stored in <c>MachineEvidenceObservations.LastEndpoint</c> fits the column.
/// Storage is fail-open, so an oversized label never fails a request: it silently loses the machine evidence, which
/// is how the 22-character clone-guard reactivation label went unnoticed. These checks need no database.
/// </summary>
public sealed class MachineEvidenceEndpointsTests
{
    /// <summary>
    /// Returns every public constant label of <see cref="MachineEvidenceEndpoints"/>, so a label added later is
    /// covered without editing this test.
    /// </summary>
    private static IReadOnlyList<string> Labels() => typeof(MachineEvidenceEndpoints)
        .GetFields(BindingFlags.Public | BindingFlags.Static)
        .Where(field => field.IsLiteral && field.FieldType == typeof(string))
        .Select(field => (string)field.GetRawConstantValue()!)
        .ToList();

    [Fact]
    public void EveryLabel_FitsTheColumn_AndIsAnUpperCaseAsciiCode()
    {
        var labels = Labels();

        Assert.Contains(MachineEvidenceEndpoints.CloneGuardReactivate, labels);
        Assert.Equal(labels.Count, labels.Distinct(StringComparer.Ordinal).Count());
        Assert.All(labels, label =>
        {
            Assert.InRange(label.Length, 1, MachineEvidenceObservation.MaxEndpointLength);
            Assert.All(label, character => Assert.True(character is >= 'A' and <= 'Z' or '_',
                $"label {label} must stay an upper-case ASCII code"));
        });
    }

    /// <summary>
    /// The relational column length comes from the same constant as the guard above; a model change that drops the
    /// constant would otherwise let the column and the guard drift apart.
    /// </summary>
    [Fact]
    public void ModelColumnLength_IsTheSharedConstant()
    {
        using var db = new LicenseDbContext(new DbContextOptionsBuilder<LicenseDbContext>()
            .UseNpgsql("Host=localhost;Database=model-only").Options);

        var property = db.Model.FindEntityType(typeof(MachineEvidenceObservation))!
            .FindProperty(nameof(MachineEvidenceObservation.LastEndpoint))!;

        Assert.Equal(MachineEvidenceObservation.MaxEndpointLength, property.GetMaxLength());
    }
}
