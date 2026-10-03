using Xunit;

namespace SoftLicence.Tests.Core;

/// <summary>
/// Serializes every test class that replaces the process-wide machine-identity readers
/// (<c>MachineIdentity.UseWmiQueryReaderForTests</c> and <c>UseRegistryValueReaderForTests</c>),
/// so parallel classes never observe each other's fake machine.
/// </summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class MachineIdentityReadersCollection
{
    /// <summary>Collection name used by the serialized test classes.</summary>
    public const string Name = "MachineIdentityReaders";
}
