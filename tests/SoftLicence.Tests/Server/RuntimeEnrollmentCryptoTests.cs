using Xunit;

namespace SoftLicence.Tests.Server;

public sealed class RuntimeEnrollmentCryptoTests
{
    [Fact]
    public void EncryptionPurpose_IsCanonicalLowercase()
    {
        Assert.Equal("encryption", new SoftLicence.Server.Data.RuntimeEnrollmentEncryptionNonce().Purpose);
    }
}
