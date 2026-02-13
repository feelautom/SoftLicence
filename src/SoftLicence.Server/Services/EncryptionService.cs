using Microsoft.AspNetCore.DataProtection;

namespace SoftLicence.Server.Services;

public class EncryptionService
{
    private readonly IDataProtector _protector;

    public EncryptionService(IDataProtectionProvider provider)
    {
        _protector = provider.CreateProtector("SoftLicence.ProductKeys.v1");
    }

    public string Encrypt(string plainText)
    {
        if (string.IsNullOrEmpty(plainText)) return string.Empty;
        return _protector.Protect(plainText);
    }

    public string Decrypt(string cipherText)
    {
        if (string.IsNullOrEmpty(cipherText)) return string.Empty;
        try
        {
            return _protector.Unprotect(cipherText);
        }
        catch
        {
            // Si le déchiffrement échoue (clé corrompue ou changement de master key system)
            return "ERROR_DECRYPTION_FAILED";
        }
    }
}
