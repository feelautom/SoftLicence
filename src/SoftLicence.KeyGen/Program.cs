using SoftLicence.Core;

namespace SoftLicence.KeyGen
{
    class Program
    {
        static void Main(string[] args)
        {
            // Mode "AUTO-GEN" pour setup rapide
            var keys = LicenseService.GenerateKeys();
            File.WriteAllText("gen_private.xml", keys.PrivateKey);
            File.WriteAllText("gen_public.xml", keys.PublicKey);
        }
    }
}