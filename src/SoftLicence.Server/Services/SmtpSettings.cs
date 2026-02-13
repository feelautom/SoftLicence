namespace SoftLicence.Server.Services
{
    public class SmtpSettings
    {
        public string Host { get; set; } = "localhost";
        public int Port { get; set; } = 25;
        public string Username { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
        public string FromEmail { get; set; } = "noreply@softlicence.com";
        public string FromName { get; set; } = "SoftLicence Bot";
        public bool EnableSsl { get; set; } = true;
    }
}
