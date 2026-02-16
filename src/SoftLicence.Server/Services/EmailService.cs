using Microsoft.Extensions.Options;
using MailKit.Net.Smtp;
using MailKit.Security;
using MimeKit;

namespace SoftLicence.Server.Services
{
    public class EmailService
    {
        private readonly SmtpSettings _settings;
        private readonly ILogger<EmailService> _logger;

        public EmailService(IOptions<SmtpSettings> settings, ILogger<EmailService> logger)
        {
            _settings = settings.Value;
            _logger = logger;
        }

        public async Task SendLicenseEmailAsync(string toEmail, string customerName, string productName, string licenseKey)
        {
            await SendEmailInternalAsync(toEmail, customerName, productName, licenseKey, false, null);
        }

        public async Task SendResetCodeEmailAsync(string toEmail, string customerName, string productName, string resetCode)
        {
            // On utilise une méthode dédiée pour le reset pour avoir un template spécifique
            var host = _settings.Host?.Trim('"', '\'', ' ', '\t') ?? "";
            var user = _settings.Username?.Trim('"', '\'', ' ', '\t') ?? "";
            var pass = _settings.Password?.Trim('"', '\'', ' ', '\t') ?? "";

            if (string.IsNullOrEmpty(host) || host == "localhost") return;

            var message = new MimeMessage();
            message.From.Add(new MailboxAddress(productName, _settings.FromEmail?.Trim('"')));
            message.To.Add(new MailboxAddress(customerName, toEmail));
            message.Subject = $"Code de réinitialisation - {productName}";

            var builder = new BodyBuilder();
            builder.HtmlBody = $@"
<div style=""font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; max-width: 600px; margin: 0 auto; border: 1px solid #e0e0e0; border-radius: 8px; overflow: hidden;"">
    <div style=""background-color: #e53e3e; padding: 30px; text-align: center; color: white;"">
        <h1 style=""margin: 0; font-size: 24px; font-weight: 600;"">{productName}</h1>
        <p style=""margin: 5px 0 0 0; opacity: 0.8; font-size: 14px;"">Réinitialisation de votre licence</p>
    </div>
    
    <div style=""padding: 40px 30px; background-color: #ffffff; color: #333333; line-height: 1.6;"">
        <p style=""margin-top: 0;"">Bonjour <strong>{customerName}</strong>,</p>
        <p>Vous avez demandé à délier votre licence <strong>{productName}</strong> pour l'utiliser sur un autre ordinateur. Voici votre code de confirmation :</p>
        
        <div style=""margin: 30px 0; padding: 20px; background-color: #fff5f5; border: 2px solid #feb2b2; border-radius: 6px; text-align: center;"">
            <span style=""display: block; font-size: 12px; text-transform: uppercase; color: #c53030; margin-bottom: 10px; font-weight: bold;"">Code à usage unique</span>
            <code style=""font-family: 'Consolas', 'Monaco', monospace; font-size: 32px; font-weight: bold; color: #c53030; letter-spacing: 5px;"">{resetCode}</code>
            <p style=""margin: 10px 0 0 0; font-size: 12px; color: #9b2c2c;"">Valable pendant 15 minutes</p>
        </div>
        
        <p>Si vous n'êtes pas à l'origine de cette demande, vous pouvez ignorer cet e-mail. Votre licence restera active sur votre ordinateur actuel.</p>
        
        <p style=""font-size: 14px; color: #718096; border-top: 1px solid #edf2f7; padding-top: 20px; margin-top: 30px;"">
            Besoin d'aide ? Répondez simplement à cet e-mail.
        </p>
    </div>
    
    <div style=""background-color: #f8f9fa; padding: 20px; text-align: center; font-size: 12px; color: #a0aec0;"">
        &copy; {DateTime.Now.Year} YOUR_COMPANY_NAME - {productName}
    </div>
</div>";
            builder.TextBody = $"Bonjour {customerName},\n\nVotre code de réinitialisation pour {productName} est : {resetCode}\n\nCordialement,\nL'équipe {productName}";
            message.Body = builder.ToMessageBody();

            using var client = new SmtpClient();
            await client.ConnectAsync(host, _settings.Port, _settings.Port == 465 ? SecureSocketOptions.SslOnConnect : SecureSocketOptions.StartTls);
            if (!string.IsNullOrEmpty(user)) await client.AuthenticateAsync(user, pass);
            await client.SendAsync(message);
            await client.DisconnectAsync(true);
        }

        public async Task SendAdminWelcomeEmailAsync(string toEmail, string username, string tempPassword)
        {
            var host = _settings.Host?.Trim('"', '\'', ' ', '\t') ?? "";
            var user = _settings.Username?.Trim('"', '\'', ' ', '\t') ?? "";
            var pass = _settings.Password?.Trim('"', '\'', ' ', '\t') ?? "";

            if (string.IsNullOrEmpty(host) || host == "localhost") return;

            var message = new MimeMessage();
            message.From.Add(new MailboxAddress("SoftLicence Security", _settings.FromEmail?.Trim('"')));
            message.To.Add(new MailboxAddress(username, toEmail));
            message.Subject = "Bienvenue sur SoftLicence - Vos accès Administrateur";

            var builder = new BodyBuilder();
            builder.HtmlBody = $@"
<div style=""font-family: 'Segoe UI', sans-serif; max-width: 600px; margin: 0 auto; border: 1px solid #e0e0e0; border-radius: 8px; overflow: hidden;"">
    <div style=""background-color: #2d3748; padding: 30px; text-align: center; color: white;"">
        <h1 style=""margin: 0; font-size: 24px;"">SoftLicence Admin</h1>
        <p style=""margin: 5px 0 0 0; opacity: 0.8;"">Nouveau compte utilisateur</p>
    </div>
    
    <div style=""padding: 40px 30px; color: #333; line-height: 1.6;"">
        <p>Bonjour <strong>{username}</strong>,</p>
        <p>Un compte administrateur vient d'être créé pour vous sur la console SoftLicence.</p>
        
        <div style=""margin: 30px 0; padding: 20px; background-color: #f7fafc; border-left: 4px solid #4299e1;"">
            <div style=""margin-bottom: 10px;"">Identifiant : <strong>{username}</strong></div>
            <div>Mot de passe temporaire : <code style=""background: #edf2f7; padding: 2px 5px; border-radius: 4px; font-size: 1.1em; color: #2b6cb0;"">{tempPassword}</code></div>
        </div>
        
        <p style=""background-color: #fff5f5; padding: 15px; border-radius: 6px; color: #c53030; font-size: 14px;"">
            <strong>Sécurité :</strong> Pour des raisons de sécurité, vous devrez obligatoirement changer ce mot de passe lors de votre première connexion.
        </p>
        
        <p style=""margin-top: 30px;"">
            L'équipe Sécurité SoftLicence
        </p>
    </div>
</div>";
            builder.TextBody = $"Bonjour {username},\n\nUn compte administrateur a été créé pour vous.\nIdentifiant : {username}\nMot de passe temporaire : {tempPassword}\n\nVous devrez le changer à la première connexion.";
            message.Body = builder.ToMessageBody();

            using var client = new SmtpClient();
            await client.ConnectAsync(host, _settings.Port, _settings.Port == 465 ? SecureSocketOptions.SslOnConnect : SecureSocketOptions.StartTls);
            if (!string.IsNullOrEmpty(user)) await client.AuthenticateAsync(user, pass);
            await client.SendAsync(message);
            await client.DisconnectAsync(true);
        }

        public async Task RunDiagnosticAsync(string toEmail, string customerName, string productName, string licenseKey, Action<string>? onProgress)
        {
            await SendEmailInternalAsync(toEmail, customerName, productName, licenseKey, true, onProgress);
        }

        private async Task SendEmailInternalAsync(string toEmail, string customerName, string productName, string licenseKey, bool isDiagnostic, Action<string>? onProgress)
        {
            void Log(string msg) { onProgress?.Invoke(msg); _logger.LogInformation(msg); }

            if (isDiagnostic) Log("Démarrage du diagnostic SMTP...");

            // Nettoyage
            string host = _settings.Host?.Trim('"', '\'', ' ', '\t') ?? "";
            string user = _settings.Username?.Trim('"', '\'', ' ', '\t') ?? "";
            string pass = _settings.Password?.Trim('"', '\'', ' ', '\t') ?? "";

            if (string.IsNullOrEmpty(host) || host == "localhost")
            {
                var msg = "ERREUR : SMTP non configuré (Host vide ou localhost)";
                if (isDiagnostic) Log(msg);
                throw new InvalidOperationException(msg);
            }

            if (isDiagnostic) Log($"Tentative d'envoi à {toEmail} via {host}:{_settings.Port}");

            var message = new MimeMessage();
            string senderName = isDiagnostic ? "YOUR_COMPANY_NAME Diagnostic" : productName;
            message.From.Add(new MailboxAddress(senderName, _settings.FromEmail?.Trim('"')));
            message.To.Add(new MailboxAddress(customerName, toEmail));
            
            message.Subject = isDiagnostic 
                ? "Test de configuration SMTP - YOUR_COMPANY_NAME" 
                : $"Votre licence pour {productName}";
            
            var builder = new BodyBuilder();
            builder.HtmlBody = $@"
<div style=""font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; max-width: 600px; margin: 0 auto; border: 1px solid #e0e0e0; border-radius: 8px; overflow: hidden;"">
    <div style=""background-color: #2c3e50; padding: 30px; text-align: center; color: white;"">
        <h1 style=""margin: 0; font-size: 24px; font-weight: 600;"">{(isDiagnostic ? "Test Système" : productName)}</h1>
        <p style=""margin: 5px 0 0 0; opacity: 0.8; font-size: 14px;"">{(isDiagnostic ? "Ceci est un e-mail de test" : "Livraison de votre licence")}</p>
    </div>
    
    <div style=""padding: 40px 30px; background-color: #ffffff; color: #333333; line-height: 1.6;"">
        <p style=""margin-top: 0;"">Bonjour <strong>{customerName}</strong>,</p>
        <p>{(isDiagnostic ? "Félicitations ! Votre configuration SMTP est correcte." : $"Merci pour votre confiance. Vous trouverez ci-dessous la clé nécessaire pour activer votre exemplaire de <strong>{productName}</strong>.")}</p>
        
        <div style=""margin: 30px 0; padding: 20px; background-color: #f8f9fa; border: 2px dashed #cbd5e0; border-radius: 6px; text-align: center;"">
            <span style=""display: block; font-size: 12px; text-transform: uppercase; color: #718096; margin-bottom: 10px; font-weight: bold;"">{(isDiagnostic ? "Clé de test" : "Votre clé de licence")}</span>
            <code style=""font-family: 'Consolas', 'Monaco', monospace; font-size: 22px; font-weight: bold; color: #2d3748; letter-spacing: 1px;"">{licenseKey}</code>
        </div>
        
        <h3 style=""font-size: 16px; color: #2c3e50; margin-bottom: 10px;"">Comment activer votre logiciel ?</h3>
        <ol style=""padding-left: 20px; margin-bottom: 30px;"">
            <li style=""margin-bottom: 8px;"">Lancez l'application <strong>{(isDiagnostic ? "VotreProduit" : productName)}</strong> sur votre ordinateur.</li>
            <li style=""margin-bottom: 8px;"">Copiez la clé ci-dessus (Ctrl+C).</li>
            <li>Collez-la dans le champ d'activation (Ctrl+V) et validez.</li>
        </ol>
        
        <p style=""font-size: 14px; color: #718096; border-top: 1px solid #edf2f7; padding-top: 20px; margin-top: 30px;"">
            Besoin d'aide ? Répondez simplement à cet e-mail, notre équipe vous assistera dans les plus brefs délais.
        </p>
    </div>
    
    <div style=""background-color: #f8f9fa; padding: 20px; text-align: center; font-size: 12px; color: #a0aec0;"">
        &copy; {DateTime.Now.Year} YOUR_COMPANY_NAME - {(isDiagnostic ? "Test Système" : productName)}
    </div>
</div>";
            
            builder.TextBody = isDiagnostic 
                ? $"Bonjour {customerName},\n\nVotre configuration SMTP est correcte.\n\nCordialement,\nL'équipe YOUR_COMPANY_NAME"
                : $"Bonjour {customerName},\n\nVotre clé pour {productName} est : {licenseKey}\n\nCordialement,\nL'équipe {productName}";
            
            message.Body = builder.ToMessageBody();

            using var client = new SmtpClient();
            client.Timeout = isDiagnostic ? 15000 : 30000; 

            try
            {
                if (isDiagnostic) Log("Connexion et sécurisation...");
                
                SecureSocketOptions security = _settings.Port switch
                {
                    465 => SecureSocketOptions.SslOnConnect,
                    587 => SecureSocketOptions.StartTls,
                    _ => _settings.EnableSsl ? SecureSocketOptions.Auto : SecureSocketOptions.None
                };

                await client.ConnectAsync(host, _settings.Port, security);
                
                if (isDiagnostic) {
                    Log("Connecté.");
                    Log($"Auth supportées : {string.Join(", ", client.AuthenticationMechanisms)}");
                }

                if (!string.IsNullOrEmpty(user))
                {
                    if (isDiagnostic) Log($"Authentification ({user})...");
                    await client.AuthenticateAsync(user, pass);
                }

                if (isDiagnostic) Log("Envoi du message...");
                await client.SendAsync(message);
                
                if (isDiagnostic) Log("Email envoyé avec succès !");

                await client.DisconnectAsync(true);
            }
            catch (SmtpCommandException ex)
            {
                if (isDiagnostic) Log($"ERREUR SMTP : {ex.Message} (Code: {ex.StatusCode})");
                throw;
            }
            catch (Exception ex)
            {
                if (isDiagnostic) Log($"ERREUR : {ex.Message}");
                throw;
            }
        }
    }
}