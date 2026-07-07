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
            message.From.Add(new MailboxAddress(productName, _settings.FromEmail?.Trim('"') ?? ""));
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
        &copy; {DateTime.Now.Year} FeelAutom - {productName}
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
            message.From.Add(new MailboxAddress("SoftLicence Security", _settings.FromEmail?.Trim('"') ?? ""));
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

        public async Task SendCanaryAlertEmailAsync(string trigger, string hardwareId, string? machineName, string? userName, string? ip, string? appVersion, string? details, int severity, bool isNewBan, string? osVersion = null, bool? debuggerAttached = null)
        {
            var host = _settings.Host?.Trim('"', '\'', ' ', '\t') ?? "";
            var user = _settings.Username?.Trim('"', '\'', ' ', '\t') ?? "";
            var pass = _settings.Password?.Trim('"', '\'', ' ', '\t') ?? "";

            if (string.IsNullOrEmpty(host) || host == "localhost") return;

            var fromEmail = _settings.FromEmail?.Trim('"') ?? "";
            var toEmail = !string.IsNullOrEmpty(user) ? user : fromEmail;
            if (string.IsNullOrEmpty(toEmail)) return;

            // Severity badge
            var (sevLabel, sevColor) = severity switch
            {
                >= 3 => ("CRITICAL", "#c53030"),
                2 => ("WARNING", "#dd6b20"),
                _ => ("INFO", "#718096")
            };
            var sevBadge = $"<span style=\"background:{sevColor};color:white;padding:3px 10px;border-radius:4px;font-weight:bold;\">{sevLabel}</span>";

            // Status badge
            string statusBadge;
            if (isNewBan)
                statusBadge = "<span style=\"background:#c53030;color:white;padding:3px 10px;border-radius:4px;font-weight:bold;\">AUTO-BANNED</span>";
            else if (severity >= 3)
                statusBadge = "<span style=\"background:#e53e3e;color:white;padding:3px 10px;border-radius:4px;\">Critical - Not Banned (review)</span>";
            else
                statusBadge = "<span style=\"background:#38a169;color:white;padding:3px 10px;border-radius:4px;\">Monitoring</span>";

            // Header color by severity
            var headerColor = severity >= 3 ? "#c53030" : (severity >= 2 ? "#dd6b20" : "#4a5568");

            var message = new MimeMessage();
            message.From.Add(new MailboxAddress("SoftLicence Security", fromEmail));
            message.To.Add(new MailboxAddress("Admin", toEmail));
            message.Subject = $"[CANARY][{sevLabel}][{machineName ?? "?"}] {trigger}";

            var builder = new BodyBuilder();
            builder.HtmlBody = $@"
<div style=""font-family:'Segoe UI',sans-serif;max-width:600px;margin:0 auto;border:1px solid #e0e0e0;border-radius:8px;overflow:hidden;"">
    <div style=""background-color:{headerColor};padding:20px 30px;color:white;"">
        <h2 style=""margin:0;"">Canary Alert {sevBadge}</h2>
        <p style=""margin:5px 0 0 0;opacity:0.9;"">{trigger}</p>
    </div>
    <div style=""padding:30px;color:#333;line-height:1.8;"">
        <table style=""width:100%;border-collapse:collapse;"">
            <tr><td style=""padding:5px 10px;font-weight:bold;width:140px;"">Machine</td><td>{machineName ?? "N/A"}</td></tr>
            <tr><td style=""padding:5px 10px;font-weight:bold;"">User</td><td>{userName ?? "N/A"}</td></tr>
            <tr><td style=""padding:5px 10px;font-weight:bold;"">Hardware ID</td><td><code>{hardwareId}</code></td></tr>
            <tr><td style=""padding:5px 10px;font-weight:bold;"">IP</td><td>{ip ?? "N/A"}</td></tr>
            <tr><td style=""padding:5px 10px;font-weight:bold;"">Version</td><td>{appVersion ?? "N/A"}</td></tr>
            <tr><td style=""padding:5px 10px;font-weight:bold;"">OS</td><td>{osVersion ?? "N/A"}</td></tr>
            <tr><td style=""padding:5px 10px;font-weight:bold;"">Debugger.IsAttached</td><td>{(debuggerAttached.HasValue ? debuggerAttached.Value.ToString() : "N/A")}</td></tr>
            <tr><td style=""padding:5px 10px;font-weight:bold;"">Severity</td><td>{sevBadge}</td></tr>
            <tr><td style=""padding:5px 10px;font-weight:bold;"">Action</td><td>{statusBadge}</td></tr>
        </table>
        {(string.IsNullOrEmpty(details) ? "" : $"<div style=\"margin-top:20px;padding:15px;background:#f7fafc;border-left:4px solid {headerColor};font-family:monospace;font-size:13px;white-space:pre-wrap;word-break:break-all;\">{details}</div>")}
        <p style=""margin-top:20px;font-size:12px;color:#718096;"">Received at {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC</p>
    </div>
</div>";
            builder.TextBody = $"CANARY ALERT [{sevLabel}]: {trigger}\nMachine: {machineName}\nUser: {userName}\nHWID: {hardwareId}\nIP: {ip}\nVersion: {appVersion}\nOS: {osVersion}\nDebugger.IsAttached: {debuggerAttached}\nSeverity: {severity}\nDetails: {details}\nBan: {(isNewBan ? "NEW" : "none")}";
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
            string senderName = isDiagnostic ? "FeelAutom Diagnostic" : productName;
            message.From.Add(new MailboxAddress(senderName, _settings.FromEmail?.Trim('"') ?? ""));
            message.To.Add(new MailboxAddress(customerName, toEmail));
            
            message.Subject = isDiagnostic 
                ? "Test de configuration SMTP - FeelAutom" 
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
        &copy; {DateTime.Now.Year} FeelAutom - {(isDiagnostic ? "Test Système" : productName)}
    </div>
</div>";
            
            builder.TextBody = isDiagnostic 
                ? $"Bonjour {customerName},\n\nVotre configuration SMTP est correcte.\n\nCordialement,\nL'équipe FeelAutom"
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