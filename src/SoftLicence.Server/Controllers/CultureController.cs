using Microsoft.AspNetCore.Localization;
using Microsoft.AspNetCore.Mvc;

namespace SoftLicence.Server.Controllers;

[Route("[controller]/[action]")]
public class CultureController : Controller
{
    public IActionResult Set(string culture, string redirectUri)
    {
        if (!string.IsNullOrEmpty(culture))
        {
            HttpContext.Response.Cookies.Append(
                CookieRequestCultureProvider.DefaultCookieName,
                CookieRequestCultureProvider.MakeCookieValue(new RequestCulture(culture)),
                new CookieOptions { Expires = DateTimeOffset.UtcNow.AddYears(1) }
            );
        }

        // Sécurité : uniquement les redirections locales ou même hôte (pas d'open redirect)
        if (!string.IsNullOrEmpty(redirectUri))
        {
            if (Url.IsLocalUrl(redirectUri))
                return LocalRedirect(redirectUri);

            // Blazor Nav.Uri envoie des URLs absolues — vérifier que c'est le même hôte
            if (Uri.TryCreate(redirectUri, UriKind.Absolute, out var uri)
                && uri.Host == HttpContext.Request.Host.Host)
                return Redirect(redirectUri);
        }

        return LocalRedirect("/");
    }
}
