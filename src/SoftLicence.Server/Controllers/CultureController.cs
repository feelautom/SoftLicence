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

        // Use Redirect instead of LocalRedirect because Nav.Uri from Blazor is absolute.
        // We check if it's a relative URL or if it belongs to the same host for security.
        if (Url.IsLocalUrl(redirectUri))
        {
            return LocalRedirect(redirectUri);
        }
        
        return Redirect(redirectUri ?? "/");
    }
}
