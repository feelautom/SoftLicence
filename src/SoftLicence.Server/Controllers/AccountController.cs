using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using System.Security.Claims;

namespace SoftLicence.Server.Controllers
{
    [Route("account")]
    public class AccountController : Controller
    {
        private readonly IConfiguration _configuration;
        private readonly LicenseDbContext _db;
        private readonly SecurityService _security;

        public AccountController(IConfiguration configuration, LicenseDbContext db, SecurityService security)
        {
            _configuration = configuration;
            _db = db;
            _security = security;
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromForm] string username, [FromForm] string password, [FromForm] string returnUrl = "/")
        {
            var adminUser = _configuration["AdminSettings:Username"] ?? "admin";
            var adminPass = _configuration["AdminSettings:Password"] ?? "password";
            var loginPathValue = (_configuration["AdminSettings:LoginPath"] ?? "login").Replace("\"", "").Trim().Trim('/');
            var loginPath = "/" + loginPathValue;

            var claims = new List<Claim>();
            bool authenticated = false;

            // 1. Vérification du compte ROOT (Super Admin)
            if (username == adminUser && password == adminPass)
            {
                claims.Add(new Claim(ClaimTypes.Name, "Root"));
                claims.Add(new Claim(ClaimTypes.Role, "CHANGE_ME_RANDOM_SECRET"));
                // Root a toutes les permissions imaginables
                claims.Add(new Claim("Permissions", "all"));
                authenticated = true;
            }
            else
            {
                // 2. Vérification des utilisateurs en base
                var user = await _db.AdminUsers
                    .Include(u => u.Role)
                    .FirstOrDefaultAsync(u => u.Username == username && u.IsEnabled);

                if (user != null && _security.VerifyPassword(password, user.PasswordHash))
                {
                    claims.Add(new Claim(ClaimTypes.Name, user.Username));
                    claims.Add(new Claim(ClaimTypes.Role, user.Role?.Name ?? "User"));
                    claims.Add(new Claim("Permissions", user.Role?.Permissions ?? ""));
                    if (user.MustChangePassword)
                    {
                        claims.Add(new Claim("MustChangePassword", "true"));
                    }
                    authenticated = true;
                }
            }

            if (authenticated)
            {
                var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                var authProperties = new AuthenticationProperties
                {
                    IsPersistent = true,
                    ExpiresUtc = DateTime.UtcNow.AddDays(7)
                };

                await HttpContext.SignInAsync(
                    CookieAuthenticationDefaults.AuthenticationScheme,
                    new ClaimsPrincipal(claimsIdentity),
                    authProperties);

                return LocalRedirect(returnUrl);
            }

            return Redirect($"{loginPath}?error=Invalid credentials&returnUrl={Uri.EscapeDataString(returnUrl)}");
        }

        [HttpGet("logout")]
        public async Task<IActionResult> Logout()
        {
            var loginPath = _configuration["AdminSettings:LoginPath"] ?? "login";
            if (!loginPath.StartsWith("/")) loginPath = "/" + loginPath;

            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return Redirect(loginPath);
        }
    }
}
