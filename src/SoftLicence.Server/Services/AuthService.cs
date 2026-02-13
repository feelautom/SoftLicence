using System.Security.Claims;
using Microsoft.AspNetCore.Components.Authorization;

namespace SoftLicence.Server.Services;

public class AuthService
{
    private readonly AuthenticationStateProvider _authStateProvider;

    public AuthService(AuthenticationStateProvider authStateProvider)
    {
        _authStateProvider = authStateProvider;
    }

    public async Task<bool> HasPermissionAsync(string permission)
    {
        var authState = await _authStateProvider.GetAuthenticationStateAsync();
        var user = authState.User;

        if (user.Identity?.IsAuthenticated != true) return false;

        // Si c'est le Root (Role SuperAdmin), il a TOUT
        if (user.IsInRole("SuperAdmin")) return true;

        var permissionsClaim = user.FindFirst("Permissions")?.Value;
        if (string.IsNullOrEmpty(permissionsClaim)) return false;

        var userPermissions = permissionsClaim.Split(',', StringSplitOptions.RemoveEmptyEntries);
        return userPermissions.Contains(permission) || userPermissions.Contains("all");
    }

    public async Task<bool> IsRootAsync()
    {
        var authState = await _authStateProvider.GetAuthenticationStateAsync();
        var user = authState.User;
        return user.Identity?.IsAuthenticated == true && user.IsInRole("SuperAdmin");
    }

    public async Task<bool> MustChangePasswordAsync()
    {
        var authState = await _authStateProvider.GetAuthenticationStateAsync();
        return authState.User.HasClaim("MustChangePassword", "true");
    }
}
