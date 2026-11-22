using System.Reflection;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Routing;
using Microsoft.AspNetCore.RateLimiting;
using SoftLicence.Server.Data;

namespace SoftLicence.SchemaGen;

/// <summary>Une route déclarée dans le code.</summary>
/// <param name="Kind">« API » pour une action de contrôleur, « Page » pour un composant Blazor routable.</param>
/// <param name="Protection">Protection lisible dans la déclaration (attributs, dépendances d'authentification du contrôleur).</param>
public sealed record RouteInfo(
    string Kind,
    string Method,
    string Path,
    string Protection,
    string RateLimit,
    Type HandlerType,
    string? HandlerName);

/// <summary>
/// Relève les routes par réflexion sur l'assembly de <c>SoftLicence.Server</c>, sans démarrer l'application :
/// actions des contrôleurs (routage par attributs) et composants Blazor portant <c>@page</c>.
/// SoftLicence contrôle surtout ses appels dans le contrôleur lui-même (secret admin, signature) ;
/// la colonne protection cite donc aussi les services d'authentification reçus par le constructeur.
/// </summary>
public static class RouteReader
{
    /// <summary>Retourne toutes les routes, triées par chemin, méthode puis gestionnaire.</summary>
    public static IReadOnlyList<RouteInfo> Read()
    {
        var assembly = typeof(LicenseDbContext).Assembly;
        var routes = new List<RouteInfo>();
        foreach (var type in assembly.GetTypes().Where(type => type is { IsClass: true, IsAbstract: false }))
        {
            if (typeof(ControllerBase).IsAssignableFrom(type))
                routes.AddRange(ReadController(type));
            else
                routes.AddRange(ReadPage(type));
        }
        return routes
            .OrderBy(route => route.Path, StringComparer.Ordinal)
            .ThenBy(route => route.Method, StringComparer.Ordinal)
            .ThenBy(route => route.HandlerType.FullName, StringComparer.Ordinal)
            .ThenBy(route => route.HandlerName, StringComparer.Ordinal)
            .ToList();
    }

    /// <summary>Actions d'un contrôleur portant un verbe HTTP ou une route.</summary>
    private static IEnumerable<RouteInfo> ReadController(Type controller)
    {
        var controllerName = controller.Name.EndsWith("Controller", StringComparison.Ordinal)
            ? controller.Name[..^"Controller".Length]
            : controller.Name;
        var prefixes = controller.GetCustomAttributes(inherit: true)
            .OfType<IRouteTemplateProvider>()
            .Where(provider => provider is not IActionHttpMethodProvider)
            .Select(provider => provider.Template ?? "")
            .DefaultIfEmpty("")
            .ToList();
        var authenticationDependencies = AuthenticationDependencies(controller);

        foreach (var action in controller.GetMethods(BindingFlags.Instance | BindingFlags.Public | BindingFlags.DeclaredOnly)
                     .Where(method => !method.IsSpecialName && !method.IsDefined(typeof(NonActionAttribute), inherit: true)))
        {
            var templates = action.GetCustomAttributes(inherit: true).OfType<IRouteTemplateProvider>().ToList();
            if (templates.Count == 0)
                continue;
            var protection = Protection(controller, action, authenticationDependencies);
            var rateLimit = RateLimit(controller, action);
            foreach (var provider in templates)
            {
                var methods = provider is IActionHttpMethodProvider verbs && verbs.HttpMethods.Any()
                    ? verbs.HttpMethods.Order(StringComparer.Ordinal).ToList()
                    : ["ANY"];
                foreach (var prefix in prefixes)
                {
                    var path = Combine(prefix, provider.Template)
                        .Replace("[controller]", controllerName, StringComparison.OrdinalIgnoreCase)
                        .Replace("[action]", action.Name, StringComparison.OrdinalIgnoreCase);
                    foreach (var method in methods)
                        yield return new RouteInfo("API", method, path, protection, rateLimit, controller, action.Name);
                }
            }
        }
    }

    /// <summary>Composant Blazor routable : une ligne par gabarit <c>@page</c>.</summary>
    private static IEnumerable<RouteInfo> ReadPage(Type component)
    {
        var pages = component.GetCustomAttributes<Microsoft.AspNetCore.Components.RouteAttribute>(inherit: false).ToList();
        if (pages.Count == 0)
            yield break;
        var authorize = component.GetCustomAttributes<AuthorizeAttribute>(inherit: true).ToList();
        var protection = component.IsDefined(typeof(AllowAnonymousAttribute), inherit: true) ? "anonyme autorisé"
            : authorize.Count > 0 ? DescribeAuthorize(authorize)
            : "aucun attribut";
        foreach (var page in pages)
            yield return new RouteInfo("Page", "GET", "/" + page.Template.TrimStart('/'), protection, "", component, null);
    }

    /// <summary>Attributs Authorize ou AllowAnonymous, puis dépendances d'authentification du contrôleur.</summary>
    private static string Protection(Type controller, MethodInfo action, IReadOnlyList<string> authenticationDependencies)
    {
        var parts = new List<string>();
        if (action.IsDefined(typeof(AllowAnonymousAttribute), inherit: true) || controller.IsDefined(typeof(AllowAnonymousAttribute), inherit: true))
            parts.Add("anonyme autorisé");
        var authorize = controller.GetCustomAttributes<AuthorizeAttribute>(inherit: true)
            .Concat(action.GetCustomAttributes<AuthorizeAttribute>(inherit: true))
            .ToList();
        if (authorize.Count > 0)
            parts.Add(DescribeAuthorize(authorize));
        if (authenticationDependencies.Count > 0)
            parts.Add("contrôle dans le contrôleur : " + string.Join(", ", authenticationDependencies));
        return parts.Count == 0 ? "aucune déclarée" : string.Join(" ; ", parts);
    }

    /// <summary>Résume rôles et politiques des attributs Authorize.</summary>
    private static string DescribeAuthorize(IReadOnlyList<AuthorizeAttribute> attributes)
    {
        var details = attributes
            .Select(attribute => string.Join(" ", new[]
            {
                attribute.Roles is { Length: > 0 } roles ? $"rôles {roles}" : null,
                attribute.Policy is { Length: > 0 } policy ? $"politique {policy}" : null
            }.Where(part => part is not null)))
            .Where(detail => detail.Length > 0)
            .Distinct(StringComparer.Ordinal)
            .ToList();
        return details.Count == 0 ? "authentifié" : "authentifié (" + string.Join(", ", details) + ")";
    }

    /// <summary>Services reçus par le constructeur dont le nom désigne une authentification ou une signature.</summary>
    private static IReadOnlyList<string> AuthenticationDependencies(Type controller) =>
        controller.GetConstructors()
            .SelectMany(constructor => constructor.GetParameters())
            .Select(parameter => parameter.ParameterType.Name)
            .Where(name => name.Contains("Authentication", StringComparison.Ordinal)
                || name.Contains("Authorization", StringComparison.Ordinal)
                || name.Contains("Signature", StringComparison.Ordinal))
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .ToList();

    /// <summary>Politique de limitation la plus proche (action puis contrôleur).</summary>
    private static string RateLimit(Type controller, MethodInfo action)
    {
        if (action.IsDefined(typeof(DisableRateLimitingAttribute), inherit: true))
            return "désactivée";
        var attribute = action.GetCustomAttribute<EnableRateLimitingAttribute>(inherit: true)
            ?? controller.GetCustomAttribute<EnableRateLimitingAttribute>(inherit: true);
        return attribute?.PolicyName ?? "";
    }

    /// <summary>Assemble le gabarit du contrôleur et celui de l'action (absolu si l'action commence par « / » ou « ~/ »).</summary>
    private static string Combine(string prefix, string? template)
    {
        template ??= "";
        if (template.StartsWith("~/", StringComparison.Ordinal))
            return "/" + template[2..].Trim('/');
        if (template.StartsWith('/'))
            return "/" + template.Trim('/');
        var parts = new[] { prefix.Trim('/'), template.Trim('/') }.Where(part => part.Length > 0);
        return "/" + string.Join("/", parts);
    }
}
