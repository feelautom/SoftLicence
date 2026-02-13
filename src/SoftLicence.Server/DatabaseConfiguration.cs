using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using SoftLicence.Server.Data;

namespace SoftLicence.Server;

public static class DatabaseConfiguration
{
    public static void AddSoftLicenceDatabase(this IServiceCollection services, IConfiguration config)
    {
        var isTest = config["IsIntegrationTest"] == "true";
        
        if (isTest)
        {
            services.AddDbContextFactory<LicenseDbContext>(options =>
                options.UseInMemoryDatabase("IntegrationTestsDb"));
        }
        else
        {
            var connectionString = config.GetConnectionString("DefaultConnection");
            if (string.IsNullOrEmpty(connectionString))
            {
                throw new InvalidOperationException("ERREUR CRITIQUE : Aucune chaîne de connexion PostgreSQL 'DefaultConnection' trouvée. Le serveur NE PEUT PAS démarrer.");
            }

            services.AddDbContextFactory<LicenseDbContext>(options =>
                options.UseNpgsql(connectionString));
        }

        services.AddScoped(p => 
            p.GetRequiredService<IDbContextFactory<LicenseDbContext>>().CreateDbContext());
    }
}
