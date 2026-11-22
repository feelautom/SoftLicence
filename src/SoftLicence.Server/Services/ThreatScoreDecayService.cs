namespace SoftLicence.Server.Services;

/// <summary>
/// Hourly sweep of the threat-score decay (TKT-002685): every score below 200 without any event for
/// 30 days is erased and journaled with the reason <c>inactif 30 j</c>. The same rule is also applied
/// at load time and before each new event, so this sweep only keeps the table and the memory tidy.
/// Independent from <see cref="CleanupService"/>, which can be disabled by configuration.
/// </summary>
public sealed class ThreatScoreDecayService(IServiceScopeFactory scopeFactory, ILogger<ThreatScoreDecayService> logger)
    : BackgroundService
{
    /// <summary>Delay between two sweeps.</summary>
    public static readonly TimeSpan SweepInterval = TimeSpan.FromHours(1);

    /// <inheritdoc />
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Let migrations and startup validators finish before the first sweep.
        await Task.Delay(TimeSpan.FromMinutes(1), stoppingToken);
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                using var scope = scopeFactory.CreateScope();
                var security = scope.ServiceProvider.GetRequiredService<SecurityService>();
                await security.PurgeInactiveThreatScoresAsync(DateTime.UtcNow);
            }
            catch (Exception exception) when (!stoppingToken.IsCancellationRequested)
            {
                logger.LogWarning(exception, "Threat score decay sweep failed; retrying at the next interval.");
            }

            await Task.Delay(SweepInterval, stoppingToken);
        }
    }
}
