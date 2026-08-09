using Microsoft.EntityFrameworkCore;
using Npgsql;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;

namespace SoftLicence.Server;

public static class DatabaseMigrationRunner
{
    internal const string ApplicationRole = "softlicence_app";
    private const int MaxAttempts = 10;
    private static readonly TimeSpan RetryDelay = TimeSpan.FromSeconds(5);

    public static async Task RunAsync(
        IConfiguration configuration,
        CancellationToken cancellationToken = default)
    {
        var connectionString = configuration.GetConnectionString("MigrationConnection");
        if (string.IsNullOrWhiteSpace(connectionString))
        {
            throw new InvalidOperationException(
                "Database migration mode requires ConnectionStrings:MigrationConnection.");
        }

        NpgsqlConnectionStringBuilder connectionBuilder;
        try
        {
            connectionBuilder = new NpgsqlConnectionStringBuilder(connectionString);
        }
        catch (ArgumentException exception)
        {
            throw new InvalidOperationException(
                "ConnectionStrings:MigrationConnection is not a valid PostgreSQL connection string.",
                exception);
        }

        if (string.Equals(connectionBuilder.Username, ApplicationRole, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"Database migrations must not run as the application role '{ApplicationRole}'.");
        }

        var options = new DbContextOptionsBuilder<LicenseDbContext>()
            .UseNpgsql(connectionString)
            .Options;

        for (var attempt = 1; attempt <= MaxAttempts; attempt++)
        {
            try
            {
                await using var db = new LicenseDbContext(options);
                await db.Database.MigrateAsync(cancellationToken);
                await InitializeRuntimeKeyRegistryAsync(
                    configuration,
                    connectionString,
                    cancellationToken);
                await InitializeCanaryAckKeyRegistryAsync(
                    configuration,
                    connectionString,
                    cancellationToken);
                Console.WriteLine("Database migrations completed successfully.");
                return;
            }
            catch (Exception exception) when (
                attempt < MaxAttempts
                && IsTransientFailure(exception)
                && !cancellationToken.IsCancellationRequested)
            {
                Console.Error.WriteLine(
                    $"Database migration attempt {attempt}/{MaxAttempts} failed ({exception.GetType().Name}); retrying.");
                await Task.Delay(RetryDelay, cancellationToken);
            }
        }
    }

    private static bool IsTransientFailure(Exception exception) =>
        exception is TimeoutException
        || exception is NpgsqlException { IsTransient: true }
        || (exception.InnerException != null && IsTransientFailure(exception.InnerException));

    private static async Task InitializeRuntimeKeyRegistryAsync(
        IConfiguration configuration,
        string connectionString,
        CancellationToken cancellationToken)
    {
        var runtimeOptions = new RuntimeEnrollmentOptions();
        configuration.GetSection("RuntimeEnrollment").Bind(runtimeOptions);
        RuntimeEnrollmentOptionsConfiguration.RemoveEmptySigningKeyPlaceholders(runtimeOptions);
        if (runtimeOptions.Mode == "off")
            return;

        var validation = new RuntimeEnrollmentOptionsValidator().Validate(null, runtimeOptions);
        if (validation.Failed)
        {
            throw new InvalidOperationException(
                $"Runtime enrollment configuration is invalid for migration: {string.Join(' ', validation.Failures)}");
        }

        await RuntimeEnrollmentKeyRegistryProvisioner.InitializeOrValidateAsync(
            connectionString,
            runtimeOptions,
            cancellationToken);
    }

    private static async Task InitializeCanaryAckKeyRegistryAsync(
        IConfiguration configuration,
        string connectionString,
        CancellationToken cancellationToken)
    {
        var runtimeOptions = new RuntimeEnrollmentOptions();
        configuration.GetSection("RuntimeEnrollment").Bind(runtimeOptions);
        RuntimeEnrollmentOptionsConfiguration.RemoveEmptySigningKeyPlaceholders(runtimeOptions);
        if (runtimeOptions.Mode == "off")
            return;

        var options = new CanaryAckOptions();
        configuration.GetSection("CanaryAck").Bind(options);
        var validation = new CanaryAckOptionsValidator().Validate(null, options);
        if (validation.Failed)
        {
            throw new InvalidOperationException(
                $"Canary ACK configuration is invalid for migration: {string.Join(' ', validation.Failures)}");
        }

        await CanaryAckKeyRegistryProvisioner.InitializeOrValidateAsync(
            connectionString,
            options,
            cancellationToken);
    }
}
