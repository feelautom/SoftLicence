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

    /// <summary>
    /// Validates migration and Runtime startup configuration, applies database migrations with bounded
    /// transient retries, then initializes the Runtime and Canary key registries.
    /// </summary>
    /// <param name="configuration">Untrusted process configuration containing migration and registry settings.</param>
    /// <param name="cancellationToken">Caller-owned cancellation propagated to database and retry operations.</param>
    /// <returns>A task that completes only after migrations and enabled registry initialization succeed.</returns>
    /// <exception cref="InvalidOperationException">
    /// Thrown before database access when the migration connection, role, Runtime configuration, or
    /// enabled Canary configuration is invalid.
    /// </exception>
    /// <exception cref="NpgsqlException">
    /// Propagated when PostgreSQL migration or registry work fails after bounded transient retries.
    /// </exception>
    /// <exception cref="TimeoutException">
    /// Retried as a transient failure while attempts remain, then propagated unchanged from the final attempt.
    /// </exception>
    /// <exception cref="OperationCanceledException">Thrown when caller cancellation is observed.</exception>
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

        var runtimeOptions = BindAndValidateRuntimeEnrollmentOptions(configuration);
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
                    runtimeOptions,
                    connectionString,
                    cancellationToken);
                await InitializeCanaryAckKeyRegistryAsync(
                    configuration,
                    runtimeOptions,
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

    /// <summary>
    /// Binds and validates the exact Runtime configuration before the migrator can access PostgreSQL.
    /// This preserves the same fail-closed startup contract as the server host.
    /// </summary>
    /// <param name="configuration">Untrusted process configuration containing the Runtime section.</param>
    /// <returns>
    /// A newly allocated, post-configured options graph owned by the caller and safe to reuse for the
    /// remainder of this migration run.
    /// </returns>
    /// <exception cref="InvalidOperationException">
    /// Thrown when any Runtime value fails the canonical startup validator.
    /// </exception>
    private static RuntimeEnrollmentOptions BindAndValidateRuntimeEnrollmentOptions(
        IConfiguration configuration)
    {
        var runtimeOptions = new RuntimeEnrollmentOptions();
        configuration.GetSection("RuntimeEnrollment").Bind(runtimeOptions);
        RuntimeEnrollmentOptionsConfiguration.RemoveEmptySigningKeyPlaceholders(runtimeOptions);
        var validation = new RuntimeEnrollmentOptionsValidator().Validate(null, runtimeOptions);
        if (validation.Failed)
        {
            throw new InvalidOperationException(
                $"Runtime enrollment configuration is invalid for migration: {string.Join(' ', validation.Failures)}");
        }

        return runtimeOptions;
    }

    /// <summary>Initializes the Runtime key registry only after the prevalidated mode is enabled.</summary>
    /// <param name="runtimeOptions">Prevalidated options owned by the migration run; this method does not mutate them.</param>
    /// <param name="connectionString">Exact migration-role PostgreSQL connection string.</param>
    /// <param name="cancellationToken">Caller-owned cancellation propagated to registry initialization.</param>
    /// <returns>A task that completes after validation/provisioning, or immediately when Runtime mode is off.</returns>
    /// <exception cref="InvalidOperationException">
    /// Propagated when the configured Runtime registry differs from authoritative persisted state.
    /// </exception>
    /// <exception cref="NpgsqlException">Propagated when PostgreSQL registry initialization fails.</exception>
    /// <exception cref="OperationCanceledException">Thrown when caller cancellation is observed.</exception>
    private static async Task InitializeRuntimeKeyRegistryAsync(
        RuntimeEnrollmentOptions runtimeOptions,
        string connectionString,
        CancellationToken cancellationToken)
    {
        if (runtimeOptions.Mode == "off")
            return;

        await RuntimeEnrollmentKeyRegistryProvisioner.InitializeOrValidateAsync(
            connectionString,
            runtimeOptions,
            cancellationToken);
    }

    /// <summary>Initializes the Canary ACK registry only when the same prevalidated Runtime mode is enabled.</summary>
    /// <param name="configuration">Untrusted process configuration containing Canary ACK settings.</param>
    /// <param name="runtimeOptions">Prevalidated Runtime options owned by the migration run; this method does not mutate them.</param>
    /// <param name="connectionString">Exact migration-role PostgreSQL connection string.</param>
    /// <param name="cancellationToken">Caller-owned cancellation propagated to registry initialization.</param>
    /// <returns>A task that completes after validation/provisioning, or immediately when Runtime mode is off.</returns>
    /// <exception cref="InvalidOperationException">Thrown when enabled Canary ACK configuration is invalid.</exception>
    /// <exception cref="NpgsqlException">Propagated when PostgreSQL Canary registry initialization fails.</exception>
    /// <exception cref="OperationCanceledException">Thrown when caller cancellation is observed.</exception>
    private static async Task InitializeCanaryAckKeyRegistryAsync(
        IConfiguration configuration,
        RuntimeEnrollmentOptions runtimeOptions,
        string connectionString,
        CancellationToken cancellationToken)
    {
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
